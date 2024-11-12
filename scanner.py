# scanner.py
import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import asyncio
from concurrent.futures import ThreadPoolExecutor
import math
import git
from github import Github, GithubIntegration

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for repository scanning"""
    max_file_size_mb: int = 50
    max_total_size_gb: int = 2
    max_memory_percent: int = 80
    chunk_size_mb: int = 500
    timeout_seconds: int = 3600
    max_retries: int = 3
    concurrent_processes: int = 2

class ChunkedScanner:
    def __init__(self, config: ScanConfig = ScanConfig()):
        self.config = config
        self.executor = ThreadPoolExecutor(max_workers=config.concurrent_processes)
        self._setup_temp_dir()

    def _setup_temp_dir(self):
        """Create a temporary directory for processing"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
        logger.info(f"Created temporary directory: {self.temp_dir}")

    def _cleanup_temp_dir(self):
        """Clean up temporary directory"""
        try:
            shutil.rmtree(self.temp_dir)
            logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up directory {self.temp_dir}: {e}")

    async def clone_repository(self, repo_url: str, installation_token: str) -> Path:
        """Clone repository with progress monitoring and size checks"""
        clone_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Add token to URL
            auth_url = repo_url.replace(
                'https://', 
                f'https://x-access-token:{installation_token}@'
            )

            logger.info(f"Cloning repository to {clone_dir}")
            
            # Use GitPython for better control
            repo = git.Repo.clone_from(
                auth_url,
                clone_dir,
                progress=GitProgress(),
                multi_options=['--depth=1']  # Shallow clone
            )

            # Check repository size
            repo_size = await self._get_directory_size(clone_dir)
            if repo_size > self.config.max_total_size_gb * 1024 * 1024 * 1024:
                raise ValueError(
                    f"Repository size ({repo_size / (1024**3):.2f} GB) exceeds "
                    f"limit of {self.config.max_total_size_gb} GB"
                )

            logger.info(f"Successfully cloned repository: {repo_size / (1024**2):.2f} MB")
            return clone_dir

        except Exception as e:
            if clone_dir.exists():
                shutil.rmtree(clone_dir)
            raise RuntimeError(f"Clone failed: {str(e)}") from e

    async def _get_directory_size(self, directory: Path) -> int:
        """Get directory size asynchronously"""
        total_size = 0
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = Path(dirpath) / filename
                total_size += file_path.stat().st_size
        return total_size

    def _chunk_directory(self, directory: Path) -> List[List[Path]]:
        """Split directory into manageable chunks"""
        all_files = []
        current_chunk = []
        current_chunk_size = 0

        # Collect all scannable files
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = Path(dirpath) / filename
                if self._is_scannable_file(file_path):
                    file_size = file_path.stat().st_size
                    if file_size > self.config.max_file_size_mb * 1024 * 1024:
                        logger.warning(
                            f"Skipping large file: {file_path} "
                            f"({file_size / (1024**2):.2f} MB)"
                        )
                        continue
                    
                    if current_chunk_size + file_size > self.config.chunk_size_mb * 1024 * 1024:
                        if current_chunk:
                            all_files.append(current_chunk)
                        current_chunk = [file_path]
                        current_chunk_size = file_size
                    else:
                        current_chunk.append(file_path)
                        current_chunk_size += file_size

        if current_chunk:
            all_files.append(current_chunk)

        logger.info(f"Split repository into {len(all_files)} chunks")
        return all_files

    def _is_scannable_file(self, file_path: Path) -> bool:
        """Check if file should be scanned"""
        SCANNABLE_EXTENSIONS = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb',
            '.php', '.cs', '.cpp', '.c', '.h', '.hpp', '.scala', '.kt',
            '.rs', '.swift', '.m', '.mm', '.sql', '.sh', '.bash', '.zsh'
        }
        
        EXCLUDED_DIRS = {
            'node_modules', 'vendor', 'build', 'dist', 'target',
            'venv', 'env', '.git', '.idea', '.vscode'
        }

        return (
            file_path.suffix in SCANNABLE_EXTENSIONS and
            not any(part in EXCLUDED_DIRS for part in file_path.parts)
        )

    async def _scan_chunk(
        self, 
        chunk: List[Path], 
        chunk_index: int,
        retries: int = 0
    ) -> Optional[Dict]:
        """Scan a chunk of files with Semgrep"""
        if retries >= self.config.max_retries:
            logger.error(f"Max retries reached for chunk {chunk_index}")
            return None

        chunk_dir = self.temp_dir / f"chunk_{chunk_index}"
        chunk_dir.mkdir(exist_ok=True)

        try:
            # Create symlinks to files in chunk directory
            for file_path in chunk:
                relative_path = file_path.relative_to(self.temp_dir / "repo")
                target_path = chunk_dir / relative_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if not target_path.exists():
                    os.symlink(file_path, target_path)

            # Set resource limits
            memory_limit = psutil.virtual_memory().total * self.config.max_memory_percent / 100

            # Run Semgrep with resource constraints
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--timeout",
                str(self.config.timeout_seconds),
                "."
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(chunk_dir),
                limit=memory_limit
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout_seconds
                )

                if process.returncode != 0:
                    logger.error(
                        f"Semgrep failed for chunk {chunk_index}: "
                        f"{stderr.decode()}"
                    )
                    if retries < self.config.max_retries:
                        logger.info(f"Retrying chunk {chunk_index}")
                        return await self._scan_chunk(
                            chunk, 
                            chunk_index, 
                            retries + 1
                        )
                    return None

                return json.loads(stdout)

            except asyncio.TimeoutError:
                process.terminate()
                logger.error(f"Timeout scanning chunk {chunk_index}")
                if retries < self.config.max_retries:
                    return await self._scan_chunk(chunk, chunk_index, retries + 1)
                return None

        except Exception as e:
            logger.error(f"Error scanning chunk {chunk_index}: {e}")
            if retries < self.config.max_retries:
                return await self._scan_chunk(chunk, chunk_index, retries + 1)
            return None

        finally:
            # Cleanup chunk directory
            if chunk_dir.exists():
                shutil.rmtree(chunk_dir)

    async def scan_repository(
        self,
        repo_url: str,
        installation_token: str
    ) -> Dict:
        """Main method to scan a repository"""
        try:
            # Clone repository
            repo_dir = await self.clone_repository(repo_url, installation_token)

            # Split into chunks
            chunks = self._chunk_directory(repo_dir)

            # Scan chunks concurrently
            tasks = []
            for i, chunk in enumerate(chunks):
                task = asyncio.create_task(self._scan_chunk(chunk, i))
                tasks.append(task)

            # Wait for all chunks to complete
            chunk_results = await asyncio.gather(*tasks)

            # Merge results
            merged_results = self._merge_results(chunk_results)

            return merged_results

        finally:
            self._cleanup_temp_dir()

    def _merge_results(self, chunk_results: List[Optional[Dict]]) -> Dict:
        """Merge results from all chunks"""
        merged = {
            'results': [],
            'errors': [],
            'paths': {'scanned': set(), 'ignored': set()}
        }

        for result in chunk_results:
            if result is None:
                continue

            merged['results'].extend(result.get('results', []))
            merged['errors'].extend(result.get('errors', []))
            merged['paths']['scanned'].update(result.get('paths', {}).get('scanned', []))
            merged['paths']['ignored'].update(result.get('paths', {}).get('ignored', []))

        # Convert sets back to lists for JSON serialization
        merged['paths']['scanned'] = list(merged['paths']['scanned'])
        merged['paths']['ignored'] = list(merged['paths']['ignored'])

        return merged

class GitProgress(git.RemoteProgress):
    """Progress monitor for git operations"""
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            logger.info(f"Git progress: {message}")

# Example usage in your Flask route
async def scan_repository_handler(repo_url: str, installation_token: str) -> Dict:
    """Handler function for Flask route"""
    scanner = ChunkedScanner(ScanConfig(
        max_file_size_mb=50,
        max_total_size_gb=2,
        max_memory_percent=80,
        chunk_size_mb=500,
        timeout_seconds=3600,
        max_retries=3,
        concurrent_processes=2
    ))
    
    try:
        results = await scanner.scan_repository(repo_url, installation_token)
        return {
            'success': True,
            'data': results
        }
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return {
            'success': False,
            'error': {
                'message': str(e),
                'type': type(e).__name__
            }
        }