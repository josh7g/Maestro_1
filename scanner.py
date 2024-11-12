import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import asyncio
import git

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%b %d %I:%M:%S %p'
)
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
    exclude_patterns: List[str] = field(default_factory=lambda: [
        'node_modules',
        'vendor',
        'build',
        'dist',
        'target',
        'venv',
        'env',
        '.git',
        '.idea',
        '.vscode'
    ])

class GitProgress(git.RemoteProgress):
    """Progress monitor for git operations"""
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            logger.info(f"Git progress: {message}")
        elif max_count:
            progress = (cur_count / max_count) * 100
            logger.info(f"Git progress: {progress:.1f}%")

# Maintaining the ChunkedScanner name for compatibility
class ChunkedScanner:
    """Scanner class for processing repositories"""

    SCANNABLE_EXTENSIONS = {
        # Web development
        '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
        '.html', '.htm', '.css', '.scss', '.sass', '.less',
        
        # Backend development
        '.py', '.rb', '.php', '.java', '.go', '.cs', '.cpp',
        '.c', '.h', '.hpp', '.scala', '.kt', '.rs',
        
        # Configuration and data
        '.json', '.yml', '.yaml', '.xml', '.conf', '.ini',
        '.env', '.properties',
        
        # Scripts and templates
        '.sh', '.bash', '.ps1', '.ejs', '.hbs', '.pug',
        
        # Documentation
        '.md', '.txt'
    }
    
    def __init__(self, config: ScanConfig = ScanConfig()):
        self.config = config
        self.temp_dir = None
        self.repo_dir = None

    async def __aenter__(self):
        """Setup for async context manager"""
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup for async context manager"""
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner resources"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
        logger.info(f"Created temporary directory: {self.temp_dir}")

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    async def clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with authentication"""
        try:
            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')

            logger.info(f"Cloning repository to {self.repo_dir}")
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                progress=GitProgress(),
                multi_options=['--depth=1']
            )

            repo_size = await self._get_directory_size(self.repo_dir)
            size_gb = repo_size / (1024 ** 3)
            
            if size_gb > self.config.max_total_size_gb:
                raise ValueError(
                    f"Repository size ({size_gb:.2f} GB) exceeds "
                    f"limit of {self.config.max_total_size_gb} GB"
                )

            logger.info(f"Successfully cloned repository: {size_gb:.2f} GB")
            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _get_directory_size(self, directory: Path) -> int:
        """Calculate directory size excluding ignored paths"""
        total_size = 0
        for dirpath, _, filenames in os.walk(directory):
            if any(exclude in dirpath for exclude in self.config.exclude_patterns):
                continue
            for filename in filenames:
                file_path = Path(dirpath) / filename
                total_size += file_path.stat().st_size
        return total_size

    
    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with proper configuration"""
        cmd = [
            "semgrep",
            "scan",
            "--config=auto",
            "--json",
            "--timeout",
            str(self.config.timeout_seconds),
            # Remove unsupported options
            # "--disable-metrics" and "--disable-version-check" are not supported
            str(target_dir)
        ]

        logger.info(f"Running Semgrep scan with command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.timeout_seconds
            )

            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "No error message"
                logger.error(f"Semgrep scan failed with error: {error_msg}")
                raise RuntimeError(f"Semgrep scan failed: {error_msg}")

            try:
                results = json.loads(stdout.decode())
                logger.info("Semgrep scan completed successfully")
                return results
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep output: {e}")
                raise RuntimeError("Failed to parse Semgrep output") from e

        except asyncio.TimeoutError:
            if 'process' in locals():
                try:
                    process.terminate()
                    await process.wait()
                except Exception:
                    pass
            logger.error(f"Semgrep scan timed out after {self.config.timeout_seconds} seconds")
            raise RuntimeError(f"Semgrep scan timed out after {self.config.timeout_seconds} seconds")
            
        except Exception as e:
            logger.error(f"Semgrep scan error: {str(e)}")
            raise RuntimeError(f"Semgrep scan error: {str(e)}")


    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        try:
            repo_path = await self.clone_repository(repo_url, token)
            return await self._run_semgrep_scan(repo_path)
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__
                }
            }
        finally:
            await self._cleanup()

async def scan_repository_handler(repo_url: str, installation_token: str) -> Dict:
    """Handler function for web routes"""
    config = ScanConfig(
        max_file_size_mb=50,
        max_total_size_gb=2,
        max_memory_percent=80,
        timeout_seconds=3600,
        max_retries=3,
        concurrent_processes=2
    )
    
    async with ChunkedScanner(config) as scanner:
        try:
            results = await scanner.scan_repository(repo_url, installation_token)
            return {
                'success': True,
                'data': results
            }
        except Exception as e:
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }