
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
    concurrent_processes: int = 1  # Set to 1 for better memory management
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
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
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

    def _split_into_chunks(self, files: List[Path], chunk_size_mb: int) -> List[List[Path]]:
        """Split files into chunks based on size"""
        chunks = []
        current_chunk = []
        current_size = 0
        
        for file_path in files:
            file_size = file_path.stat().st_size
            if current_size + file_size > chunk_size_mb * 1024 * 1024:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = [file_path]
                current_size = file_size
            else:
                current_chunk.append(file_path)
                current_size += file_size
                
        if current_chunk:
            chunks.append(current_chunk)
            
        return chunks

    
    
    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with proper result collection"""
        # Set a lower memory limit - 2GB max per process
        max_memory_mb = 2000
        
        # Collect scannable files
        all_files = []
        file_mapping = {}  # To keep track of original file paths
        
        for root, _, files in os.walk(target_dir):
            if any(exclude in root for exclude in self.config.exclude_patterns):
                continue
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
                    all_files.append(file_path)
                    # Store relative path for result mapping
                    file_mapping[str(file_path.relative_to(target_dir))] = str(file_path)

        # Break into small chunks
        chunk_size = 20
        chunks = [all_files[i:i + chunk_size] for i in range(0, len(all_files), chunk_size)]
        
        logger.info(f"Split scanning into {len(chunks)} chunks of {chunk_size} files each")

        all_results = {
            'results': [],
            'errors': [],
            'paths': {
                'scanned': set(),  # Use set to avoid duplicates
                'ignored': set()
            },
            'version': "1.56.0"
        }

        for i, chunk in enumerate(chunks, 1):
            logger.info(f"Scanning chunk {i}/{len(chunks)} with {len(chunk)} files")
            
            # Create temporary directory for this chunk
            chunk_dir = target_dir / f"chunk_{i}"
            chunk_dir.mkdir(exist_ok=True)

            try:
                # Copy files to chunk directory maintaining structure
                chunk_file_mapping = {}  # Track files in this chunk
                for file_path in chunk:
                    rel_path = file_path.relative_to(target_dir)
                    target_path = chunk_dir / rel_path
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, target_path)
                    chunk_file_mapping[str(rel_path)] = str(file_path)

                cmd = [
                    "semgrep",
                    "scan",
                    "--config=auto",
                    "--json",
                    "--max-memory",
                    str(max_memory_mb),
                    "--timeout",
                    "300",
                    "--jobs",
                    "1",
                    str(chunk_dir)
                ]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(chunk_dir)
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=300
                    )

                    stdout_str = stdout.decode() if stdout else ""
                    if stdout_str.strip():
                        chunk_results = json.loads(stdout_str)
                        
                        # Add scanned files to the set
                        all_results['paths']['scanned'].update(
                            chunk_file_mapping.keys()
                        )

                        # Process and add findings
                        for finding in chunk_results.get('results', []):
                            # Update the path to the original file path
                            if 'path' in finding:
                                rel_path = finding['path']
                                finding['path'] = chunk_file_mapping.get(rel_path, rel_path)
                            all_results['results'].append(finding)

                        logger.info(f"Successfully scanned chunk {i} with "
                                  f"{len(chunk_results.get('results', []))} findings")

                except asyncio.TimeoutError:
                    logger.warning(f"Timeout scanning chunk {i}")
                    continue

            except Exception as e:
                logger.error(f"Error processing chunk {i}: {str(e)}")
                continue

            finally:
                # Cleanup chunk directory
                try:
                    shutil.rmtree(chunk_dir)
                except Exception as e:
                    logger.error(f"Error cleaning up chunk directory: {str(e)}")

        # Convert sets to lists for JSON serialization
        all_results['paths']['scanned'] = list(all_results['paths']['scanned'])
        all_results['paths']['ignored'] = list(all_results['paths']['ignored'])

        # Add semgrep version
        all_results['version'] = "1.56.0"

        logger.info(f"Completed scan: {len(all_results['results'])} findings, "
                   f"{len(all_results['paths']['scanned'])} files scanned")
        
        return all_results

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        try:
            repo_path = await self.clone_repository(repo_url, token)
            
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            
            logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
            results = await self._run_semgrep_scan(repo_path)
            
            return {
                'success': True,
                'data': {
                    'results': results['results'],
                    'errors': results['errors'],
                    'paths': results['paths'],
                    'version': results['version'],
                    'scan_status': 'completed',
                    'files_scanned': len(results['paths']['scanned']),
                    'total_findings': len(results['results'])
                },
                'metadata': {
                    'repository_size_mb': round(size_mb, 2),
                    'scan_timestamp': datetime.now().isoformat(),
                    'files_analyzed': len(results['paths']['scanned']),
                    'findings_count': len(results['results'])
                }
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }
        finally:
            await self._cleanup()


class GitProgress(git.RemoteProgress):
    """Progress monitor for git operations"""
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            logger.info(f"Git progress: {message}")
        elif max_count:
            progress = (cur_count / max_count) * 100
            logger.info(f"Git progress: {progress:.1f}%")

async def scan_repository_handler(repo_url: str, installation_token: str, user_id: str) -> Dict:
    """Handler function for web routes"""
    if not all([repo_url, installation_token, user_id]):
        return {
            'success': False,
            'error': {
                'message': 'Missing required parameters',
                'code': 'INVALID_PARAMETERS',
                'details': {
                    'repo_url': bool(repo_url),
                    'installation_token': bool(installation_token),
                    'user_id': bool(user_id)
                }
            }
        }

    config = ScanConfig(
        max_file_size_mb=50,
        max_total_size_gb=2,
        max_memory_percent=70,
        timeout_seconds=3600,
        max_retries=3,
        concurrent_processes=1
    )
    
    async with ChunkedScanner(config) as scanner:
        try:
            results = await scanner.scan_repository(repo_url, installation_token)
            if results['success']:
                results['metadata']['user_id'] = user_id
            return results
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }
