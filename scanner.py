
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
        """Execute Semgrep scan with chunking for large codebases"""
        all_files = []
        for root, _, files in os.walk(target_dir):
            if any(exclude in root for exclude in self.config.exclude_patterns):
                continue
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
                    all_files.append(file_path)

        # Calculate available memory and chunk size
        available_memory = psutil.virtual_memory().available
        max_memory_mb = min(int((available_memory * 0.7) / (1024 * 1024)), 5000)
        chunk_size_mb = min(max_memory_mb // 2, 500)  # Use half of max memory or 500MB, whichever is smaller

        chunks = self._split_into_chunks(all_files, chunk_size_mb)
        logger.info(f"Split scanning into {len(chunks)} chunks")

        all_results = {
            'results': [],
            'errors': [],
            'paths': {'scanned': [], 'ignored': []},
            'version': "1.56.0"
        }

        for i, chunk in enumerate(chunks):
            logger.info(f"Scanning chunk {i+1}/{len(chunks)} with {len(chunk)} files")
            
            cmd = [
                "semgrep",
                "scan",
                "--config=auto",
                "--json",
                "--timeout",
                str(self.config.timeout_seconds),
                "--max-memory",
                f"{max_memory_mb}"
            ]
            cmd.extend(str(f) for f in chunk)

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(target_dir)
                )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout_seconds
                )

                stdout_str = stdout.decode() if stdout else ""
                
                if stdout_str.strip():
                    chunk_results = json.loads(stdout_str)
                    all_results['results'].extend(chunk_results.get('results', []))
                    all_results['errors'].extend(chunk_results.get('errors', []))
                    all_results['paths']['scanned'].extend(
                        chunk_results.get('paths', {}).get('scanned', [])
                    )
                    all_results['paths']['ignored'].extend(
                        chunk_results.get('paths', {}).get('ignored', [])
                    )

            except asyncio.TimeoutError:
                logger.error(f"Timeout scanning chunk {i+1}")
                all_results['errors'].append({
                    'code': 'timeout',
                    'message': f'Scan timeout in chunk {i+1}'
                })
                continue
            except Exception as e:
                logger.error(f"Error scanning chunk {i+1}: {str(e)}")
                all_results['errors'].append({
                    'code': 'scan_error',
                    'message': str(e)
                })
                continue

        return all_results

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        try:
            repo_path = await self.clone_repository(repo_url, token)
            results = await self._run_semgrep_scan(repo_path)
            
            return {
                'success': True,
                'data': results,
                'metadata': {
                    'repository_url': repo_url,
                    'scan_timestamp': datetime.now().isoformat(),
                    'total_findings': len(results.get('results', [])),
                    'total_files_scanned': len(results.get('paths', {}).get('scanned', [])),
                    'total_errors': len(results.get('errors', []))
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
