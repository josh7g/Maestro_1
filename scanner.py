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

@dataclass
class ScanResult:
    """Structure for scan results"""
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scanned_files: Set[str] = field(default_factory=set)
    ignored_files: Set[str] = field(default_factory=set)
    scan_time: datetime = field(default_factory=datetime.now)

class GitProgress(git.RemoteProgress):
    """Progress monitor for git operations"""
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            logger.info(f"Git progress: {message}")
        elif max_count:
            progress = (cur_count / max_count) * 100
            size_mb = cur_count / (1024 * 1024)
            logger.info(f"Git progress: {progress:.1f}% ({size_mb:.2f} MB)")

class RepositoryScanner:
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
        self.scan_result = ScanResult()

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
        try:
            for dirpath, _, filenames in os.walk(directory):
                if any(exclude in dirpath for exclude in self.config.exclude_patterns):
                    continue
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    total_size += file_path.stat().st_size
        except Exception as e:
            logger.error(f"Error calculating directory size: {e}")
            raise
        return total_size

    def _is_scannable_file(self, file_path: Path) -> bool:
        """Determine if file should be scanned"""
        try:
            if any(exclude in file_path.parts for exclude in self.config.exclude_patterns):
                return False
            return file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS
        except Exception as e:
            logger.error(f"Error checking file scannability: {e}")
            return False

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with proper configuration"""
        cmd = [
            "semgrep",
            "scan",
            "--config=auto",
            "--json",
            "--timeout",
            str(self.config.timeout_seconds),
            "--max-memory",
            f"{int(psutil.virtual_memory().total * self.config.max_memory_percent / 100 / (1024 * 1024))}M",
            "--disable-metrics",
            "--disable-version-check",
            str(target_dir)
        ]

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
                raise RuntimeError(f"Semgrep scan failed: {error_msg}")

            return json.loads(stdout.decode())

        except asyncio.TimeoutError:
            process.terminate()
            raise RuntimeError("Semgrep scan timed out")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Semgrep output")
        except Exception as e:
            raise RuntimeError(f"Semgrep scan error: {str(e)}")

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        try:
            # Clone and scan repository
            repo_path = await self.clone_repository(repo_url, token)
            scan_results = await self._run_semgrep_scan(repo_path)

            # Process results
            findings = scan_results.get('results', [])
            self.scan_result.findings = findings
            
            # Get scanned and ignored files
            for file in Path(repo_path).rglob('*'):
                if file.is_file():
                    rel_path = str(file.relative_to(repo_path))
                    if self._is_scannable_file(file):
                        self.scan_result.scanned_files.add(rel_path)
                    else:
                        self.scan_result.ignored_files.add(rel_path)

            return {
                'success': True,
                'data': {
                    'findings': self.scan_result.findings,
                    'errors': self.scan_result.errors,
                    'paths': {
                        'scanned': list(self.scan_result.scanned_files),
                        'ignored': list(self.scan_result.ignored_files)
                    }
                },
                'metadata': {
                    'scan_time': self.scan_result.scan_time.isoformat(),
                    'total_files_scanned': len(self.scan_result.scanned_files),
                    'total_files_ignored': len(self.scan_result.ignored_files),
                    'total_findings': len(self.scan_result.findings)
                }
            }

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }

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
    
    async with RepositoryScanner(config) as scanner:
        return await scanner.scan_repository(repo_url, installation_token)