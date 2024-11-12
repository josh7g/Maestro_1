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
    max_memory_percent: int = 90
    chunk_size_mb: int = 500
    timeout_seconds: int = 3600
    max_retries: int = 3
    concurrent_processes: int = 1
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
        """Execute Semgrep scan with proper memory management"""
        # Calculate 70% of available system memory in MB
        available_memory = psutil.virtual_memory().available
        max_memory_mb = int((available_memory * 0.7) / (1024 * 1024))  # 70% of available memory
        
        # Cap at 5000MB if it's higher (Semgrep's recommended limit)
        max_memory_mb = min(max_memory_mb, 5000)
        
        cmd = [
            "semgrep",
            "scan",
            "--config=auto",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout",
            str(self.config.timeout_seconds),
            "--max-memory",
            f"{max_memory_mb}",
            "--jobs",
            "1",  # Use single job to reduce memory usage
            str(target_dir)
        ]

        logger.info(f"Running Semgrep scan with {max_memory_mb}MB max memory")
        logger.debug(f"Full command: {' '.join(cmd)}")

        try:
            # Set ulimit for stack size (helps with memory issues)
            import resource
            resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except Exception as e:
            logger.warning(f"Could not set stack limit: {e}")

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
            stderr_str = stderr.decode() if stderr else ""

            # Try to parse JSON output
            try:
                if stdout_str.strip():
                    results = json.loads(stdout_str)
                    
                    # Check for memory-related errors
                    if results.get('errors'):
                        for error in results['errors']:
                            if 'memory' in error.get('message', '').lower():
                                logger.error("Memory limit reached, trying with reduced scope")
                                # You might want to implement retry logic here with different parameters
                                
                    # Ensure all required fields exist
                    results.setdefault('results', [])
                    results.setdefault('errors', [])
                    results.setdefault('paths', {'scanned': [], 'ignored': []})
                    
                    logger.info(f"Scan completed: Found {len(results.get('results', []))} issues")
                    return results
                else:
                    logger.info("Scan completed with no output")
                    return {
                        'results': [],
                        'errors': [],
                        'paths': {
                            'scanned': [],
                            'ignored': []
                        },
                        'version': "1.56.0"
                    }

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Semgrep output: {e}\nOutput: {stdout_str[:1000]}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)

        except asyncio.TimeoutError:
            if 'process' in locals():
                try:
                    process.terminate()
                    await process.wait()
                except Exception:
                    pass
            raise RuntimeError(f"Scan timed out after {self.config.timeout_seconds} seconds")
            
        except Exception as e:
            error_msg = f"Scan error: {str(e)}\nStderr: {stderr_str if 'stderr_str' in locals() else 'N/A'}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        try:
            repo_path = await self.clone_repository(repo_url, token)
            
            # Get repository size
            repo_size = await self._get_directory_size(repo_path)
            size_gb = repo_size / (1024 ** 3)
            
            # For large repositories, we might want to scan in chunks
            if size_gb > 1:  # If larger than 1GB
                logger.warning(f"Large repository detected ({size_gb:.2f} GB). Using optimized scan settings.")
                # You might want to implement chunked scanning here
            
            try:
                results = await self._run_semgrep_scan(repo_path)
                return {
                    'success': True,
                    'data': results,
                    'metadata': {
                        'repository_size_gb': size_gb,
                        'scan_timestamp': datetime.now().isoformat()
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
        except Exception as e:
            logger.error(f"Repository scan failed: {str(e)}")
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