import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
from typing import Dict, List, Optional, Set, Union, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import asyncio
import git
from concurrent.futures import ThreadPoolExecutor
import traceback

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
    chunk_size_mb: int = 100
    timeout_seconds: int = 300
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
        '.vscode',
        'test',
        'tests',
        '__pycache__',
        '*.min.js',
        '*.bundle.js',
        'coverage',
        '.next',
        '.nuxt'
    ])

class GitProgress(git.RemoteProgress):
    """Git progress handler for clone operations"""
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            logger.info(f"Git progress: {message}")

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
        '.md', '.txt',
        
        # Mobile
        '.swift', '.kt', '.java', '.m', '.h'
    }

    def __init__(self, config: ScanConfig = ScanConfig()):
        self.config = config
        self.temp_dir = None
        self.repo_dir = None
        self._executor = ThreadPoolExecutor(max_workers=config.concurrent_processes)

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()
        self._executor.shutdown(wait=True)

    async def _setup(self):
        """Initialize scanner resources"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            # Verify semgrep installation
            try:
                version = subprocess.check_output(['semgrep', '--version'], 
                                               stderr=subprocess.STDOUT).decode().strip()
                logger.info(f"Semgrep version: {version}")
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Semgrep not properly installed: {str(e)}")
                
        except Exception as e:
            logger.error(f"Setup failed: {str(e)}")
            raise

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    async def clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with authentication"""
        try:
            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')

            logger.info(f"Cloning repository to {self.repo_dir}")
            
            # Clone with depth=1 for faster cloning
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                progress=GitProgress(),
                multi_options=['--depth=1']
            )

            # Check repository size
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
            for dirpath, dirnames, filenames in os.walk(directory):
                # Remove excluded directories
                dirnames[:] = [d for d in dirnames 
                             if not any(exclude in d for exclude in self.config.exclude_patterns)]
                
                for filename in filenames:
                    if any(exclude in filename for exclude in self.config.exclude_patterns):
                        continue
                    
                    file_path = Path(dirpath) / filename
                    try:
                        total_size += file_path.stat().st_size
                    except (OSError, IOError) as e:
                        logger.warning(f"Error getting size for {file_path}: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error calculating directory size: {str(e)}")
            raise
            
        return total_size

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with enhanced security rules"""
        try:
            # Check system resources
            memory = psutil.virtual_memory()
            if memory.percent > self.config.max_memory_percent:
                raise ResourceWarning(
                    f"System memory usage ({memory.percent}%) exceeds "
                    f"threshold ({self.config.max_memory_percent}%)"
                )

            # Security rules configuration
            rules = {
                'general': [
                    "p/default",
                    "p/security-audit",
                    "p/owasp-top-ten",
                    "p/secrets"
                ],
                'javascript': [
                    "p/javascript",
                    "p/nodejs",
                    "p/react"
                ],
                'typescript': [
                    "p/typescript",
                    "p/react"
                ],
                'python': [
                    "p/python",
                    "p/django",
                    "p/flask"
                ],
                'java': [
                    "p/java",
                    "p/spring"
                ]
            }

            # Initialize results
            all_results = {
                'results': [],
                'errors': [],
                'paths': {
                    'scanned': set(),
                    'ignored': set()
                },
                'version': "1.56.0",
                'security_summary': {
                    'high_severity': 0,
                    'medium_severity': 0,
                    'low_severity': 0,
                    'categories': set()
                }
            }

            # Collect and group files
            files_by_type = {}
            for root, _, files in os.walk(target_dir):
                if any(exclude in root for exclude in self.config.exclude_patterns):
                    continue
                    
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
                        file_type = self._get_file_type(file_path.suffix.lower())
                        if file_type:
                            files_by_type.setdefault(file_type, []).append(file_path)

            # Run scans for each file type
            for file_type, files in files_by_type.items():
                type_rules = rules.get(file_type, rules['general'])
                chunk_size = min(20, len(files))
                chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]

                for chunk_idx, chunk in enumerate(chunks, 1):
                    chunk_dir = target_dir / f"chunk_{file_type}_{chunk_idx}"
                    chunk_dir.mkdir(exist_ok=True)

                    try:
                        # Copy files to chunk directory
                        for file_path in chunk:
                            rel_path = file_path.relative_to(target_dir)
                            target_path = chunk_dir / rel_path
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(file_path, target_path)

                        # Run scan with each rule
                        for rule in type_rules:
                            cmd = [
                                "semgrep",
                                "scan",
                                "--config", rule,
                                "--json",
                                "--max-memory", "1500",
                                "--timeout", str(self.config.timeout_seconds),
                                "--verbose",
                                str(chunk_dir)
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

                                if stdout:
                                    results = json.loads(stdout.decode())
                                    
                                    # Process findings
                                    for finding in results.get('results', []):
                                        finding['rule_source'] = rule
                                        finding['file_type'] = file_type
                                        
                                        severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                                        if severity == 'ERROR' or severity == 'HIGH':
                                            all_results['security_summary']['high_severity'] += 1
                                        elif severity == 'WARNING' or severity == 'MEDIUM':
                                            all_results['security_summary']['medium_severity'] += 1
                                        elif severity == 'INFO' or severity == 'LOW':
                                            all_results['security_summary']['low_severity'] += 1

                                        category = finding.get('extra', {}).get('metadata', {}).get('category', 'unknown')
                                        all_results['security_summary']['categories'].add(category)
                                        all_results['results'].append(finding)

                                    # Track scanned files
                                    scanned_files = {str(f.relative_to(target_dir)) for f in chunk}
                                    all_results['paths']['scanned'].update(scanned_files)

                            except asyncio.TimeoutError:
                                logger.warning(
                                    f"Timeout scanning chunk {chunk_idx} with rule {rule}"
                                )
                                continue
                            except Exception as e:
                                logger.error(
                                    f"Error scanning chunk {chunk_idx} with rule {rule}: {str(e)}"
                                )
                                continue

                    finally:
                        try:
                            shutil.rmtree(chunk_dir)
                        except Exception as e:
                            logger.error(f"Error cleaning up chunk directory: {str(e)}")

            # Finalize results
            all_results['paths']['scanned'] = list(all_results['paths']['scanned'])
            all_results['paths']['ignored'] = list(all_results['paths']['ignored'])
            all_results['security_summary']['categories'] = list(
                all_results['security_summary']['categories']
            )

            logger.info(
                f"Scan completed: {len(all_results['results'])} findings "
                f"({all_results['security_summary']['high_severity']} high, "
                f"{all_results['security_summary']['medium_severity']} medium, "
                f"{all_results['security_summary']['low_severity']} low severity)"
            )

            return all_results

        except Exception as e:
            logger.error(f"Scan execution failed: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def _get_file_type(self, extension: str) -> Optional[str]:
        """Determine file type based on extension"""
        extension_mapping = {
            'javascript': ['.js', '.jsx', '.vue'],
            'typescript': ['.ts', '.tsx'],
            'python': ['.py'],
            'java': ['.java']
        }
        
        for file_type, extensions in extension_mapping.items():
            if extension in extensions:
                return file_type
        return None

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        scan_start_time = datetime.now()
        
        try:
            # Clone repository
            logger.info(f"Starting repository clone: {repo_url}")
            repo_path = await self.clone_repository(repo_url, token)
            
            # Get repository size for logging
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
            # Run the scan
            results = await self._run_semgrep_scan(repo_path)
            
            # Calculate scan duration
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            
            return {
                'success': True,
                'data': {
                    'results': results.get('results', []),
                    'errors': results.get('errors', []),
                    'paths': {
                        'scanned': results.get('paths', {}).get('scanned', []),
                        'ignored': results.get('paths', {}).get('ignored', [])
                    },
                    'version': results.get('version', '1.56.0'),
                    'security_summary': results.get('security_summary', {
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0,
                        'categories': []
                    }),
                    'scan_status': 'completed',
                    'files_scanned': len(results.get('paths', {}).get('scanned', [])),
                    'total_findings': len(results.get('results', []))
                },
                'metadata': {
                    'repository_url': repo_url,
                    'repository_size_mb': round(size_mb, 2),
                    'scan_start_time': scan_start_time.isoformat(),
                    'scan_end_time': datetime.now().isoformat(),
                    'scan_duration_seconds': round(scan_duration, 2),
                    'scanner_version': '1.56.0'
                }
            }
            
        except git.GitCommandError as e:
            logger.error(f"Git operation failed: {str(e)}")
            return {
                'success': False,
                'error': {
                    'message': f"Repository clone failed: {str(e)}",
                    'type': 'GitCommandError',
                    'timestamp': datetime.now().isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat(),
                    'scan_duration_seconds': round((datetime.now() - scan_start_time).total_seconds(), 2)
                }
            }
        finally:
            try:
                await self._cleanup()
            except Exception as e:
                logger.error(f"Cleanup failed: {str(e)}")


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

    try:
        # Configure scanner
        config = ScanConfig(
            max_file_size_mb=50,
            max_total_size_gb=2,
            max_memory_percent=70,
            timeout_seconds=300,
            max_retries=3,
            concurrent_processes=2
        )
        
        # Initialize and run scanner
        async with ChunkedScanner(config) as scanner:
            try:
                results = await scanner.scan_repository(repo_url, installation_token)
                if results['success']:
                    results['metadata']['user_id'] = user_id
                return results
            except Exception as e:
                logger.error(f"Scan failed: {str(e)}")
                logger.error(traceback.format_exc())
                return {
                    'success': False,
                    'error': {
                        'message': str(e),
                        'type': type(e).__name__,
                        'timestamp': datetime.now().isoformat()
                    }
                }
    except Exception as e:
        logger.error(f"Scanner initialization failed: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'success': False,
            'error': {
                'message': f"Scanner initialization failed: {str(e)}",
                'type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }


def validate_environment() -> bool:
    """Validate required environment and dependencies"""
    try:
        # Check semgrep installation
        subprocess.run(['semgrep', '--version'], 
                     check=True, 
                     capture_output=True)
        
        # Check git installation
        subprocess.run(['git', '--version'], 
                     check=True, 
                     capture_output=True)
        
        # Check system resources
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            logger.warning("System memory usage is very high")
        
        # Check temporary directory access
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b"test")
            
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Dependency check failed: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Environment validation failed: {str(e)}")
        return False


# Validate environment on module import
if not validate_environment():
    logger.error("Failed to validate environment. Scanner may not work correctly.")