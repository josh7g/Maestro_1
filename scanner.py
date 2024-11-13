import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import git
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

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
    concurrent_processes: int = 1
    semgrep_rules: List[str] = field(default_factory=lambda: [
        "p/default",
        "p/security-audit",
        "p/ci",
        "p/owasp-top-ten",
        "p/javascript",
        "p/python",
        "p/java"
    ])
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
        '__pycache__',
        '*.min.js',
        '*.bundle.js'
    ])

class GitProgress(git.RemoteProgress):
    """Progress monitor for git operations"""
    def update(self, op_code, cur_count, max_count=None, message=''):
        if message:
            logger.info(f"Git progress: {message}")
        elif max_count:
            progress = (cur_count / max_count) * 100
            logger.info(f"Git progress: {progress:.1f}%")

class ChunkedScanner:
    """Enhanced scanner class for processing repositories"""
    SCANNABLE_EXTENSIONS = {
        # Web development
        '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
        '.html', '.htm', '.css', '.scss', '.sass', '.less',
        
        # Backend development
        '.py', '.rb', '.php', '.java', '.go', '.cs', '.cpp',
        '.c', '.h', '.hpp', '.scala', '.kt', '.rs',
        
        # Configuration and data
        '.json', '.yml', '.yaml', '.xml', '.conf', '.ini',
        '.env', '.properties', '.toml',
        
        # Scripts and templates
        '.sh', '.bash', '.ps1', '.ejs', '.hbs', '.pug',
        '.tpl', '.template',
        
        # Documentation and others
        '.md', '.txt', '.sql', '.graphql'
    }
    
    def __init__(self, config: ScanConfig = ScanConfig()):
        self.config = config
        self.temp_dir = None
        self.repo_dir = None
        self._setup_logging()

    def _setup_logging(self):
        """Setup detailed logging for the scanner"""
        self.logger = logging.getLogger(__name__)
        log_handler = logging.StreamHandler()
        log_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        log_handler.setFormatter(log_formatter)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(logging.INFO)

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner resources"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
        self.logger.info(f"Created temporary directory: {self.temp_dir}")

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    async def _get_directory_size(self, directory: Path) -> int:
        """Calculate directory size excluding ignored paths"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [d for d in dirnames if not any(
                exclude in d for exclude in self.config.exclude_patterns
            )]
            
            for filename in filenames:
                if any(exclude in filename for exclude in self.config.exclude_patterns):
                    continue
                    
                file_path = Path(dirpath) / filename
                try:
                    total_size += file_path.stat().st_size
                except (OSError, FileNotFoundError):
                    continue
                    
        return total_size

    async def clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with authentication and size validation"""
        try:
            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')

            self.logger.info(f"Cloning repository to {self.repo_dir}")
            
            # Configure git options for efficient cloning
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags',
                '--recursive'
            ]
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                progress=GitProgress(),
                multi_options=git_options
            )

            repo_size = await self._get_directory_size(self.repo_dir)
            size_gb = repo_size / (1024 ** 3)
            
            if size_gb > self.config.max_total_size_gb:
                raise ValueError(
                    f"Repository size ({size_gb:.2f} GB) exceeds "
                    f"limit of {self.config.max_total_size_gb} GB"
                )

            self.logger.info(f"Successfully cloned repository: {size_gb:.2f} GB")
            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _prepare_chunk(self, chunk: List[Path], chunk_dir: Path) -> Dict[str, str]:
        """Prepare a chunk of files for scanning"""
        chunk_file_mapping = {}
        for file_path in chunk:
            try:
                rel_path = file_path.relative_to(self.repo_dir)
                target_path = chunk_dir / rel_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, target_path)
                chunk_file_mapping[str(rel_path)] = str(file_path)
            except Exception as e:
                self.logger.error(f"Error copying file {file_path}: {e}")
        return chunk_file_mapping

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with comprehensive configuration"""
        max_memory_mb = 2000
        all_files = []
        file_mapping = {}

        # Collect scannable files
        for root, _, files in os.walk(target_dir):
            if any(exclude in root for exclude in self.config.exclude_patterns):
                continue
            for file in files:
                file_path = Path(root) / file
                if (file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS and 
                    file_path.stat().st_size <= self.config.max_file_size_mb * 1024 * 1024):
                    all_files.append(file_path)
                    file_mapping[str(file_path.relative_to(target_dir))] = str(file_path)

        # Split into chunks
        chunk_size = 20
        chunks = [all_files[i:i + chunk_size] for i in range(0, len(all_files), chunk_size)]
        
        self.logger.info(f"Split scanning into {len(chunks)} chunks of {chunk_size} files each")

        all_results = {
            'results': [],
            'errors': [],
            'paths': {
                'scanned': set(),
                'ignored': set()
            },
            'version': "1.56.0",
            'stats': {
                'total_chunks': len(chunks),
                'completed_chunks': 0,
                'failed_chunks': 0
            }
        }

        for i, chunk in enumerate(chunks, 1):
            self.logger.info(f"Scanning chunk {i}/{len(chunks)} with {len(chunk)} files")
            chunk_dir = target_dir / f"chunk_{i}"
            chunk_dir.mkdir(exist_ok=True)

            try:
                chunk_file_mapping = await self._prepare_chunk(chunk, chunk_dir)
                
                # Build semgrep command with all configurations
                cmd = ["semgrep", "scan"]
                
                # Add all rule configurations
                for rule in self.config.semgrep_rules:
                    cmd.extend(["--config", rule])
                
                # Add other options
                cmd.extend([
                    "--json",
                    "--max-memory", str(max_memory_mb),
                    "--timeout", "300",
                    "--jobs", "1",
                    "--severity", "INFO",
                    "--enable-nosem",
                    "--enable-metrics",
                    "--verbose",
                    str(chunk_dir)
                ])

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
                    stderr_str = stderr.decode() if stderr else ""
                    
                    if stderr_str:
                        self.logger.warning(f"Semgrep stderr for chunk {i}: {stderr_str}")

                    if stdout_str.strip():
                        chunk_results = json.loads(stdout_str)
                        all_results['paths']['scanned'].update(chunk_file_mapping.keys())

                        # Process findings
                        for finding in chunk_results.get('results', []):
                            if 'path' in finding:
                                rel_path = finding['path']
                                finding['path'] = chunk_file_mapping.get(rel_path, rel_path)
                                finding['chunk_info'] = {
                                    'chunk_number': i,
                                    'total_chunks': len(chunks)
                                }
                            all_results['results'].append(finding)

                        # Add any errors
                        chunk_errors = chunk_results.get('errors', [])
                        for error in chunk_errors:
                            error['chunk_number'] = i
                        all_results['errors'].extend(chunk_errors)

                        self.logger.info(
                            f"Successfully scanned chunk {i} with "
                            f"{len(chunk_results.get('results', []))} findings and "
                            f"{len(chunk_errors)} errors"
                        )
                        all_results['stats']['completed_chunks'] += 1

                except asyncio.TimeoutError:
                    self.logger.warning(f"Timeout scanning chunk {i}")
                    all_results['errors'].append({
                        'code': 'timeout',
                        'message': f'Chunk {i} scanning timed out after 300 seconds',
                        'chunk_number': i
                    })
                    all_results['stats']['failed_chunks'] += 1
                    continue

            except Exception as e:
                self.logger.error(f"Error processing chunk {i}: {str(e)}")
                all_results['errors'].append({
                    'code': 'chunk_error',
                    'message': f'Error processing chunk {i}: {str(e)}',
                    'chunk_number': i
                })
                all_results['stats']['failed_chunks'] += 1
                continue

            finally:
                try:
                    shutil.rmtree(chunk_dir)
                except Exception as e:
                    self.logger.error(f"Error cleaning up chunk directory: {str(e)}")

        # Convert sets to lists for JSON serialization
        all_results['paths']['scanned'] = list(all_results['paths']['scanned'])
        all_results['paths']['ignored'] = list(all_results['paths']['ignored'])

        # Add final statistics
        all_results['stats']['total_findings'] = len(all_results['results'])
        all_results['stats']['total_errors'] = len(all_results['errors'])
        all_results['stats']['files_scanned'] = len(all_results['paths']['scanned'])
        all_results['stats']['success_rate'] = (
            all_results['stats']['completed_chunks'] / 
            all_results['stats']['total_chunks'] * 100
        )

        self.logger.info(
            f"Completed scan: {all_results['stats']['total_findings']} findings, "
            f"{all_results['stats']['files_scanned']} files scanned, "
            f"{all_results['stats']['total_errors']} errors, "
            f"{all_results['stats']['success_rate']:.1f}% chunks completed successfully"
        )
        
        return all_results

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository with comprehensive error handling"""
        scan_start_time = datetime.now()
        
        try:
            repo_path = await self.clone_repository(repo_url, token)
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            
            self.logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
            results = await self._run_semgrep_scan(repo_path)
            
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            
            return {
                'success': True,
                'data': {
                    'results': results['results'],
                    'errors': results['errors'],
                    'paths': results['paths'],
                    'version': results['version'],
                    'stats': results['stats'],
                    'scan_status': 'completed',
                    'scan_duration_seconds': scan_duration
                },
                'metadata': {
                    'repository_size_mb': round(size_mb, 2),
                    'scan_timestamp': scan_start_time.isoformat(),
                    'completion_timestamp': datetime.now().isoformat(),
                    'files_analyzed': len(results['paths']['scanned']),
                    'findings_count': len(results['results']),
                    'success_rate': results['stats']['success_rate'],
                    'performance_metrics': {
                        'average_time_per_chunk': scan_duration / results['stats']['total_chunks'],
                        'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024)
                    }
                }
            }
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
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


async def scan_repository_handler(repo_url: str, installation_token: str, user_id: str) -> Dict:
    """Handler function for web routes with enhanced validation and error handling"""
    logger.info(f"Starting scan for repository: {repo_url}")
    
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

    # Validate repository URL format
    if not repo_url.startswith(('http://', 'https://')):
        return {
            'success': False,
            'error': {
                'message': 'Invalid repository URL format',
                'code': 'INVALID_URL_FORMAT'
            }
        }

    try:
        # Create scanner configuration with optimized settings
        config = ScanConfig(
            max_file_size_mb=50,
            max_total_size_gb=2,
            max_memory_percent=70,
            chunk_size_mb=500,
            timeout_seconds=3600,
            max_retries=3,
            concurrent_processes=1,
            semgrep_rules=[
                "p/default",
                "p/security-audit",
                "p/ci",
                "p/owasp-top-ten",
                "p/javascript",
                "p/python",
                "p/java"
            ]
        )
        
        # Initialize system metrics
        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        start_time = datetime.now()
        
        async with ChunkedScanner(config) as scanner:
            try:
                results = await scanner.scan_repository(repo_url, installation_token)
                
                # Calculate performance metrics
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
                memory_change = final_memory - initial_memory
                
                # Add performance metrics to results
                if results['success']:
                    results['metadata']['performance'] = {
                        'scan_duration_seconds': duration,
                        'initial_memory_mb': round(initial_memory, 2),
                        'final_memory_mb': round(final_memory, 2),
                        'memory_change_mb': round(memory_change, 2)
                    }
                    
                    results['metadata']['user_id'] = user_id
                    results['metadata']['scan_timestamp'] = start_time.isoformat()
                    
                    logger.info(
                        f"Scan completed successfully in {duration:.1f} seconds. "
                        f"Memory usage: {memory_change:.1f}MB"
                    )
                else:
                    logger.error(f"Scan failed: {results.get('error', {}).get('message')}")
                
                return results
                
            except Exception as e:
                logger.error(f"Scan failed with exception: {str(e)}")
                return {
                    'success': False,
                    'error': {
                        'message': str(e),
                        'type': type(e).__name__,
                        'timestamp': datetime.now().isoformat(),
                        'performance': {
                            'duration_seconds': (datetime.now() - start_time).total_seconds(),
                            'memory_usage_mb': round(memory_change, 2)
                        }
                    }
                }
    except Exception as e:
        logger.error(f"Handler error: {str(e)}")
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error in scan handler',
                'details': str(e),
                'type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }


# Optional: Add utility functions for testing and debugging
def test_scanner_config(config: ScanConfig) -> Dict:
    """Test scanner configuration and validate settings"""
    issues = []
    
    # Check memory limits
    system_memory = psutil.virtual_memory().total / (1024 ** 3)  # GB
    if config.max_total_size_gb > system_memory * 0.8:
        issues.append(f"max_total_size_gb ({config.max_total_size_gb}GB) may be too high for system memory ({system_memory:.1f}GB)")
    
    # Check concurrent processes
    cpu_count = psutil.cpu_count()
    if config.concurrent_processes > cpu_count:
        issues.append(f"concurrent_processes ({config.concurrent_processes}) exceeds CPU count ({cpu_count})")
    
    # Validate semgrep rules
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
        for rule in config.semgrep_rules:
            subprocess.run(["semgrep", "--validate", f"--config={rule}"], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        issues.append(f"Semgrep rule validation failed: {str(e)}")
    except FileNotFoundError:
        issues.append("Semgrep not found in system PATH")
    
    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'config': {
            'max_file_size_mb': config.max_file_size_mb,
            'max_total_size_gb': config.max_total_size_gb,
            'max_memory_percent': config.max_memory_percent,
            'timeout_seconds': config.timeout_seconds,
            'concurrent_processes': config.concurrent_processes,
            'rules_count': len(config.semgrep_rules)
        }
    }

def get_scanner_status() -> Dict:
    """Get current scanner status and system resources"""
    return {
        'timestamp': datetime.now().isoformat(),
        'system_resources': {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_available_gb': psutil.virtual_memory().available / (1024 ** 3),
            'disk_usage_percent': psutil.disk_usage('/').percent
        },
        'semgrep_version': subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True
        ).stdout.strip(),
        'scanner_ready': True
    }

if __name__ == "__main__":
    # Example usage and testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Semgrep Scanner CLI")
    parser.add_argument("--repo-url", help="Repository URL to scan")
    parser.add_argument("--token", help="GitHub token for authentication")
    parser.add_argument("--user-id", help="User ID for the scan")
    parser.add_argument("--test-config", action="store_true", help="Test scanner configuration")
    parser.add_argument("--status", action="store_true", help="Get scanner status")
    
    args = parser.parse_args()
    
    if args.test_config:
        print(json.dumps(test_scanner_config(ScanConfig()), indent=2))
    elif args.status:
        print(json.dumps(get_scanner_status(), indent=2))
    elif all([args.repo_url, args.token, args.user_id]):
        import asyncio
        result = asyncio.run(scan_repository_handler(args.repo_url, args.token, args.user_id))
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()