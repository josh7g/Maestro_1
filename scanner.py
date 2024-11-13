import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import git
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
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
        '.env', '.properties', '.toml',
        
        # Scripts and templates
        '.sh', '.bash', '.ps1', '.ejs', '.hbs', '.pug',
        '.tpl', '.template',
        
        # Documentation and others
        '.md', '.txt', '.sql', '.graphql'
    }
    
    SEMGREP_RULES = [
        "p/security-audit",
        "p/owasp-top-ten",
        "p/javascript",
        "p/python",
        "p/java",
        "p/sql-injection",
        "p/xss",
        "p/secrets"
    ]
    
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

            logger.info(f"Cloning repository to {self.repo_dir}")
            
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags'
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

            logger.info(f"Successfully cloned repository: {size_gb:.2f} GB")
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
                logger.error(f"Error copying file {file_path}: {e}")
        return chunk_file_mapping
    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with optimized configuration"""
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
        
        logger.info(f"Split scanning into {len(chunks)} chunks of {chunk_size} files each")

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
            logger.info(f"Scanning chunk {i}/{len(chunks)} with {len(chunk)} files")
            chunk_dir = target_dir / f"chunk_{i}"
            chunk_dir.mkdir(exist_ok=True)

            try:
                chunk_file_mapping = await self._prepare_chunk(chunk, chunk_dir)
                
                # Basic semgrep command
                cmd = [
                    "semgrep",
                    "scan",
                    "--json",
                    "--metrics=off",
                    "--max-memory", str(max_memory_mb),
                    "--timeout", "300",
                    "--severity", "INFO"
                ]
                
                # Add config rules
                cmd.extend(["--config", "auto"])
                
                # Add target directory
                cmd.append(str(chunk_dir))

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
                    
                    if stderr_str and "No findings were found" not in stderr_str:
                        logger.warning(f"Semgrep stderr for chunk {i}: {stderr_str}")

                    if stdout_str.strip():
                        try:
                            chunk_results = json.loads(stdout_str)
                            all_results['paths']['scanned'].update(chunk_file_mapping.keys())

                            for finding in chunk_results.get('results', []):
                                if 'path' in finding:
                                    rel_path = finding['path']
                                    finding['path'] = chunk_file_mapping.get(rel_path, rel_path)
                                    finding['chunk_info'] = {
                                        'chunk_number': i,
                                        'total_chunks': len(chunks)
                                    }
                                all_results['results'].append(finding)

                            logger.info(
                                f"Successfully scanned chunk {i} with "
                                f"{len(chunk_results.get('results', []))} findings"
                            )
                            all_results['stats']['completed_chunks'] += 1

                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse semgrep output for chunk {i}: {e}")
                            all_results['stats']['failed_chunks'] += 1

                except asyncio.TimeoutError:
                    logger.warning(f"Timeout scanning chunk {i}")
                    all_results['stats']['failed_chunks'] += 1
                    continue

            except Exception as e:
                logger.error(f"Error processing chunk {i}: {str(e)}")
                all_results['stats']['failed_chunks'] += 1
                continue

            finally:
                try:
                    shutil.rmtree(chunk_dir)
                except Exception as e:
                    logger.error(f"Error cleaning up chunk directory: {str(e)}")

        # Finalize results
        all_results['paths']['scanned'] = list(all_results['paths']['scanned'])
        all_results['paths']['ignored'] = list(all_results['paths']['ignored'])
        all_results['stats']['total_findings'] = len(all_results['results'])
        all_results['stats']['files_scanned'] = len(all_results['paths']['scanned'])
        all_results['stats']['success_rate'] = (
            all_results['stats']['completed_chunks'] / 
            all_results['stats']['total_chunks'] * 100
        ) if all_results['stats']['total_chunks'] > 0 else 0

        logger.info(
            f"Completed scan: {all_results['stats']['total_findings']} findings, "
            f"{all_results['stats']['files_scanned']} files scanned, "
            f"{all_results['stats']['success_rate']:.1f}% chunks completed successfully"
        )
        
        return all_results

    async def scan_repository(self, repo_url: str, token: str) -> Dict:
        """Main method to scan a repository"""
        scan_start_time = datetime.now()
        
        try:
            repo_path = await self.clone_repository(repo_url, token)
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            
            logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
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
                    'performance_metrics': {
                        'total_duration_seconds': scan_duration,
                        'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024)
                    }
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

async def scan_repository_handler(repo_url: str, installation_token: str, user_id: str) -> Dict:
    """Handler function for web routes"""
    logger.info(f"Starting scan request for repository: {repo_url}")
    
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
        config = ScanConfig()
        start_time = datetime.now()
        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        
        async with ChunkedScanner(config) as scanner:
            try:
                results = await scanner.scan_repository(repo_url, installation_token)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
                memory_change = final_memory - initial_memory
                
                if results['success']:
                    results['metadata']['performance_metrics'].update({
                        'total_duration_seconds': duration,
                        'initial_memory_mb': round(initial_memory, 2),
                        'final_memory_mb': round(final_memory, 2),
                        'memory_change_mb': round(memory_change, 2)
                    })
                    
                    results['metadata']['user_id'] = user_id
                    
                    logger.info(
                        f"Scan completed successfully in {duration:.1f} seconds. "
                        f"Memory usage: {memory_change:.1f}MB"
                    )
                    
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

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Semgrep Security Scanner")
    parser.add_argument("--repo-url", help="Repository URL to scan")
    parser.add_argument("--token", help="GitHub token for authentication")
    parser.add_argument("--user-id", help="User ID for the scan")
    
    args = parser.parse_args()
    
    if all([args.repo_url, args.token, args.user_id]):
        result = asyncio.run(scan_repository_handler(
            args.repo_url,
            args.token,
            args.user_id
        ))
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()