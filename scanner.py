import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import aiohttp
import git
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Suppress asyncio warnings about long-running tasks
logging.getLogger("asyncio").setLevel(logging.ERROR)

@dataclass
class ScanConfig:
    """Configuration settings for security scanning optimized for Standard plan"""
    # Resource limits for 2GB RAM, 1 CPU
    max_file_size_mb: int = 100
    max_total_size_mb: int = 1000
    max_memory_mb: int = 1800  # Leave 200MB buffer
    
    # Timeouts
    timeout_seconds: int = 600
    file_timeout_seconds: int = 60
    max_retries: int = 3
    
    # Process limits
    concurrent_processes: int = 1
    exclude_patterns: List[str] = field(default_factory=lambda: [
        # Version Control
        '.git',
        '.svn',
        
        # Dependencies
        'node_modules',
        'vendor',
        'bower_components',
        'packages',
        
        # Build outputs
        'dist',
        'build',
        'out',
        
        # Environment
        'venv',
        '.env',
        '__pycache__',
        
        # Minified files
        '*.min.js',
        '*.min.css',
        '*.bundle.js',
        '*.bundle.css',
        '*.map',
        
        # Large file types
        '*.pdf',
        '*.jpg',
        '*.jpeg',
        '*.png',
        '*.gif',
        '*.zip',
        '*.tar',
        '*.gz',
        '*.rar',
        '*.mp4',
        '*.mov'
    ])

class SecurityScanner:
    """Security scanner optimized for Standard plan resources"""
    
    def __init__(self, config: ScanConfig = ScanConfig(), db_session: Optional[Session] = None):
        self.config = config
        self.db_session = db_session
        self.temp_dir = None
        self.repo_dir = None
        self._session = None
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_files': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_too_large': 0,
            'total_size_mb': 0,
            'memory_usage_mb': 0,
            'findings_count': 0,
            'peak_memory_mb': 0
        }
        self.memory_monitor_task = None

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()
        if self._session and not self._session.closed:
            await self._session.close()

    async def _monitor_memory_usage(self):
        """Monitor memory usage during scan"""
        while True:
            try:
                process = psutil.Process()
                current_memory = process.memory_info().rss / (1024 * 1024)
                self.scan_stats['peak_memory_mb'] = max(
                    self.scan_stats['peak_memory_mb'], 
                    current_memory
                )
                
                if current_memory > self.config.max_memory_mb * 0.9:
                    logger.warning(
                        f"High memory usage detected: {current_memory:.2f}MB / "
                        f"{self.config.max_memory_mb}MB"
                    )
                
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error monitoring memory: {str(e)}")
                await asyncio.sleep(5)

    async def _setup(self):
        """Initialize scanner resources"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
            self._session = aiohttp.ClientSession()
            self.memory_monitor_task = asyncio.create_task(self._monitor_memory_usage())
            self.scan_stats['start_time'] = datetime.now()
            logger.info(f"Scanner initialized. Temp directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Setup error: {str(e)}")
            await self._cleanup()
            raise

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.memory_monitor_task:
                self.memory_monitor_task.cancel()
                try:
                    await self.memory_monitor_task
                except asyncio.CancelledError:
                    pass

            if self._session and not self._session.closed:
                await self._session.close()

            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")

        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")

    async def _check_repository_size(self, repo_url: str, token: str) -> Dict:
        """Pre-check repository size using GitHub API"""
        try:
            owner, repo = repo_url.split('github.com/')[-1].replace('.git', '').split('/')
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            async with self._session.get(api_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(f"Failed to get repository info: {error_text}")
                
                data = await response.json()
                size_kb = data.get('size', 0)
                size_mb = size_kb / 1024

                return {
                    'size_mb': size_mb,
                    'is_compatible': size_mb <= self.config.max_total_size_mb,
                    'language': data.get('language'),
                    'default_branch': data.get('default_branch'),
                    'topics': data.get('topics', []),
                    'visibility': data.get('visibility'),
                    'fork_count': data.get('forks_count'),
                    'last_updated': data.get('updated_at')
                }
                    
        except Exception as e:
            logger.error(f"Repository size check error: {str(e)}")
            raise

    async def _clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with size validation and optimizations"""
        try:
            size_info = await self._check_repository_size(repo_url, token)
            if not size_info['is_compatible']:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')
            
            logger.info(f"Cloning repository to {self.repo_dir}")
            
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags',
                f'--branch={size_info["default_branch"]}',
                '--filter=blob:none',
                '--sparse'
            ]
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                multi_options=git_options
            )

            logger.info(f"Successfully cloned repository: {size_info['size_mb']:.2f}MB")
            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir, ignore_errors=True)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute optimized semgrep scan"""
        try:
            # Create .semgrepignore file
            semgrepignore_path = target_dir / '.semgrepignore'
            with open(semgrepignore_path, 'w') as f:
                for pattern in self.config.exclude_patterns:
                    f.write(f"{pattern}\n")

            cmd = [
                "semgrep",
                "scan",
                "--config", "auto",
                "--json",
                "--verbose",
                "--metrics=on",
                
                # Resource limits
                f"--max-memory={self.config.max_memory_mb}",
                f"--jobs={self.config.concurrent_processes}",
                f"--timeout={self.config.file_timeout_seconds}",
                f"--timeout-threshold={self.config.max_retries}",
                
                # Optimization flags
                "--no-git-ignore",
                "--skip-unknown-extensions",
                "--optimizations=all",
             
                
                str(target_dir)
            ]

            env = os.environ.copy()
            env.update({
                'SEMGREP_ENABLE_VERSION_CHECK': '0',
                'SEMGREP_SEND_METRICS': '1',
                'SEMGREP_PROGRESS_FORMAT': 'tqdm'
            })

            

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir),
                env=env
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout_seconds
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Scan timed out after {self.config.timeout_seconds}s")
                return self._create_empty_result(error="Scan timed out")
            
            stderr_output = stderr.decode() if stderr else ""
            if stderr_output and not stderr_output.lower().startswith('running'):
                logger.warning(f"Semgrep stderr: {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result()

            try:
                results = json.loads(output)
                processed_results = self._process_scan_results(results)
                processed_results['scan_output'] = stderr_output
                return processed_results
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep JSON output: {str(e)}")
                return self._create_empty_result(error="Invalid Semgrep output format")

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return self._create_empty_result(error=str(e))

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure"""
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'severity_counts': defaultdict(int),
                'category_counts': defaultdict(int),
                'file_stats': {
                    'total_files': 0,
                    'files_scanned': 0,
                    'files_with_findings': 0,
                    'files_skipped': 0,
                    'files_partial': 0,
                    'files_error': 0,
                    'completion_rate': 0
                },
                'memory_usage_mb': self.scan_stats['memory_usage_mb'],
                'peak_memory_mb': self.scan_stats['peak_memory_mb'],
                'scan_duration': (
                    datetime.now() - self.scan_stats['start_time']
                ).total_seconds() if self.scan_stats['start_time'] else 0
            },
            'errors': [error] if error else []
        }

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and analyze scan results"""
        try:
            findings = results.get('results', [])
            paths = results.get('paths', {})
            errors = results.get('errors', [])
            
            files_scanned = set()
            files_skipped = set()
            files_partial = set()
            files_error = set()
            files_with_findings = set()

            for path in paths.get('scanned', []):
                files_scanned.add(str(path))
            
            for item in paths.get('skipped', []):
                if isinstance(item, str):
                    files_skipped.add(item)
                elif isinstance(item, dict) and 'path' in item:
                    files_skipped.add(item['path'])

            for error in errors or []:
                if isinstance(error, dict) and 'path' in error:
                    path = str(error['path'])
                    if 'Partially analyzed' in error.get('message', ''):
                        files_partial.add(path)
                    else:
                        files_error.add(path)

            processed_findings = []
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)

            for finding in findings:
                file_path = str(finding.get('path', ''))
                if file_path:
                    files_with_findings.add(file_path)

                severity = finding.get('extra', {}).get('severity', 'INFO').upper()
                category = finding.get('extra', {}).get('metadata', {}).get('category', 'security')
                
                severity_counts[severity] += 1
                category_counts[category] += 1
                
                processed_findings.append({
                    'id': finding.get('check_id'),
                    'file': file_path,
                    'line_start': finding.get('start', {}).get('line'),
                    'line_end': finding.get('end', {}).get('line'),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': severity,
                    'category': category,
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'fix_recommendations': finding.get('extra', {}).get('metadata', {}).get('fix', ''),
                    'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                })

            total_files = len(files_scanned.union(files_skipped, files_partial, files_error))
            completion_rate = (len(files_scanned) / total_files * 100) if total_files > 0 else 0

            return {
                'findings': processed_findings,
                'stats': {
                    'total_findings': len(processed_findings),
                    'severity_counts': dict(severity_counts),
                    'category_counts': dict(category_counts),
                    'file_stats': {
                        'total_files': total_files,
                        'files_scanned': len(files_scanned),
                        'files_with_findings': len(files_with_findings),
                        'files_skipped': len(files_skipped),
                        'files_partial': len(files_partial),
                        'files_error': len(files_error),
                        'completion_rate': round(completion_rate, 2)
                    },
                    'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024),
                    'peak_memory_mb': self.scan_stats['peak_memory_mb'],
                    'scan_duration': (
                        datetime.now() - self.scan_stats['start_time']
                    ).total_seconds()
                },
                'file_details': {
                    'scanned_files': sorted(files_scanned),
                    'skipped_files': sorted(files_skipped),
                    'partial_files': sorted(files_partial),
                    'error_files': sorted(files_error),
                    'files_with_findings': sorted(files_with_findings)
                }
            }

        except Exception as e:
            logger.error(f"Error processing scan results: {str(e)}")
            return self._create_empty_result(error=str(e))

    async def scan_repository(self, repo_url: str, installation_token: str, user_id: str) -> Dict:
        """Main method to scan a repository"""
        try:
            # Clone the repository
            repo_dir = await self._clone_repository(repo_url, installation_token)
            
            # Run the semgrep scan
            scan_results = await self._run_semgrep_scan(repo_dir)
            
            # Get repository metadata
            repo_info = await self._check_repository_size(repo_url, installation_token)
            
            self.scan_stats['end_time'] = datetime.now()
            scan_duration = (self.scan_stats['end_time'] - self.scan_stats['start_time']).total_seconds()
            
            return {
                'success': True,
                'data': {
                    'repository': repo_url,
                    'user_id': user_id,
                    'timestamp': datetime.now().isoformat(),
                    'findings': scan_results.get('findings', []),
                    'summary': {
                        'total_findings': scan_results.get('stats', {}).get('total_findings', 0),
                        'severity_counts': scan_results.get('stats', {}).get('severity_counts', {}),
                        'category_counts': scan_results.get('stats', {}).get('category_counts', {}),
                        'files_scanned': scan_results.get('stats', {}).get('file_stats', {}).get('files_scanned', 0),
                    },
                    'repository_info': {
                        'size_mb': repo_info['size_mb'],
                        'primary_language': repo_info['language'],
                        'default_branch': repo_info['default_branch'],
                        'topics': repo_info['topics'],
                        'visibility': repo_info['visibility'],
                        'fork_count': repo_info['fork_count'],
                        'last_updated': repo_info['last_updated']
                    },
                    'scan_metadata': {
                        'duration_seconds': scan_duration,
                        'memory_usage_mb': self.scan_stats['memory_usage_mb'],
                        'peak_memory_mb': self.scan_stats['peak_memory_mb'],
                        'start_time': self.scan_stats['start_time'].isoformat(),
                        'end_time': self.scan_stats['end_time'].isoformat(),
                        'completion_rate': scan_results.get('stats', {}).get('file_stats', {}).get('completion_rate', 0)
                    }
                }
            }
                
        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }

async def scan_repository_handler(
    repo_url: str,
    installation_token: str,
    user_id: str,
    db_session: Optional[Session] = None
) -> Dict:
    """Handler function for web routes with input validation"""
    logger.info(f"Starting scan request for repository: {repo_url}")
    
    if not all([repo_url, installation_token, user_id]):
        return {
            'success': False,
            'error': {
                'message': 'Missing required parameters',
                'code': 'INVALID_PARAMETERS'
            }
        }

    try:
        # Increase timeout for the entire scanning process
        return await asyncio.wait_for(
            _scan_repository_handler_inner(repo_url, installation_token, user_id, db_session),
            timeout=600  # 10 minutes timeout
        )
    except asyncio.TimeoutError:
        return {
            'success': False,
            'error': {
                'message': 'Scan operation timed out',
                'code': 'SCAN_TIMEOUT'
            }
        }

async def _scan_repository_handler_inner(
    repo_url: str,
    installation_token: str,
    user_id: str,
    db_session: Optional[Session] = None
) -> Dict:
    """Internal handler with actual scan logic"""
    try:
        config = ScanConfig()
        
        async with SecurityScanner(config, db_session) as scanner:
            try:
                return await scanner.scan_repository(
                    repo_url,
                    installation_token,
                    user_id
                )
            except ValueError as ve:
                return {
                    'success': False,
                    'error': {
                        'message': str(ve),
                        'code': 'VALIDATION_ERROR'
                    }
                }
            
    except Exception as e:
        logger.error(f"Handler error: {str(e)}")
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error in scan handler',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }

# Utility functions
def validate_repository_url(url: str) -> bool:
    """Validate GitHub repository URL format"""
    if not url:
        return False
    
    import re
    valid_formats = [
        r'https://github.com/[\w-]+/[\w-]+(?:\.git)?$',
        r'git@github\.com:[\w-]+/[\w-]+(?:\.git)?$'
    ]
    
    return any(re.match(pattern, url) for pattern in valid_formats)

def get_severity_weight(severity: str) -> int:
    """Get numerical weight for severity level"""
    weights = {
        'CRITICAL': 5,
        'HIGH': 4,
        'MEDIUM': 3,
        'LOW': 2,
        'INFO': 1
    }
    return weights.get(severity.upper(), 0)

def sort_findings_by_severity(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity level"""
    return sorted(
        findings,
        key=lambda x: get_severity_weight(x.get('severity', 'INFO')),
        reverse=True
    )

if __name__ == "__main__":
    # Example usage
    async def main():
        repo_url = "https://github.com/username/repo"
        token = "your_token"
        user_id = "test_user"
        
        result = await scan_repository_handler(repo_url, token, user_id)
        print(json.dumps(result, indent=2))

    asyncio.run(main())