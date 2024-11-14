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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Render-optimized scanning configuration"""
    max_file_size_mb: int = 25
    max_total_size_mb: int = 250     # Changed from max_total_size_gb
    max_memory_mb: int = 450
    
    # Timeouts
    timeout_seconds: int = 300
    file_timeout_seconds: int = 30
    max_retries: int = 2
    
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
    """Render-optimized security scanner"""
    
    def __init__(self, config: ScanConfig = ScanConfig(), db_session: Optional[Session] = None):
        self.config = config
        self.db_session = db_session
        self.temp_dir = None
        self.repo_dir = None
        self._session = None  # Add aiohttp session property
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_files': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_too_large': 0,
            'total_size_mb': 0,
            'memory_usage_mb': 0,
            'findings_count': 0
        }

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()
        if self._session and not self._session.closed:
            await self._session.close()

    async def _setup(self):
        """Initialize scanner resources"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
        self._session = aiohttp.ClientSession()  # Initialize aiohttp session
        logger.info(f"Created temporary directory: {self.temp_dir}")
        self.scan_stats['start_time'] = datetime.now()

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                self.scan_stats['end_time'] = datetime.now()
            
            if self._session and not self._session.closed:
                await self._session.close()
                
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

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
                    raise ValueError(f"Failed to get repository info: {await response.text()}")
                
                data = await response.json()
                size_kb = data.get('size', 0)
                size_mb = size_kb / 1024

                return {
                    'size_mb': size_mb,
                    'is_compatible': size_mb <= self.config.max_total_size_mb,
                    'language': data.get('language'),
                    'default_branch': data.get('default_branch')
                }
                    
        except Exception as e:
            logger.error(f"Error checking repository size: {str(e)}")
            raise

    async def _clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with size validation"""
        try:
            # Check repository size first
            size_info = await self._check_repository_size(repo_url, token)
            if not size_info['is_compatible']:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')
            
            logger.info(f"Cloning repository to {self.repo_dir}")
            
            # Basic clone with depth=1
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags'
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
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute memory-conscious semgrep scan"""
        try:
            cmd = [
                "semgrep",
                "scan",
                "--config", "auto",
                "--json",
                "--verbose",
                "--metrics=on",
                
                # Render-specific optimizations
                f"--max-memory", str(self.config.max_memory_mb),
                "--jobs", "1",
                "--timeout", str(self.config.file_timeout_seconds),
                "--timeout-threshold", "2",
                "--skip-git-ignores",
                "--skip-unknown-extensions",
                "--optimizations", "all",
                
                str(target_dir)
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
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

            self.scan_stats['memory_usage_mb'] = psutil.Process().memory_info().rss / (1024 * 1024)
            
            stderr_output = stderr.decode() if stderr else ""
            if stderr_output:
                logger.warning(f"Semgrep stderr: {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result()

            results = json.loads(output)
            return self._process_scan_results(results)

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return self._create_empty_result(error=str(e))

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process scan results with memory tracking"""
        findings = results.get('results', [])
        
        processed_findings = []
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        category_counts = {}
        
        for finding in findings:
            # Skip if finding processing would exceed memory limits
            current_memory = psutil.Process().memory_info().rss / (1024 * 1024)
            if current_memory > self.config.max_memory_mb:
                logger.warning("Memory limit reached during result processing")
                break

            enhanced_finding = {
                'id': finding.get('check_id'),
                'file': finding.get('path'),
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines', ''),
                'message': finding.get('extra', {}).get('message', ''),
                'severity': finding.get('extra', {}).get('severity', 'INFO'),
                'category': finding.get('extra', {}).get('metadata', {}).get('category', 'security'),
                'fix_recommendations': finding.get('extra', {}).get('metadata', {}).get('fix', '')
            }
            
            severity = enhanced_finding['severity']
            category = enhanced_finding['category']
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            
            processed_findings.append(enhanced_finding)
            self.scan_stats['findings_count'] += 1

        return {
            'findings': processed_findings,
            'stats': {
                'total_findings': len(processed_findings),
                'severity_counts': severity_counts,
                'category_counts': category_counts,
                'scan_stats': self.scan_stats,
                'memory_usage_mb': self.scan_stats['memory_usage_mb']
            }
        }

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure"""
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'severity_counts': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
                'category_counts': {},
                'scan_stats': self.scan_stats,
                'memory_usage_mb': self.scan_stats['memory_usage_mb']
            },
            'errors': [error] if error else []
        }

async def scan_repository_handler(
    repo_url: str,
    installation_token: str,
    user_id: str,
    db_session: Optional[Session] = None
) -> Dict:
    """Handler function for web routes"""
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
        config = ScanConfig()
        
        async with SecurityScanner(config, db_session) as scanner:
            try:
                # Pre-check repository size
                size_info = await scanner._check_repository_size(repo_url, installation_token)
                if not size_info['is_compatible']:
                    return {
                        'success': False,
                        'error': {
                            'message': 'Repository too large for analysis',
                            'code': 'REPOSITORY_TOO_LARGE',
                            'details': {
                                'size_mb': size_info['size_mb'],
                                'limit_mb': config.max_total_size_mb,
                                'recommendation': 'Consider analyzing specific directories or upgrading to a paid plan'
                            }
                        }
                    }
                
                results = await scanner.scan_repository(
                    repo_url,
                    installation_token,
                    user_id
                )
                
                return results

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
                'details': str(e),
                'type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }