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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration settings for security scanning"""
    max_file_size_mb: int = 25
    max_total_size_mb: int = 250
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
    """Security scanner optimized for resource-constrained environments"""
    
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
        self._session = aiohttp.ClientSession()
        logger.info(f"Created temporary directory: {self.temp_dir}")
        self.scan_stats['start_time'] = datetime.now()

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            
        
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
                    error_text = await response.text()
                    raise ValueError(f"Failed to get repository info: {error_text}")
                
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
        """Clone repository with size validation and optimizations"""
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
            
            # Optimized clone options
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags',
                f'--branch={size_info["default_branch"]}'
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
            
            # Store the full stderr output which contains the scan statistics
            scan_output = stderr.decode() if stderr else ""

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result()

            self.scan_stats['memory_usage_mb'] = psutil.Process().memory_info().rss / (1024 * 1024)
            
            stderr_output = stderr.decode() if stderr else ""
            if stderr_output and not stderr_output.lower().startswith('running'):
                logger.warning(f"Semgrep stderr: {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result()

            try:
                results = json.loads(output)
                return self._process_scan_results(results)
                processed_results['scan_output'] = scan_output
                return processed_results
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep JSON output: {str(e)}")
                return self._create_empty_result(error="Invalid Semgrep output format")

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return self._create_empty_result(error=str(e))
        
    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
   
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'severity_counts': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFO': 0,
                    'WARNING': 0,
                    'ERROR': 0
                },
                'category_counts': {},
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
                'scan_stats': {
                    'scan_duration': (
                        datetime.now() - self.scan_stats['start_time']
                    ).total_seconds() if self.scan_stats.get('start_time') else 0
                }
            },
            'file_details': {
                'scanned_files': [],
                'skipped_files': [],
                'partial_files': [],
                'error_files': [],
                'files_with_findings': []
            },
            'errors': [error] if error else []
        }
    def _process_scan_results(self, results: Dict) -> Dict:
   
        try:
            findings = results.get('results', [])
            paths = results.get('paths', {})
            errors = results.get('errors', [])
            
            # Track files by status
            files_scanned = set()
            files_skipped = set()
            files_partial = set()
            files_error = set()
            files_with_findings = set()

            # Process scanned files
            scanned_files = paths.get('scanned', [])
            if isinstance(scanned_files, list):
                files_scanned.update(str(path) for path in scanned_files)

            # Process skipped files
            skipped_files = paths.get('skipped', [])
            if isinstance(skipped_files, list):
                for item in skipped_files:
                    if isinstance(item, str):
                        files_skipped.add(item)
                    elif isinstance(item, dict) and 'path' in item:
                        files_skipped.add(item['path'])

            # Process errors and partial files
            for error in errors or []:
                if isinstance(error, dict) and 'path' in error:
                    path = str(error['path'])
                    if 'Partially analyzed' in error.get('message', ''):
                        files_partial.add(path)
                    else:
                        files_error.add(path)

            # Process findings and track files with issues
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

            # Calculate totals and stats
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
                    'scan_stats': {
                        'scan_duration': (datetime.now() - self.scan_stats['start_time']).total_seconds()
                        if self.scan_stats.get('start_time') else 0
                    }
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
            logger.error(f"Error in _process_scan_results: {str(e)}")
            return self._create_empty_result(error=str(e))
    async def scan_repository(self, repo_url: str, installation_token: str, user_id: str) -> Dict:
        
        try:
            # Clone the repository
            repo_dir = await self._clone_repository(repo_url, installation_token)
            
            # Run the semgrep scan
            scan_results = await self._run_semgrep_scan(repo_dir)
            
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
                    'metadata': {
                        'scan_duration_seconds': (
                            datetime.now() - self.scan_stats['start_time']
                        ).total_seconds() if self.scan_stats['start_time'] else 0,
                        'memory_usage_mb': scan_results.get('stats', {}).get('memory_usage_mb', 0)
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
    db_session: Optional[Session] =None
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

    if not repo_url.startswith(('https://github.com/', 'git@github.com:')):
        return {
            'success': False,
            'error': {
                'message': 'Invalid repository URL format',
                'code': 'INVALID_REPOSITORY_URL',
                'details': 'Only GitHub repositories are supported'
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
                                'recommendation': 'Consider analyzing specific directories or branches'
                            }
                        }
                    }
                
                results = await scanner.scan_repository(
                    repo_url,
                    installation_token,
                    user_id
                )
                
                if results.get('success'):
                    # Add repository metadata to results
                    results['data']['repository_info'] = {
                        'size_mb': size_info['size_mb'],
                        'primary_language': size_info['language'],
                        'default_branch': size_info['default_branch']
                    }
                
                return results

            except ValueError as ve:
                return {
                    'success': False,
                    'error': {
                        'message': str(ve),
                        'code': 'VALIDATION_ERROR',
                        'timestamp': datetime.now().isoformat()
                    }
                }
            
            except git.GitCommandError as ge:
                return {
                    'success': False,
                    'error': {
                        'message': 'Git operation failed',
                        'code': 'GIT_ERROR',
                        'details': str(ge),
                        'timestamp': datetime.now().isoformat()
                    }
                }

    except Exception as e:
        logger.error(f"Handler error: {str(e)}")
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error in scan handler',
                'code': 'INTERNAL_ERROR',
                'details': str(e),
                'type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }


# Optional: Add helper functions for common operations
def format_file_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def validate_repository_url(url: str) -> bool:
    """Validate GitHub repository URL format"""
    if not url:
        return False
    
    # Support both HTTPS and SSH formats
    valid_formats = [
        r'https://github.com/[\w-]+/[\w-]+(?:\.git)?$',
        r'git@github\.com:[\w-]+/[\w-]+(?:\.git)?$'
    ]
    
    import re
    return any(re.match(pattern, url) for pattern in valid_formats)


def get_severity_weight(severity: str) -> int:
    """Get numerical weight for severity level for sorting"""
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

from flask import Blueprint, request, jsonify
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy import desc

analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/v1/analysis')

def format_finding(finding: Dict) -> Dict:
    """Format a single finding for API response"""
    return {
        'id': finding.get('id'),
        'file': finding.get('file'),
        'line_start': finding.get('line_start'),
        'line_end': finding.get('line_end'),
        'severity': finding.get('severity', 'UNKNOWN'),
        'category': finding.get('category', 'unknown'),
        'message': finding.get('message'),
        'code_snippet': finding.get('code_snippet'),
        'cwe': finding.get('cwe', []),
        'owasp': finding.get('owasp', []),
        'fix_recommendations': finding.get('fix_recommendations'),
        'references': finding.get('references', [])
    }

@analysis_bp.route('/<owner>/<repo>/result', methods=['GET'])
def get_analysis_findings(owner: str, repo: str):
    """Get detailed findings with filtering and pagination"""
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 10))))
        severity = request.args.get('severity', '').upper()
        category = request.args.get('category', '')
        file_path = request.args.get('file', '')
        
        repo_name = f"{owner}/{repo}"
        
        # Get latest analysis result
        result = AnalysisResult.query.filter_by(
            repository_name=repo_name
        ).order_by(
            desc(AnalysisResult.timestamp)
        ).first()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analysis found',
                    'code': 'ANALYSIS_NOT_FOUND'
                }
            }), 404

        # Extract findings
        findings = result.results.get('findings', [])
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f.get('severity', '').upper() == severity]
        if category:
            findings = [f for f in findings if f.get('category', '').lower() == category.lower()]
        if file_path:
            findings = [f for f in findings if file_path in f.get('file', '')]
        
        # Get total count before pagination
        total_findings = len(findings)
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_findings = findings[start_idx:end_idx]
        
        # Get unique values for filters
        all_severities = sorted(set(f.get('severity', '').upper() for f in findings))
        all_categories = sorted(set(f.get('category', '').lower() for f in findings))
        
        return jsonify({
            'success': True,
            'data': {
                'repository': {
                    'name': repo_name,
                    'owner': owner,
                    'repo': repo
                },
                'metadata': {
                    'analysis_id': result.id,
                    'timestamp': result.timestamp.isoformat(),
                    'status': result.status,
                    'duration_seconds': result.results.get('stats', {}).get('scan_stats', {}).get('scan_duration')
                },
                'summary': {
                    'files_scanned': result.results.get('stats', {}).get('scan_stats', {}).get('total_files_scanned', 0),
                    'total_findings': total_findings,
                    'severity_counts': result.results.get('stats', {}).get('severity_counts', {}),
                    'category_counts': result.results.get('stats', {}).get('category_counts', {})
                },
                'findings': [format_finding(f) for f in paginated_findings],
                'pagination': {
                    'current_page': page,
                    'total_pages': (total_findings + per_page - 1) // per_page,
                    'total_items': total_findings,
                    'per_page': per_page
                },
                'filters': {
                    'available_severities': all_severities,
                    'available_categories': all_categories,
                }
            }
        })
        
    except ValueError as ve:
        return jsonify({
            'success': False,
            'error': {
                'message': str(ve),
                'code': 'INVALID_PARAMETER'
            }
        }), 400
        
    except Exception as e:
        logger.error(f"Error getting findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500
    
