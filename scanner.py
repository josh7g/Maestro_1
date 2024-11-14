import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import git
from typing import Dict, List, Optional, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

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
    max_file_size_mb: int = 100
    max_total_size_gb: int = 5
    max_memory_percent: int = 90
    timeout_seconds: int = 3600
    max_retries: int = 3
    concurrent_processes: int = 1
    exclude_patterns: List[str] = field(default_factory=lambda: [
        # Basic exclusions that won't interfere with scanning
        '.git',
        'node_modules',
        'venv',
        '.env',
        '__pycache__',
        '.pytest_cache'
    ])

class ChunkedScanner:
    """Enhanced scanner implementation for multi-language analysis"""
    
    def __init__(self, config: ScanConfig = ScanConfig(), db_session: Optional[Session] = None):
        self.config = config
        self.db_session = db_session
        self.temp_dir = None
        self.repo_dir = None
        self.detected_languages = set()
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_files': 0,
            'files_processed': 0,
            'findings_count': 0,
            'languages_detected': set()
        }

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner resources"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
        logger.info(f"Created temporary directory: {self.temp_dir}")
        self.scan_stats['start_time'] = datetime.now()

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                self.scan_stats['end_time'] = datetime.now()
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
    async def _clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with authentication"""
        try:
            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')

            logger.info(f"Cloning repository to {self.repo_dir}")
            
            # Minimal git options to ensure complete repository access
            git_options = [
                '--single-branch',
                '--no-tags'
            ]
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                multi_options=git_options
            )

            # Calculate repository size
            total_size = sum(
                f.stat().st_size for f in self.repo_dir.rglob('*') 
                if f.is_file() and not any(p in str(f) for p in self.config.exclude_patterns)
            )
            size_gb = total_size / (1024 ** 3)
            
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

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with comprehensive configuration"""
        try:
            # Build command to match CLI behavior
            cmd = [
                "semgrep",
                "scan",
                "--config", "auto",  # Use auto config like CLI
                "--json",
                "--verbose",
                "--metrics=on",
                
                # Performance settings
                "--timeout", "300",  # 5 minutes per rule
                "--timeout-threshold", "3",  # Skip file after 3 timeouts
                
                # Target directory
                str(target_dir)
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
            )

            stdout, stderr = await process.communicate()
            
            stderr_output = stderr.decode() if stderr else ""
            if stderr_output:
                logger.warning(f"Semgrep stderr: {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result()

            # Parse and enhance results
            results = json.loads(output)
            enhanced_results = self._process_scan_results(results)
            
            return enhanced_results

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return self._create_empty_result(error=str(e))

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and enhance scan results"""
        findings = results.get('results', [])
        
        processed_findings = []
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        category_counts = {}
        
        for finding in findings:
            enhanced_finding = {
                'id': finding.get('check_id'),
                'file': finding.get('path'),
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines', ''),
                'message': finding.get('extra', {}).get('message', ''),
                'severity': finding.get('extra', {}).get('severity', 'INFO'),
                'category': finding.get('extra', {}).get('metadata', {}).get('category', 'security'),
                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                'fix_recommendations': {
                    'description': finding.get('extra', {}).get('metadata', {}).get('fix', ''),
                    'references': finding.get('extra', {}).get('metadata', {}).get('fix_references', [])
                }
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
                'files_scanned': results.get('stats', {}).get('files_analyzed', 0),
                'files_skipped': results.get('stats', {}).get('files_skipped', 0),
                'scan_duration': results.get('time', {}).get('duration_ms', 0) / 1000
            },
            'errors': results.get('errors', [])
        }

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure"""
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'severity_counts': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
                'category_counts': {},
                'files_scanned': 0,
                'files_skipped': 0,
                'scan_duration': 0
            },
            'errors': [error] if error else []
        }
    async def scan_repository(
        self,
        repo_url: str,
        token: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Union[bool, Dict]]:
        """Execute repository scanning workflow"""
        scan_start_time = datetime.now()
        
        try:
            # Clone and scan repository
            repo_path = await self._clone_repository(repo_url, token)
            repo_size = os.path.getsize(repo_path) / (1024 * 1024)  # Size in MB
            
            logger.info(f"Starting scan of repository ({repo_size:.2f} MB)")
            
            # Run semgrep scan
            scan_results = await self._run_semgrep_scan(repo_path)
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            
            # Format response
            response = {
                'success': True,
                'data': {
                    'repository': {
                        'name': repo_url.split('github.com/')[-1].replace('.git', ''),
                        'owner': repo_url.split('github.com/')[-1].split('/')[0],
                        'repo': repo_url.split('github.com/')[-1].split('/')[1].replace('.git', '')
                    },
                    'metadata': {
                        'semgrep_version': '1.96.0',  # You might want to get this dynamically
                        'status': 'completed',
                        'timestamp': scan_start_time.isoformat(),
                        'completion_timestamp': datetime.now().isoformat(),
                        'scan_duration_seconds': scan_duration,
                        'repository_size_mb': round(repo_size, 2),
                        'performance_metrics': {
                            'total_duration_seconds': scan_duration,
                            'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024),
                            'files_analyzed': scan_results.get('stats', {}).get('files_scanned', 0),
                            'files_ignored': scan_results.get('stats', {}).get('files_skipped', 0)
                        }
                    },
                    'summary': {
                        'files_scanned': scan_results.get('stats', {}).get('files_scanned', 0),
                        'scan_status': 'completed_with_errors' if scan_results.get('errors') else 'completed',
                        'total_findings': scan_results.get('stats', {}).get('total_findings', 0),
                        'severity_counts': scan_results.get('stats', {}).get('severity_counts', {}),
                        'category_counts': scan_results.get('stats', {}).get('category_counts', {})
                    },
                    'findings': scan_results.get('findings', []),
                    'errors': scan_results.get('errors', []),
                    'filters': {
                        'available_severities': ['HIGH', 'MEDIUM', 'LOW', 'INFO'],
                        'available_categories': list(set(finding.get('category', 'unknown') 
                                                      for finding in scan_results.get('findings', [])))
                    },
                    'pagination': {
                        'current_page': 1,
                        'per_page': 10,
                        'total_items': len(scan_results.get('findings', [])),
                        'total_pages': (len(scan_results.get('findings', [])) + 9) // 10
                    }
                }
            }

            # Update database if session provided
            if self.db_session is not None and user_id is not None:
                try:
                    from models import ScanResult
                    
                    scan_record = ScanResult(
                        user_id=user_id,
                        repository_url=repo_url,
                        findings_count=response['data']['summary']['total_findings'],
                        results=response['data']
                    )
                    
                    self.db_session.add(scan_record)
                    self.db_session.commit()
                    
                    response['data']['scan_id'] = scan_record.id
                    logger.info(f"Scan record {scan_record.id} created successfully")
                    
                except Exception as db_error:
                    logger.error(f"Database error: {str(db_error)}")
                    response['data']['database_error'] = str(db_error)

            return response

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
        
        async with ChunkedScanner(config, db_session) as scanner:
            results = await scanner.scan_repository(
                repo_url,
                installation_token,
                user_id
            )
            
            return results

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
    import sys
    
    parser = argparse.ArgumentParser(description="Security Scanner")
    parser.add_argument("--repo-url", required=True, help="Repository URL to scan")
    parser.add_argument("--token", required=True, help="GitHub token for authentication")
    parser.add_argument("--user-id", required=True, help="User ID for the scan")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        result = asyncio.run(scan_repository_handler(
            args.repo_url,
            args.token,
            args.user_id
        ))
        print(json.dumps(result, indent=2))
    except Exception as e:
        logger.error(f"Scanner failed: {str(e)}")
        sys.exit(1)