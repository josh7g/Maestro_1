# scanner.py
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
        '*.bundle.js',
        '*.map'
    ])

class ChunkedScanner:
    """Scanner implementation for repository analysis"""
    
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
        
        # Documentation and others
        '.md', '.txt', '.sql', '.graphql'
    }
    
    SEMGREP_RULESETS = {
        'javascript': ['p/javascript', 'p/nodejs', 'p/react', 'p/typescript', 'p/express'],
        'python': ['p/python', 'p/flask', 'p/django'],
        'java': ['p/java', 'p/spring'],
        'csharp': ['p/csharp'],
        'security': [
            'p/security-audit',
            'p/owasp-top-ten',
            'p/jwt',
            'p/secrets',
            'p/sql-injection',
            'p/xss'
        ]
    }
    
    def __init__(self, config: ScanConfig = ScanConfig(), db_session: Optional[Session] = None):
        self.config = config
        self.db_session = db_session
        self.temp_dir = None
        self.repo_dir = None
        self.detected_languages = set()

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
            logger.error(f"Error during cleanup: {str(e)}")

    def _detect_language(self, file_extension: str) -> Optional[str]:
        """Detect programming language from file extension"""
        extension_map = {
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.vue': 'javascript',
            '.py': 'python',
            '.java': 'java',
            '.cs': 'csharp'
        }
        return extension_map.get(file_extension.lower())

    async def _get_directory_size(self, directory: Path) -> int:
        """Calculate directory size excluding ignored paths"""
        total_size = 0
        try:
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
        except Exception as e:
            logger.error(f"Error calculating directory size: {str(e)}")
            
        return total_size

    async def _clone_repository(self, repo_url: str, token: str) -> Path:
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

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with optimized configuration"""
        try:
            cmd = [
                "semgrep",
                "scan",
                "--json",
                "--config", "auto",
                "--max-memory", "2000",
                "--timeout", "300",
                "--severity", "INFO"
            ]
            
            cmd.append(str(target_dir))

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
            )

            stdout, stderr = await process.communicate()
            
            output = stdout.decode() if stdout else ""
            stderr_output = stderr.decode() if stderr else ""

            if stderr_output and "No findings were found" not in stderr_output:
                logger.warning(f"Semgrep stderr: {stderr_output}")

            if not output.strip():
                return {}

            results = json.loads(output)
            
            return {
                'findings': results.get('results', []),
                'errors': results.get('errors', []),
                'stats': {
                    'total_findings': len(results.get('results', [])),
                    'total_errors': len(results.get('errors', [])),
                    'scan_duration': results.get('time', {}).get('duration_ms', 0) / 1000,
                    'files_scanned': len(results.get('paths', {}).get('scanned', [])),
                    'files_ignored': len(results.get('paths', {}).get('ignored', [])),
                },
                'severity_counts': self._count_severities(results.get('results', [])),
                'paths': results.get('paths', {}),
                'version': results.get('version', 'unknown')
            }

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return {}

    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        severity_counts = {}
        for finding in findings:
            severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts

    async def scan_repository(
        self,
        repo_url: str,
        token: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Union[bool, Dict]]:
        """Execute repository scanning and results processing"""
        scan_start_time = datetime.now()
        
        try:
            repo_path = await self._clone_repository(repo_url, token)
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            
            logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
            processed_results = await self._run_semgrep_scan(repo_path)
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            
            response = {
                'success': True,
                'data': {
                    'results': processed_results.get('findings', []),
                    'errors': processed_results.get('errors', []),
                    'paths': processed_results.get('paths', {}),
                    'version': processed_results.get('version', 'unknown'),
                    'stats': processed_results.get('stats', {}),
                    'scan_status': 'completed',
                    'scan_duration_seconds': scan_duration,
                    'metadata': {
                        'repository_size_mb': round(size_mb, 2),
                        'scan_timestamp': scan_start_time.isoformat(),
                        'completion_timestamp': datetime.now().isoformat(),
                        'files_analyzed': processed_results.get('stats', {}).get('files_scanned', 0),
                        'findings_count': len(processed_results.get('findings', [])),
                        'detected_languages': list(self.detected_languages),
                        'performance_metrics': {
                            'total_duration_seconds': scan_duration,
                            'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024)
                        }
                    }
                }
            }

            if self.db_session is not None and user_id is not None:
                try:
                    from models import AnalysisResult
                    
                    analysis = AnalysisResult(
                        repository_name=repo_url.split('github.com/')[-1].replace('.git', ''),
                        user_id=user_id,
                        status='completed',
                        results=response['data']
                    )
                    
                    self.db_session.add(analysis)
                    self.db_session.commit()
                    
                    response['data']['analysis_id'] = analysis.id
                    
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
        finally:
            await self._cleanup()

# Handler function (moved outside the class)
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
    
    parser = argparse.ArgumentParser(description="Enhanced Semgrep Security Scanner")
    parser.add_argument("--repo-url", help="Repository URL to scan")
    parser.add_argument("--token", help="GitHub token for authentication")
    parser.add_argument("--user-id", help="User ID for the scan")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if all([args.repo_url, args.token, args.user_id]):
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
    else:
        parser.print_help()
