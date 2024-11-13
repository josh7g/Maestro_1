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
from typing import Dict, List, Optional, Set, Tuple, Union
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
    include_raw_output: bool = True  # New option to include raw semgrep output
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
    """Enhanced scanner combining async performance with comprehensive results"""
    
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
        self.raw_outputs = []  # Store raw outputs from each chunk

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

    async def _run_semgrep_scan(self, target_dir: Path) -> Tuple[Dict, Optional[str]]:
        """Execute Semgrep scan with optimized configuration and return both processed and raw results"""
        try:
            # Build command with all selected rulesets
            cmd = [
                "semgrep",
                "scan",
                "--json",
                "--config", "auto",  # Use auto for comprehensive scanning
                "--max-memory", "2000",
                "--timeout", "300",
                "--severity", "INFO"
            ]
            
            # Add target directory
            cmd.append(str(target_dir))

            # Run semgrep
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
            )

            stdout, stderr = await process.communicate()
            
            # Store raw output
            raw_output = stdout.decode() if stdout else ""
            stderr_output = stderr.decode() if stderr else ""

            if stderr_output and "No findings were found" not in stderr_output:
                logger.warning(f"Semgrep stderr: {stderr_output}")

            if not raw_output.strip():
                return {}, None

            # Parse and process results
            results = json.loads(raw_output)
            
            # Enhanced results processing
            processed_results = {
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

            return processed_results, raw_output if self.config.include_raw_output else None

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return {}, None

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
        """
        Enhanced repository scanning with both processed and raw results
        """
        scan_start_time = datetime.now()
        
        try:
            # Clone repository
            repo_path = await self._clone_repository(repo_url, token)
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            
            logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
            # Run the scan
            processed_results, raw_output = await self._run_semgrep_scan(repo_path)
            
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            
            # Prepare comprehensive response
            response = {
                'success': True,
                'data': {
                    'processed_results': processed_results,
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
            
            # Include raw output if requested
            if self.config.include_raw_output and raw_output:
                response['data']['raw_semgrep_output'] = raw_output

            # Update database if session provided
            if self.db_session is not None and user_id is not None:
                try:
                    from models import AnalysisResult  # Import here to avoid circular dependency
                    
                    analysis = AnalysisResult(
                        repository_name=repo_url.split('github.com/')[-1].replace('.git', ''),
                        user_id=user_id,
                        status='completed',
                        results=processed_results,
                        raw_results=raw_output if self.config.include_raw_output else None
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

async def scan_repository_handler(
    repo_url: str,
    installation_token: str,
    user_id: str,
    db_session: Optional[Session] = None,
    include_raw_output: bool = True
) -> Dict:
    """Enhanced handler function for web routes"""
    logger.info(f"Starting scan request for repository: {repo_url}")
    
    # Validate inputs
    if not all([repo_url, installation_token, user_id]):
        return {
            'success': False,
            'error': {
                'message': 'Missing required parameters',
                'code': 'INVALID_PARAMETERS'
            }
        }

    try:
        config = ScanConfig(include_raw_output=include_raw_output)
        
        async with EnhancedScanner(config, db_session) as scanner:
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

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Semgrep Security Scanner")
    parser.add_argument("--repo-url", help="Repository URL to scan")
    parser.add_argument("--token", help="GitHub token for authentication")
    parser.add_argument("--user-id", help="User ID for the scan")
    parser.add_argument("--raw", action="store_true", help="Include raw Semgrep output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if all([args.repo_url, args.token, args.user_id]):
        try:
            result = asyncio.run(scan_repository_handler(
                args.repo_url,
                args.token,
                args.user_id,
                include_raw_output=args.raw
            ))
            print(json.dumps(result, indent=2))
        except Exception as e:
            logger.error(f"Scanner failed: {str(e)}")
            sys.exit(1)
    else:
        parser.print_help()