
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

    def _detect_language(self, file_path: str) -> Optional[str]:
        """Detect programming language from file path"""
        extension = os.path.splitext(file_path)[1].lower()
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
        return extension_map.get(extension)

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
                        # Detect language for the file
                        lang = self._detect_language(str(file_path))
                        if lang:
                            self.detected_languages.add(lang)
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

            return json.loads(output)

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return {}

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
            
            semgrep_output = await self._run_semgrep_scan(repo_path)
            scan_duration = (datetime.now() - scan_start_time).total_seconds()

            # Process findings
            formatted_findings = []
            for finding in semgrep_output.get('results', []):
                formatted_finding = {
                    'id': finding.get('check_id'),
                    'file': finding.get('path'),
                    'line_start': finding.get('start', {}).get('line'),
                    'line_end': finding.get('end', {}).get('line'),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': finding.get('extra', {}).get('severity', 'INFO'),
                    'category': 'security',
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'fix_recommendations': {
                        'description': finding.get('extra', {}).get('metadata', {}).get('message', ''),
                        'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                    }
                }
                formatted_findings.append(formatted_finding)

            # Prepare response
            response = {
                'success': True,
                'data': {
                    'repository': {
                        'name': repo_url.split('github.com/')[-1].replace('.git', ''),
                        'owner': repo_url.split('github.com/')[-1].split('/')[0],
                        'repo': repo_url.split('github.com/')[-1].split('/')[1].replace('.git', '')
                    },
                    'metadata': {
                        'semgrep_version': semgrep_output.get('version', 'unknown'),
                        'status': 'completed',
                        'timestamp': scan_start_time.isoformat()
                    },
                    'summary': {
                        'files_scanned': len(semgrep_output.get('paths', {}).get('scanned', [])),
                        'scan_status': 'completed_with_errors' if semgrep_output.get('errors') else 'completed',
                        'total_findings': len(formatted_findings)
                    },
                    'findings': formatted_findings,
                    'filters': {
                        'available_severities': ['HIGH', 'MEDIUM', 'LOW', 'WARNING', 'INFO'],
                        'available_categories': ['security']
                    },
                    'pagination': {
                        'current_page': 1,
                        'per_page': 10,
                        'total_items': len(formatted_findings),
                        'total_pages': (len(formatted_findings) + 9) // 10
                    }
                }
            }

            # Update database if session provided
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
