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
    """Enhanced configuration for multi-language repository scanning"""
    max_file_size_mb: int = 100
    max_total_size_gb: int = 5
    max_memory_percent: int = 90
    chunk_size_mb: int = 1000
    timeout_seconds: int = 3600
    max_retries: int = 3
    concurrent_processes: int = 1
    exclude_patterns: List[str] = field(default_factory=lambda: [
        # Package Management
        'node_modules',
        'vendor',
        'packages',
        'pip-cache',
        'gradle-cache',
        'maven-cache',
        
        # Build Outputs
        'build',
        'dist',
        'target',
        'out',
        'output',
        'bin',
        'obj',
        
        # Virtual Environments
        'venv',
        'env',
        '.virtualenv',
        '.venv',
        'virtualenv',
        
        # IDE and Editor
        '.git',
        '.idea',
        '.vscode',
        '.vs',
        '.eclipse',
        '.settings',
        
        # Cache and Temp
        '__pycache__',
        '.pytest_cache',
        '.mypy_cache',
        '.ruff_cache',
        'coverage',
        '.coverage',
        '.cache',
        'tmp',
        'temp',
        
        # Compiled and Minified
        '*.min.js',
        '*.min.css',
        '*.bundle.js',
        '*.bundle.css',
        '*.map',
        '*.pyc',
        '*.pyo',
        '*.pyd',
        '*.class',
        '*.jar',
        '*.war',
        
        # Framework Specific
        '.next',
        '.nuxt',
        '.gatsby',
        'migrations',
        'assets/generated',
        'public/static',
        
        # Documentation
        'docs/_build',
        'site-packages',
        'htmlcov',
        
        # Large Data
        '*.csv',
        '*.json',
        '*.sql',
        '*.db',
        '*.sqlite3',
        '*.bak',
        
        # Mobile Specific
        'Pods',
        'Carthage',
        'build-ios',
        'build-android',
        
        # Container and Infrastructure
        '.terraform',
        'terraform.tfstate*',
        'bower_components'
    ])

class ChunkedScanner:
    """Enhanced scanner implementation for multi-language analysis"""
    
    SCANNABLE_EXTENSIONS = {
        # Web Technologies
        '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
        '.html', '.htm', '.css', '.scss', '.sass', '.less',
        
        # Backend Languages
        '.py', '.rb', '.php', '.java', '.go', '.cs', '.cpp',
        '.c', '.h', '.hpp', '.scala', '.kt', '.rs',
        
        # Mobile Development
        '.swift', '.m', '.mm', '.kotlin', '.dart',
        
        # Configuration and Data
        '.json', '.yml', '.yaml', '.xml', '.conf', '.ini',
        '.env', '.properties', '.toml', '.lock',
        
        # Infrastructure
        '.tf', '.hcl', '.dockerfile', '.docker',
        
        # Scripts and Templates
        '.sh', '.bash', '.ps1', '.ejs', '.hbs', '.pug',
        '.jsp', '.asp', '.aspx', '.cshtml', '.razor',
        
        # Documentation and Others
        '.md', '.txt', '.sql', '.graphql', '.proto'
    }

    SEMGREP_RULESETS = {
        'javascript': [
            'p/javascript',
            'p/nodejs',
            'p/react',
            'p/typescript'
        ],
        'python': [
            'p/python',
            'p/flask',
            'p/django'
        ],
        'java': [
            'p/java'
        ],
        'security': [
            'p/security-audit',
            'p/owasp-top-ten',
            'p/jwt',
            'p/secrets',
            'p/sql-injection',
            'p/xss'
        ],
        'quality': [
            'p/ci'
        ]
    }

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

    def _detect_language(self, file_path: str) -> Optional[str]:
        """Enhanced language detection from file path"""
        extension = os.path.splitext(file_path)[1].lower()
        extension_map = {
            # Web Technologies
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.vue': 'vue',
            '.svelte': 'javascript',
            
            # Backend Languages
            '.py': 'python',
            '.java': 'java',
            '.cs': 'csharp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.scala': 'scala',
            '.kt': 'kotlin',
            '.rs': 'rust',
            
            # Mobile
            '.swift': 'swift',
            '.m': 'objective-c',
            '.mm': 'objective-c',
            '.dart': 'dart',
            
            # Infrastructure
            '.tf': 'terraform',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.docker': 'docker',
            '.dockerfile': 'docker',
            
            # Templates and Markup
            '.html': 'html',
            '.htm': 'html',
            '.xml': 'xml',
            '.xhtml': 'html',
            '.jsp': 'java',
            '.asp': 'asp',
            '.aspx': 'asp',
            
            # Data
            '.sql': 'sql',
            '.graphql': 'graphql',
            '.gql': 'graphql',
            
            # Configuration
            '.json': 'json',
            '.toml': 'toml',
            '.ini': 'ini',
            '.conf': 'conf',
            
            # CSS and Styling
            '.css': 'css',
            '.scss': 'scss',
            '.sass': 'sass',
            '.less': 'less',
            
            # Shell and Scripts
            '.sh': 'shell',
            '.bash': 'shell',
            '.zsh': 'shell',
            '.ps1': 'powershell'
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
                            self.scan_stats['languages_detected'].add(lang)
                        self.scan_stats['total_files'] += 1
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
                '--no-tags',
                '--filter=blob:none',  # Optimize clone size
                '--sparse'  # Enable sparse checkout
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
            logger.info(f"Detected languages: {', '.join(self.detected_languages)}")
            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        try:
            """Execute Semgrep scan with comprehensive configuration"""
        
            # Build base command
            cmd = [
            "semgrep",
            "scan",
            "--json",
            
            # Core Security Rulesets (verified available)
            "--config", "p/security-audit",
            "--config", "p/owasp-top-ten",
            
            # Language-specific rulesets (verified available)
            "--config", "p/javascript",
            "--config", "p/typescript",
            "--config", "p/react",
            "--config", "p/nodejs",
            
            # Security-specific rulesets (verified available)
            "--config", "p/secrets",
            "--config", "p/sql-injection",
            "--config", "p/xss",
            "--config", "p/jwt",
            
            # Performance Settings
            "--max-memory", "4000",
            "--timeout", "900",
            "--severity", "INFO",
            "--verbose",
            "--metrics=on"
            ]

            # Only add language-specific rulesets for detected languages
            language_ruleset_map = {
                'javascript': ['p/javascript', 'p/nodejs', 'p/react'],
                'typescript': ['p/typescript'],
                'html': ['p/security-audit'],  # Basic security checks for HTML
                'css': ['p/security-audit']    # Basic security checks for CSS
            }

            # Add any detected language-specific rulesets
            for lang in self.detected_languages:
                if lang in language_ruleset_map:
                    for ruleset in language_ruleset_map[lang]:
                        if ruleset not in cmd:  # Avoid duplicate rulesets
                            cmd.extend(["--config", ruleset])

            # Add target directory
            cmd.append(str(target_dir))

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
            )

            stdout, stderr = await process.communicate()
            
            stderr_output = stderr.decode() if stderr else ""
            if stderr_output and "No findings were found" not in stderr_output:
                logger.warning(f"Semgrep stderr: {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return {}

            # Parse and enhance results
            results = json.loads(output)
            
            # Process findings and collect statistics
            processed_findings = []
            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            category_counts = {}
            
            for finding in results.get('results', []):
                # Detect language for the file
                file_path = finding.get('path', '')
                lang = self._detect_language(file_path) if file_path else None
                
                # Enhance finding with additional metadata
                enhanced_finding = {
                    'id': finding.get('check_id'),
                    'file': finding.get('path'),
                    'line_start': finding.get('start', {}).get('line'),
                    'line_end': finding.get('end', {}).get('line'),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': finding.get('extra', {}).get('severity', 'INFO'),
                    'category': finding.get('extra', {}).get('metadata', {}).get('category', 'security'),
                    'language': lang,
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'references': finding.get('extra', {}).get('metadata', {}).get('references', []),
                    'fix_recommendations': {
                        'description': finding.get('extra', {}).get('metadata', {}).get('fix', ''),
                        'references': finding.get('extra', {}).get('metadata', {}).get('fix_references', [])
                    }
                }
                
                # Update statistics
                severity = enhanced_finding['severity']
                category = enhanced_finding['category']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                category_counts[category] = category_counts.get(category, 0) + 1
                
                processed_findings.append(enhanced_finding)
                self.scan_stats['findings_count'] += 1

            # Prepare comprehensive scan results
            scan_results = {
                'findings': processed_findings,
                'stats': {
                    'total_findings': len(processed_findings),
                    'severity_counts': severity_counts,
                    'category_counts': category_counts,
                    'files_scanned': len(results.get('paths', {}).get('scanned', [])),
                    'files_ignored': len(results.get('paths', {}).get('ignored', [])),
                    'scan_duration': results.get('time', {}).get('duration_ms', 0) / 1000,
                    'languages_detected': list(self.detected_languages)
                },
                'scan_metadata': {
                    'semgrep_version': '1.96.0',
                    'scan_start': self.scan_stats['start_time'].isoformat(),
                    'scan_end': datetime.now().isoformat(),
                    'total_files_analyzed': self.scan_stats['total_files'],
                    'detected_languages': list(self.scan_stats['languages_detected'])
                },
                'errors': results.get('errors', []),
                'paths': {
                    'scanned': results.get('paths', {}).get('scanned', []),
                    'ignored': results.get('paths', {}).get('ignored', [])
                }
            }

            return scan_results

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return {
                'findings': [],
                'stats': {
                    'total_findings': 0,
                    'error': str(e)
                },
                'scan_metadata': {
                    'status': 'failed',
                    'error': str(e)
                },
                'errors': [str(e)]
            }
    
    async def scan_repository(
        self,
        repo_url: str,
        token: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Union[bool, Dict]]:
        """Execute repository scanning and results processing"""
        scan_start_time = datetime.now()
        
        try:
            # Clone and analyze repository
            repo_path = await self._clone_repository(repo_url, token)
            repo_size = await self._get_directory_size(repo_path)
            size_mb = repo_size / (1024 * 1024)
            
            logger.info(f"Starting scan of repository ({size_mb:.2f} MB)")
            
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
                        'semgrep_version': scan_results.get('scan_metadata', {}).get('semgrep_version', 'unknown'),
                        'status': 'completed',
                        'timestamp': scan_start_time.isoformat(),
                        'completion_timestamp': datetime.now().isoformat(),
                        'scan_duration_seconds': scan_duration,
                        'repository_size_mb': round(size_mb, 2),
                        'languages_detected': list(self.detected_languages),
                        'performance_metrics': {
                            'total_duration_seconds': scan_duration,
                            'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024),
                            'files_analyzed': scan_results.get('stats', {}).get('files_scanned', 0),
                            'files_ignored': scan_results.get('stats', {}).get('files_ignored', 0)
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
                    from models import AnalysisResult
                    
                    analysis = AnalysisResult(
                        repository_name=response['data']['repository']['name'],
                        user_id=user_id,
                        status='completed',
                        results=response['data']
                    )
                    
                    self.db_session.add(analysis)
                    self.db_session.commit()
                    
                    response['data']['analysis_id'] = analysis.id
                    logger.info(f"Analysis record {analysis.id} created successfully")
                    
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
    
    parser = argparse.ArgumentParser(description="Advanced Semgrep Security Scanner")
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