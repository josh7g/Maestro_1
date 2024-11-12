import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import asyncio
import git
from aiohttp import web
import signal

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
    chunk_size_mb: int = 100  # Reduced chunk size for better performance
    timeout_seconds: int = 300  # Reduced timeout
    max_retries: int = 3
    concurrent_processes: int = 2  # Increased for parallel processing
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
        'test',
        'tests',
        '__pycache__',
        '*.min.js',  # Exclude minified files
        '*.bundle.js'  # Exclude bundled files
    ])

class ChunkedScanner:
    """Scanner class for processing repositories"""
    # ... (previous SCANNABLE_EXTENSIONS remain the same)

    async def _run_semgrep_scan(self, target_dir: Path) -> Dict:
        """Execute Semgrep scan with enhanced security rules and better performance"""
        max_memory_mb = 1500  # Reduced memory limit
        
        # Optimized security rulesets
        security_rules = [
            "p/default",
            "p/security-audit",
            "p/owasp-top-ten"
        ]
        
        # Language-specific rules applied only to relevant files
        language_rules = {
            '.js': ["p/javascript", "p/nodejs"],
            '.ts': ["p/typescript"],
            '.jsx': ["p/react"],
            '.tsx': ["p/react", "p/typescript"]
        }
        
        all_results = {
            'results': [],
            'errors': [],
            'paths': {
                'scanned': set(),
                'ignored': set()
            },
            'version': "1.56.0",
            'security_summary': {
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'categories': set()
            }
        }

        # Group files by extension for targeted scanning
        files_by_extension = {}
        for root, _, files in os.walk(target_dir):
            if any(exclude in root for exclude in self.config.exclude_patterns):
                continue
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
                    files_by_extension.setdefault(
                        file_path.suffix.lower(), 
                        []
                    ).append(file_path)

        # Scan files in parallel by extension
        async def scan_files_group(files: List[Path], rules: List[str]) -> List[Dict]:
            chunk_results = []
            chunk_size = min(10, len(files))  # Smaller chunks for better performance
            chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]

            for chunk in chunks:
                chunk_dir = target_dir / f"chunk_{hash(str(chunk))}"
                chunk_dir.mkdir(exist_ok=True)

                try:
                    # Copy files to chunk directory
                    for file_path in chunk:
                        rel_path = file_path.relative_to(target_dir)
                        target_path = chunk_dir / rel_path
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(file_path, target_path)

                    # Run scans
                    for rule in rules:
                        cmd = [
                            "semgrep",
                            "scan",
                            f"--config={rule}",
                            "--json",
                            "--max-memory", str(max_memory_mb),
                            "--timeout", str(self.config.timeout_seconds),
                            "--jobs", str(self.config.concurrent_processes),
                            str(chunk_dir)
                        ]

                        try:
                            process = await asyncio.create_subprocess_exec(
                                *cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                                cwd=str(chunk_dir)
                            )

                            stdout, stderr = await asyncio.wait_for(
                                process.communicate(),
                                timeout=self.config.timeout_seconds
                            )

                            if stdout:
                                results = json.loads(stdout.decode())
                                chunk_results.extend(results.get('results', []))

                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout scanning with rule {rule}")
                            continue

                finally:
                    try:
                        shutil.rmtree(chunk_dir)
                    except Exception as e:
                        logger.error(f"Error cleaning up chunk directory: {str(e)}")

            return chunk_results

        # Run scans in parallel for different file types
        tasks = []
        for ext, files in files_by_extension.items():
            rules_to_apply = security_rules + language_rules.get(ext, [])
            if files:  # Only create tasks for extensions with files
                tasks.append(scan_files_group(files, rules_to_apply))

        # Gather results
        chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result_group in chunk_results:
            if isinstance(result_group, Exception):
                logger.error(f"Scan error: {str(result_group)}")
                continue
                
            for finding in result_group:
                severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                if severity == 'ERROR' or severity == 'HIGH':
                    all_results['security_summary']['high_severity'] += 1
                elif severity == 'WARNING' or severity == 'MEDIUM':
                    all_results['security_summary']['medium_severity'] += 1
                elif severity == 'INFO' or severity == 'LOW':
                    all_results['security_summary']['low_severity'] += 1

                category = finding.get('extra', {}).get('metadata', {}).get('category', 'unknown')
                all_results['security_summary']['categories'].add(category)
                all_results['results'].append(finding)

        # Finalize results
        all_results['paths']['scanned'] = list(all_results['paths']['scanned'])
        all_results['paths']['ignored'] = list(all_results['paths']['ignored'])
        all_results['security_summary']['categories'] = list(all_results['security_summary']['categories'])

        return all_results

# Web server setup
routes = web.RouteTableDef()

@routes.post('/webhook')
async def webhook_handler(request):
    """Handle GitHub webhook events"""
    try:
        data = await request.json()
        event_type = request.headers.get('X-GitHub-Event')
        
        if event_type == 'push':
            repo_url = data['repository']['clone_url']
            installation_id = data['installation']['id']
            # Process webhook...
            return web.Response(text='Webhook received', status=200)
            
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return web.Response(text=str(e), status=500)

# Create the application
app = web.Application()
app.add_routes(routes)

# Graceful shutdown handler
async def shutdown(app):
    logger.info("Shutting down gracefully...")
    for task in asyncio.all_tasks():
        task.cancel()
    await asyncio.gather(*asyncio.all_tasks(), return_exceptions=True)

app.on_shutdown.append(shutdown)

if __name__ == "__main__":
    web.run_app(app, port=10000)