# Part 1: Imports and App Initialization
from flask import Flask, request, jsonify
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
import json
import base64
from github import Github, GithubIntegration
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS

# Load environment variables in development
if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Store results in memory
analysis_results = {}

# Part 2: Helper Functions
def format_private_key(key_data):
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")
        
        # Remove any whitespace and normalize line endings
        key_data = key_data.strip()
        
        # Handle different potential formats
        if '\\n' in key_data:
            # Handle escaped newlines
            parts = key_data.split('\\n')
            key_data = '\n'.join(part.strip() for part in parts if part.strip())
        elif '\n' not in key_data:
            # Handle single-line key
            key_length = len(key_data)
            if key_length < 64:  # Minimum size for a valid key
                raise ValueError("Key content too short")
            
            # Extract the key content and format properly
            if not key_data.startswith('-----BEGIN'):
                key_data = (
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(key_data[i:i+64] for i in range(0, len(key_data), 64)) +
                    '\n-----END RSA PRIVATE KEY-----'
                )
        
        # Ensure proper header and footer
        if not key_data.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            key_data = '-----BEGIN RSA PRIVATE KEY-----\n' + key_data
        if not key_data.endswith('-----END RSA PRIVATE KEY-----'):
            key_data = key_data + '\n-----END RSA PRIVATE KEY-----'
        
        # Validate key format
        lines = key_data.split('\n')
        if len(lines) < 3:
            raise ValueError("Invalid key format - too few lines")
        
        logger.info("Private key formatted successfully")
        return key_data
        
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise ValueError(f"Private key formatting failed: {str(e)}")

def verify_webhook_signature(request_data, signature_header):
    """Verify webhook signature"""
    try:
        if not WEBHOOK_SECRET or not signature_header:
            logger.error("Missing webhook secret or signature")
            return False

        expected_signature = 'sha256=' + hmac.new(
            WEBHOOK_SECRET.encode('utf-8'),
            request_data,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_signature, signature_header)
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        return False

def clean_directory(directory):
    """Safely remove a directory"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
    except Exception as e:
        logger.error(f"Error cleaning directory {directory}: {str(e)}")

# Part 3: Main Processing Functions
def format_semgrep_results(raw_results):
    """Format Semgrep results for frontend"""
    try:
        # Handle string input
        if isinstance(raw_results, str):
            try:
                results = json.loads(raw_results)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON results: {str(e)}")
                return {
                    'summary': {
                        'total_files_scanned': 0,
                        'total_findings': 0,
                        'files_scanned': [],
                        'semgrep_version': 'unknown',
                        'scan_status': 'failed'
                    },
                    'findings': [],
                    'findings_by_severity': {
                        'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
                    },
                    'findings_by_category': {},
                    'errors': [f"Failed to parse results: {str(e)}"],
                    'severity_counts': {},
                    'category_counts': {}
                }
        else:
            results = raw_results

        # Validate results structure
        if not isinstance(results, dict):
            raise ValueError(f"Invalid results format: expected dict, got {type(results)}")

        formatted_response = {
            'summary': {
                'total_files_scanned': len(results.get('paths', {}).get('scanned', [])),
                'total_findings': len(results.get('results', [])),
                'files_scanned': results.get('paths', {}).get('scanned', []),
                'semgrep_version': results.get('version', 'unknown'),
                'scan_status': 'success' if not results.get('errors') else 'completed_with_errors'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': results.get('errors', [])
        }

        # Process findings
        for finding in results.get('results', []):
            try:
                severity = finding.get('extra', {}).get('severity', 'INFO')
                category = finding.get('extra', {}).get('metadata', {}).get('category', 'uncategorized')
                
                formatted_finding = {
                    'id': finding.get('check_id', 'unknown'),
                    'file': finding.get('path', 'unknown'),
                    'line_start': finding.get('start', {}).get('line', 0),
                    'line_end': finding.get('end', {}).get('line', 0),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': severity,
                    'category': category,
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'fix_recommendations': {
                        'description': finding.get('extra', {}).get('metadata', {}).get('message', ''),
                        'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                    }
                }

                formatted_response['findings'].append(formatted_finding)
                
                # Ensure severity exists in findings_by_severity
                if severity not in formatted_response['findings_by_severity']:
                    formatted_response['findings_by_severity'][severity] = []
                formatted_response['findings_by_severity'][severity].append(formatted_finding)
                
                # Ensure category exists in findings_by_category
                if category not in formatted_response['findings_by_category']:
                    formatted_response['findings_by_category'][category] = []
                formatted_response['findings_by_category'][category].append(formatted_finding)
                
            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                formatted_response['errors'].append(f"Error processing finding: {str(e)}")

        # Calculate counts
        formatted_response['severity_counts'] = {
            severity: len(findings)
            for severity, findings in formatted_response['findings_by_severity'].items()
        }

        formatted_response['category_counts'] = {
            category: len(findings)
            for category, findings in formatted_response['findings_by_category'].items()
        }

        return formatted_response

    except Exception as e:
        logger.error(f"Error formatting results: {str(e)}")
        return {
            'summary': {
                'total_files_scanned': 0,
                'total_findings': 0,
                'files_scanned': [],
                'semgrep_version': 'unknown',
                'scan_status': 'failed'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': [f"Failed to format results: {str(e)}"],
            'severity_counts': {},
            'category_counts': {}
        }

def trigger_semgrep_analysis(repo_url, installation_token):
    """Run Semgrep analysis"""
    clone_dir = None
    repo_name = repo_url.split('github.com/')[-1].replace('.git', '')
    
    try:
        repo_url_with_auth = f"https://x-access-token:{installation_token}@github.com/{repo_name}.git"
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"
        
        analysis_results[repo_name] = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'in_progress'
        }
        
        clean_directory(clone_dir)
        
        # Use arrays instead of shell=True for security
        clone_cmd = ["git", "clone", "--depth", "1", repo_url_with_auth, clone_dir]
        subprocess.run(clone_cmd, check=True, capture_output=True, text=True)
        logger.info(f"Repository cloned successfully: {repo_name}")
        
        semgrep_cmd = ["semgrep", "--config=auto", "--json", "."]
        semgrep_process = subprocess.run(
            semgrep_cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=clone_dir
        )
        
        try:
            semgrep_output = json.loads(semgrep_process.stdout)
            analysis_results[repo_name] = {
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'completed',
                'results': semgrep_output
            }
            logger.info(f"Semgrep analysis completed successfully for {repo_name}")
            return semgrep_process.stdout
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {str(e)}")
            analysis_results[repo_name] = {
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'failed',
                'error': f"Invalid Semgrep output: {str(e)}"
            }
            return None

    except Exception as e:
        logger.error(f"Analysis error for {repo_name}: {str(e)}")
        analysis_results[repo_name] = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'failed',
            'error': str(e)
        }
        return None
    finally:
        if clone_dir:
            clean_directory(clone_dir)

# Part 4: Configuration Loading
try:
    APP_ID = os.getenv('GITHUB_APP_ID')
    WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
    PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
    
    if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
        raise ValueError("Missing required environment variables")
    
    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("GitHub Integration initialized successfully")
except Exception as e:
    logger.error(f"Configuration error: {str(e)}")
    raise

# Part 5: Route Handlers
@app.route('/', methods=['GET'])
def root():
    """Root endpoint - API information"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'endpoints': {
            '/webhook': 'GitHub webhook endpoint',
            '/api/v1/analysis/status': 'Get all analyses status',
            '/api/v1/analysis/<owner>/<repo>/summary': 'Get repository analysis summary',
            '/api/v1/analysis/<owner>/<repo>/findings': 'Get detailed analysis findings'
        }
    }), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle GitHub webhook events"""
    try:
        logger.info("Received webhook request")
        
        # Verify webhook signature
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_webhook_signature(request.get_data(), signature):
            logger.error("Invalid webhook signature")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Invalid signature',
                    'code': 'INVALID_SIGNATURE'
                }
            }), 401

        event_type = request.headers.get('X-GitHub-Event', 'ping')
        logger.info(f"Processing event type: {event_type}")

        if event_type == 'ping':
            return jsonify({
                'success': True,
                'message': 'Webhook configured successfully'
            })

        if event_type == 'installation':
            payload = request.json
            
            if payload.get('action') not in ['created', 'added']:
                return jsonify({
                    'success': True,
                    'message': 'Event ignored'
                })

            installation_id = payload['installation']['id']
            logger.info(f"Processing installation ID: {installation_id}")

            try:
                installation_token = git_integration.get_access_token(installation_id).token
                github_client = Github(installation_token)
            except Exception as e:
                logger.error(f"Failed to get installation token: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Failed to authenticate with GitHub',
                        'details': str(e)
                    }
                }), 500

            results = {}
            repositories = payload.get('repositories', [])
            
            for repo in repositories:
                repo_full_name = repo['full_name']
                repo_url = f"https://github.com/{repo_full_name}.git"
                
                logger.info(f"Analyzing repository: {repo_full_name}")
                semgrep_output = trigger_semgrep_analysis(repo_url, installation_token)
                
                if semgrep_output:
                    results[repo_full_name] = semgrep_output
                    
                    try:
                        repo_obj = github_client.get_repo(repo_full_name)
                        formatted_results = format_semgrep_results(json.loads(semgrep_output))
                        
                        if formatted_results.get('errors'):
                            logger.warning(f"Analysis completed with errors: {formatted_results['errors']}")
                        
                        # Create issue body
                        issue_body = f"""## Semgrep Security Analysis Results

**Scan Summary:**
- Total Findings: {formatted_results['summary']['total_findings']}
- Files Scanned: {formatted_results['summary']['total_files_scanned']}
- Scan Status: {formatted_results['summary']['scan_status']}

**Severity Breakdown:**
```json
{json.dumps(formatted_results['severity_counts'], indent=2)}
```

**Category Breakdown:**
```json
{json.dumps(formatted_results['category_counts'], indent=2)}
```

### Detailed Findings:

"""
                        # Add findings only if they exist
                        if formatted_results['findings']:
                            for i, finding in enumerate(formatted_results['findings'], 1):
                                issue_body += f"""
#### {i}. {finding['id']}
- **Severity:** {finding['severity']}
- **File:** {finding['file']} (lines {finding['line_start']}-{finding['line_end']})
- **Issue:** {finding['message']}
- **Code:**
```
{finding['code_snippet']}
```
- **Fix Recommendations:** {finding['fix_recommendations']['description']}
- **References:** {', '.join(finding['fix_recommendations']['references']) if finding['fix_recommendations']['references'] else 'None'}

"""
                        else:
                            issue_body += "\nNo security findings were detected in this scan."

                        # Add errors if any
                        if formatted_results.get('errors'):
                            issue_body += "\n### Errors During Analysis:\n"
                            for error in formatted_results['errors']:
                                issue_body += f"- {error}\n"

                        repo_obj.create_issue(
                            title=f"Semgrep Security Analysis Results - {datetime.utcnow().strftime('%Y-%m-%d')}",
                            body=issue_body,
                            labels=['security', 'semgrep']
                        )
                        logger.info(f"Created issue in {repo_full_name}")
                    except Exception as e:
                        logger.error(f"Error creating issue in {repo_full_name}: {str(e)}")
                        # Create a simplified issue if formatting fails
                        try:
                            repo_obj.create_issue(
                                title=f"Semgrep Security Analysis Results (Raw) - {datetime.utcnow().strftime('%Y-%m-%d')}",
                                body=f"Raw analysis results:\n```json\n{semgrep_output}\n```",
                                labels=['security', 'semgrep', 'raw-results']
                            )
                            logger.info(f"Created raw results issue in {repo_full_name}")
                        except Exception as e2:
                            logger.error(f"Failed to create raw results issue: {str(e2)}")

            return jsonify({
                'success': True,
                'data': {
                    'message': 'Analysis completed',
                    'repositories_analyzed': list(results.keys())
                }
            })

        return jsonify({
            'success': True,
            'message': 'Event processed'
        })

    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Webhook processing failed',
                'details': str(e)
            }
        }), 500

@app.route('/api/v1/analysis/status', methods=['GET'])
def get_all_analyses():
    """Get status of all analyses with pagination"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', 10))
        
        all_repos = list(analysis_results.items())
        total_repos = len(all_repos)
        
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_repos = all_repos[start_idx:end_idx]
        
        analyses = [{
            'repository': repo_name,
            'timestamp': data['timestamp'],
            'status': data['status'],
            'error': data.get('error'),
            'summary': {
                'total_findings': len(data.get('results', {}).get('results', [])) if data.get('results') else 0,
                'status': 'completed' if data.get('results') else 'failed'
            }
        } for repo_name, data in paginated_repos]
        
        return jsonify({
            'success': True,
            'data': {
                'analyses': analyses,
                'pagination': {
                    'current_page': page,
                    'total_pages': (total_repos + per_page - 1) // per_page,
                    'total_items': total_repos,
                    'per_page': per_page
                }
            }
        })
    except Exception as e:
        logger.error(f"Error getting analyses: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to fetch analyses',
                'details': str(e)
            }
        }), 500

@app.route('/api/v1/analysis/<owner>/<repo>/summary', methods=['GET'])
def get_analysis_summary(owner, repo):
    """Get analysis summary"""
    try:
        repo_name = f"{owner}/{repo}"
        result = analysis_results.get(repo_name)
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analysis found',
                    'code': 'ANALYSIS_NOT_FOUND'
                }
            }), 404
        
        if result.get('status') == 'failed':
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Analysis failed',
                    'details': result.get('error'),
                    'code': 'ANALYSIS_FAILED'
                }
            }), 400
            
        formatted_results = format_semgrep_results(result['results'])
        
        return jsonify({
            'success': True,
            'data': {
                'repository': {
                    'name': repo_name,
                    'owner': owner,
                    'repo': repo
                },
                'metadata': {
                    'timestamp': result['timestamp'],
                    'status': result['status'],
                    'semgrep_version': formatted_results['summary']['semgrep_version']
                },
                'summary': {
                    'total_findings': formatted_results['summary']['total_findings'],
                    'files_scanned': formatted_results['summary']['total_files_scanned'],
                    'scan_status': formatted_results['summary']['scan_status']
                },
                'severity_breakdown': formatted_results['severity_counts'],
                'category_breakdown': formatted_results['category_counts'],
                'error_count': len(formatted_results['errors'])
            }
        })
    except Exception as e:
        logger.error(f"Error getting summary: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to fetch summary',
                'details': str(e)
            }
        }), 500

@app.route('/api/v1/analysis/<owner>/<repo>/findings', methods=['GET'])
def get_analysis_findings(owner, repo):
    """Get detailed findings with filtering and pagination"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', 10))
        severity = request.args.get('severity', '').upper()
        category = request.args.get('category', '')
        
        repo_name = f"{owner}/{repo}"
        result = analysis_results.get(repo_name)
        
        if not result or not result.get('results'):
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analysis found',
                    'code': 'ANALYSIS_NOT_FOUND'
                }
            }), 404
            
        formatted_results = format_semgrep_results(result['results'])
        findings = formatted_results['findings']
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f['severity'] == severity]
        if category:
            findings = [f for f in findings if f['category'] == category]
            
        total_findings = len(findings)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_findings = findings[start_idx:end_idx]
        
        return jsonify({
            'success': True,
            'data': {
                'repository': {
                    'name': repo_name,
                    'owner': owner,
                    'repo': repo
                },
                'metadata': {
                    'timestamp': result['timestamp'],
                    'status': result['status']
                },
                'findings': paginated_findings,
                'pagination': {
                    'current_page': page,
                    'total_pages': (total_findings + per_page - 1) // per_page,
                    'total_items': total_findings,
                    'per_page': per_page
                },
                'filters': {
                    'available_severities': list(formatted_results['findings_by_severity'].keys()),
                    'available_categories': list(formatted_results['findings_by_category'].keys())
                }
            }
        })
    except Exception as e:
        logger.error(f"Error getting findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to fetch findings',
                'details': str(e)
            }
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    if os.getenv('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=port)
    else:
        app.run(host='127.0.0.1', port=port, debug=True)