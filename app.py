from flask import Flask, request, jsonify
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
import json
from github import Github, GithubIntegration
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS

# Load environment variables in development
if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Store results in memory (consider using Redis for production)
analysis_results = {}

def format_private_key(key_data):
    """Format the private key correctly."""
    try:
        key_data = key_data.strip()
        key_parts = key_data.replace('\\n', '\n').split('\n')
        key_parts = [part.strip() for part in key_parts if part.strip()]
        
        formatted_key = []
        if not key_parts[0].startswith('-----BEGIN RSA PRIVATE KEY-----'):
            formatted_key.append('-----BEGIN RSA PRIVATE KEY-----')
        else:
            formatted_key.append(key_parts[0])
            key_parts = key_parts[1:]
        
        for part in key_parts:
            if not (part.startswith('----') or part.endswith('----')):
                formatted_key.append(part)
        
        if not key_parts[-1].endswith('-----END RSA PRIVATE KEY-----'):
            formatted_key.append('-----END RSA PRIVATE KEY-----')
        
        result = '\n'.join(formatted_key)
        return result
        
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise

def verify_webhook_signature(request_data, signature_header):
    """Verify webhook signature"""
    try:
        if not WEBHOOK_SECRET or not signature_header:
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

def format_semgrep_results(raw_results):
    """Format Semgrep results for frontend consumption"""
    try:
        if isinstance(raw_results, str):
            results = json.loads(raw_results)
        else:
            results = raw_results

        formatted_response = {
            'summary': {
                'total_files_scanned': len(results.get('paths', {}).get('scanned', [])),
                'total_findings': len(results.get('results', [])),
                'files_scanned': results.get('paths', {}).get('scanned', []),
                'semgrep_version': results.get('version'),
                'scan_status': 'success' if not results.get('errors') else 'completed_with_errors'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': results.get('errors', [])
        }

        for finding in results.get('results', []):
            severity = finding.get('extra', {}).get('severity', 'INFO')
            category = finding.get('extra', {}).get('metadata', {}).get('category', 'uncategorized')
            
            formatted_finding = {
                'id': finding.get('check_id'),
                'file': finding.get('path'),
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines'),
                'message': finding.get('extra', {}).get('message'),
                'severity': severity,
                'category': category,
                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                'fix_recommendations': {
                    'description': finding.get('extra', {}).get('metadata', {}).get('message'),
                    'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                }
            }

            formatted_response['findings'].append(formatted_finding)
            formatted_response['findings_by_severity'][severity].append(formatted_finding)
            
            if category not in formatted_response['findings_by_category']:
                formatted_response['findings_by_category'][category] = []
            formatted_response['findings_by_category'][category].append(formatted_finding)

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
        return {'error': str(e)}

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
        
        semgrep_cmd = ["semgrep", "--config=auto", "--json", "."]
        semgrep_process = subprocess.run(
            semgrep_cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=clone_dir
        )
        
        semgrep_output = json.loads(semgrep_process.stdout)
        analysis_results[repo_name] = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'completed',
            'results': semgrep_output
        }
        
        return semgrep_process.stdout

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        analysis_results[repo_name] = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'failed',
            'error': str(e)
        }
        return None
    finally:
        if clone_dir:
            clean_directory(clone_dir)

# Load configuration
required_env_vars = {
    'GITHUB_APP_ID': 'GitHub App ID not configured',
    'GITHUB_WEBHOOK_SECRET': 'Webhook secret not configured',
    'GITHUB_APP_PRIVATE_KEY': 'GitHub App private key not configured'
}

for var, message in required_env_vars.items():
    if not os.getenv(var):
        raise ValueError(message)

APP_ID = os.getenv('GITHUB_APP_ID')
WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
PORT = int(os.getenv('PORT', 10000))

try:
    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("GitHub Integration initialized successfully")
except Exception as e:
    logger.error(f"GitHub Integration initialization failed: {str(e)}")
    raise

# API Routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    })

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

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle GitHub webhook events"""
    try:
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_webhook_signature(request.get_data(), signature):
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
            installation_token = git_integration.get_access_token(installation_id).token
            github_client = Github(installation_token)

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
                        
                        # Create a more readable issue body
                        issue_body = f"""## Semgrep Security Analysis Results

**Scan Summary:**
- Total Findings: {formatted_results['summary']['total_findings']}
- Files Scanned: {formatted_results['summary']['total_files_scanned']}
- Scan Status: {formatted_results['summary']['scan_status']}

**Severity Breakdown:**
{json.dumps(formatted_results['severity_counts'], indent=2)}

**Category Breakdown:**
{json.dumps(formatted_results['category_counts'], indent=2)}

### Detailed Findings:

{chr(10).join(f'''
#### {i+1}. {finding['id']}
- **Severity:** {finding['severity']}
- **File:** {finding['file']} (lines {finding['line_start']}-{finding['line_end']})
- **Issue:** {finding['message']}
- **Code:**
```
{finding['code_snippet']}
```
- **Fix Recommendations:** {finding['fix_recommendations']['description']}
- **References:** {', '.join(finding['fix_recommendations']['references'])}
''' for i, finding in enumerate(formatted_results['findings']))}
"""
                        
                        repo_obj.create_issue(
                            title=f"Semgrep Security Analysis Results - {datetime.utcnow().strftime('%Y-%m-%d')}",
                            body=issue_body,
                            labels=['security', 'semgrep']
                        )
                        logger.info(f"Created issue in {repo_full_name}")
                    except Exception as e:
                        logger.error(f"Error creating issue in {repo_full_name}: {str(e)}")

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

if __name__ == '__main__':
    # Use production WSGI server if in production
    if os.getenv('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=PORT)
    else:
        app.run(host='127.0.0.1', port=PORT, debug=True)