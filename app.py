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

# Load environment variables only in development
if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

app = Flask(__name__)

# Enhanced logging for debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Store results in memory
analysis_results = {}

def format_private_key(key_data):
    """Format the private key correctly."""
    try:
        key_data = key_data.strip()
        logger.debug("Initial key format check started")
        
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
        elif formatted_key[-1] != '-----END RSA PRIVATE KEY-----':
            formatted_key.append('-----END RSA PRIVATE KEY-----')
        
        result = '\n'.join(formatted_key)
        
        if not result.startswith('-----BEGIN RSA PRIVATE KEY-----\n'):
            result = '-----BEGIN RSA PRIVATE KEY-----\n' + result.replace('-----BEGIN RSA PRIVATE KEY-----', '')
        if not result.endswith('\n-----END RSA PRIVATE KEY-----'):
            result = result.replace('-----END RSA PRIVATE KEY-----', '') + '\n-----END RSA PRIVATE KEY-----'
        
        logger.debug(f"Formatted key length: {len(result)}")
        logger.debug("Key formatting completed successfully")
        
        return result
        
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise

def verify_webhook_signature(request_data, signature_header):
    """Verify that the webhook signature is valid"""
    try:
        if not WEBHOOK_SECRET:
            logger.error("Webhook secret is not configured")
            return False
        if not signature_header:
            logger.error("No signature header in request")
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
    """Safely remove a directory and its contents"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
    except Exception as e:
        logger.error(f"Error cleaning directory {directory}: {str(e)}")

def format_semgrep_results(raw_results):
    """Format Semgrep results into a more frontend-friendly structure"""
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
                'HIGH': [],
                'MEDIUM': [],
                'LOW': [],
                'WARNING': [],
                'INFO': []
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
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp'),
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
        logger.error(f"Error formatting Semgrep results: {str(e)}")
        return {
            'error': 'Failed to format results',
            'message': str(e)
        }

def trigger_semgrep_analysis(repo_url, installation_token):
    """Clone repository and run Semgrep scan with proper authentication"""
    clone_dir = None
    repo_name = repo_url.split('github.com/')[-1].replace('.git', '')
    
    try:
        repo_url_with_auth = repo_url.replace(
            "https://",
            f"https://x-access-token:{installation_token}@"
        )
        
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"
        
        analysis_results[repo_name] = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'in_progress',
            'results': None
        }
        
        clean_directory(clone_dir)
        
        logger.info(f"Cloning repository to {clone_dir}")
        clone_process = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url_with_auth, clone_dir],
            check=True,
            capture_output=True,
            text=True
        )
        
        logger.info("Running Semgrep analysis")
        semgrep_process = subprocess.run(
            ["semgrep", "--config=auto", "--json", "."],
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
        logger.error(f"Error in analysis: {str(e)}")
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
try:
    APP_ID = os.getenv('GITHUB_APP_ID')
    if not APP_ID:
        raise ValueError("GITHUB_APP_ID not set")
    logger.debug(f"APP_ID: {APP_ID}")
    
    WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
    if not WEBHOOK_SECRET:
        raise ValueError("GITHUB_WEBHOOK_SECRET not set")
    
    PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
    if not PRIVATE_KEY:
        raise ValueError("GITHUB_APP_PRIVATE_KEY not set")
    
    PORT = int(os.getenv('PORT', 10000))
    
    formatted_key = format_private_key(PRIVATE_KEY)
    
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("Successfully initialized GitHub Integration")
    
except Exception as e:
    logger.error(f"Configuration error: {str(e)}", exc_info=True)
    raise

# API Endpoints
@app.route('/', methods=['GET'])
def root():
    """Root endpoint - basic API information"""
    return jsonify({
        'status': 'running',
        'endpoints': {
            '/api/analysis/<owner>/<repo>/formatted': 'Get detailed analysis results',
            '/api/analysis/<owner>/<repo>/summary': 'Get analysis summary'
        }
    })

@app.route('/api/analysis/<owner>/<repo>/formatted', methods=['GET'])
def get_formatted_analysis(owner, repo):
    """Get formatted analysis results with detailed breakdown"""
    repo_name = f"{owner}/{repo}"
    result = analysis_results.get(repo_name)
    
    if not result:
        return jsonify({
            'error': 'No analysis results found for this repository'
        }), 404
    
    if result.get('results'):
        formatted_results = format_semgrep_results(result['results'])
        return jsonify({
            'repository': repo_name,
            'timestamp': result['timestamp'],
            'status': result['status'],
            'analysis': formatted_results
        })
    
    return jsonify({
        'error': 'Analysis results are empty or invalid'
    }), 404

@app.route('/api/analysis/<owner>/<repo>/summary', methods=['GET'])
def get_analysis_summary(owner, repo):
    """Get a quick summary of the analysis results"""
    repo_name = f"{owner}/{repo}"
    result = analysis_results.get(repo_name)
    
    if not result or not result.get('results'):
        return jsonify({
            'error': 'No analysis results found for this repository'
        }), 404
    
    formatted_results = format_semgrep_results(result['results'])
    
    return jsonify({
        'repository': repo_name,
        'timestamp': result['timestamp'],
        'status': result['status'],
        'summary': {
            'total_findings': formatted_results['summary']['total_findings'],
            'files_scanned': formatted_results['summary']['total_files_scanned'],
            'severity_counts': formatted_results['severity_counts'],
            'category_counts': formatted_results['category_counts'],
            'has_errors': len(formatted_results['errors']) > 0
        }
    })

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle GitHub webhook events"""
    try:
        logger.debug("Received webhook request")
        
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_webhook_signature(request.get_data(), signature):
            logger.error("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 401

        event_type = request.headers.get('X-GitHub-Event', 'ping')
        logger.info(f"Processing event type: {event_type}")

        if event_type == 'ping':
            return jsonify({"message": "Pong!"}), 200

        if event_type == 'installation':
            payload = request.json
            
            if payload.get('action') not in ['created', 'added']:
                return jsonify({"message": "Ignored installation action"}), 200

            installation_id = payload['installation']['id']
            logger.info(f"Processing installation ID: {installation_id}")

            installation_token = git_integration.get_access_token(installation_id).token
            github_client = Github(installation_token)

            results = {}
            repositories = payload.get('repositories', [])
            
            for repo in repositories:
                repo_full_name = repo['full_name']
                repo_url = f"https://github.com/{repo_full_name}.git"
                
                logger.info(f"Processing repository: {repo_full_name}")
                semgrep_output = trigger_semgrep_analysis(repo_url, installation_token)
                
                if semgrep_output:
                    results[repo_full_name] = semgrep_output
                    
                    try:
                        repo_obj = github_client.get_repo(repo_full_name)
                        repo_obj.create_issue(
                            title="Semgrep Security Analysis Results",
                            body=f"```json\n{semgrep_output}\n```"
                        )
                        logger.info(f"Created issue in {repo_full_name}")
                    except Exception as e:
                        logger.error(f"Error creating issue in {repo_full_name}: {str(e)}")

            return jsonify({
                "status": "success",
                "message": "Analysis completed",
                "results": results
            }), 200

        return jsonify({"message": "Event received"}), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)