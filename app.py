from flask import Flask, request, jsonify
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
from github import Github, GithubIntegration
from dotenv import load_dotenv

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

def get_env_variable(var_name):
    """Get environment variable or raise exception."""
    value = os.getenv(var_name)
    if value is None:
        raise ValueError(f"Environment variable {var_name} is not set")
    return value

def format_private_key(key):
    """Format the private key correctly with improved error handling."""
    try:
        # Remove any whitespace and newline characters
        key = key.strip()
        
        # Handle different newline formats
        if '\\n' in key:
            key = key.replace('\\n', '\n')
        if r'\n' in key:
            key = key.replace(r'\n', '\n')
        
        # Add header and footer if missing
        if not key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            key = '-----BEGIN RSA PRIVATE KEY-----\n' + key
        if not key.endswith('-----END RSA PRIVATE KEY-----'):
            key = key + '\n-----END RSA PRIVATE KEY-----'
            
        # Ensure proper line breaks
        parts = key.split('\n')
        if len(parts) == 1:
            # If it's a single line, try to format it properly
            key_body = parts[0]
            if '-----BEGIN RSA PRIVATE KEY-----' in key_body:
                key_body = key_body.replace('-----BEGIN RSA PRIVATE KEY-----', '')
            if '-----END RSA PRIVATE KEY-----' in key_body:
                key_body = key_body.replace('-----END RSA PRIVATE KEY-----', '')
            
            formatted_key = (
                '-----BEGIN RSA PRIVATE KEY-----\n' +
                key_body + '\n' +
                '-----END RSA PRIVATE KEY-----'
            )
            key = formatted_key

        logger.info("Successfully formatted private key")
        return key
        
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

def trigger_semgrep_analysis(repo_url, installation_token):
    """Clone repository and run Semgrep scan with proper authentication"""
    clone_dir = None
    try:
        # Use installation token for authentication
        repo_url_with_auth = repo_url.replace(
            "https://",
            f"https://x-access-token:{installation_token}@"
        )
        
        # Create unique directory for this analysis
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        clone_dir = f"/tmp/semgrep_{repo_name}_{os.getpid()}"
        
        # Ensure clean directory
        clean_directory(clone_dir)
        
        # Clone repository
        logger.info(f"Cloning repository to {clone_dir}")
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url_with_auth, clone_dir],
            check=True,
            capture_output=True,
            text=True
        )

        # Run Semgrep analysis
        logger.info("Running Semgrep analysis")
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", clone_dir],
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.cmd}")
        logger.error(f"Error output: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"Error in Semgrep analysis: {str(e)}")
        return None
    finally:
        # Clean up cloned repository
        if clone_dir:
            clean_directory(clone_dir)

# Load configuration with enhanced error handling
try:
    APP_ID = get_env_variable('GITHUB_APP_ID')
    WEBHOOK_SECRET = get_env_variable('GITHUB_WEBHOOK_SECRET')
    PRIVATE_KEY = get_env_variable('GITHUB_APP_PRIVATE_KEY')
    PORT = int(os.getenv('PORT', 10000))
    
    # Log configuration (safely)
    logger.info(f"Loaded APP_ID: {APP_ID}")
    logger.info(f"Webhook secret length: {len(WEBHOOK_SECRET) if WEBHOOK_SECRET else 0}")
    logger.info(f"Private key length: {len(PRIVATE_KEY) if PRIVATE_KEY else 0}")
    
    # Format the private key
    formatted_key = format_private_key(PRIVATE_KEY)
    
    # Initialize GitHub Integration
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("Successfully initialized GitHub Integration")
    
except Exception as e:
    logger.error(f"Initialization error: {str(e)}", exc_info=True)
    raise

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle GitHub webhook events"""
    try:
        # Log the incoming request
        logger.debug(f"Received webhook. Headers: {dict(request.headers)}")
        
        # Verify webhook signature
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_webhook_signature(request.get_data(), signature):
            logger.error("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 401

        # Get event type
        event_type = request.headers.get('X-GitHub-Event', 'ping')
        logger.info(f"Processing event type: {event_type}")

        if event_type == 'ping':
            return jsonify({"message": "Pong!"}), 200

        if event_type == 'installation':
            payload = request.json
            logger.debug(f"Received payload: {payload}")
            
            if payload.get('action') not in ['created', 'added']:
                return jsonify({"message": "Ignored installation action"}), 200

            installation_id = payload['installation']['id']
            logger.info(f"Processing installation ID: {installation_id}")

            # Get installation token
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
                    
                    # Create issue with results
                    try:
                        repo_obj = github_client.get_repo(repo_full_name)
                        repo_obj.create_issue(
                            title="Semgrep Security Analysis Results",
                            body=f"```json\n{semgrep_output}\n```"
                        )
                        logger.info(f"Created issue in {repo_full_name}")
                    except Exception as e:
                        logger.error(f"Error creating issue in {repo_full_name}: {str(e)}")

            return jsonify({"results": results}), 200

        return jsonify({"message": "Event received"}), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)