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

# Enhanced logging for Render
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration with better error handling
def get_env_variable(var_name):
    """Get environment variable or raise exception."""
    value = os.getenv(var_name)
    if value is None:
        raise ValueError(f"Environment variable {var_name} is not set")
    return value

try:
    APP_ID = get_env_variable('GITHUB_APP_ID')
    WEBHOOK_SECRET = get_env_variable('GITHUB_WEBHOOK_SECRET')
    PRIVATE_KEY = get_env_variable('GITHUB_APP_PRIVATE_KEY')
    PORT = int(os.getenv('PORT', 10000))  # Render prefers port 10000
except ValueError as e:
    logger.error(f"Configuration error: {str(e)}")
    raise

def format_private_key(key):
    """Format the private key correctly."""
    try:
        # Remove any existing whitespace
        key = key.strip()
        
        # If key is already properly formatted, return it
        if "\n" in key and "-----BEGIN RSA PRIVATE KEY-----" in key:
            return key
            
        # Replace literal \n with actual newlines
        if '\\n' in key:
            key = key.replace('\\n', '\n')
            
        # Verify the key format
        if not key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            raise ValueError("Private key is missing proper header")
        if not key.endswith('-----END RSA PRIVATE KEY-----'):
            raise ValueError("Private key is missing proper footer")
            
        return key
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise

# Initialize GitHub Integration with better error handling
try:
    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("Successfully initialized GitHub Integration")
except Exception as e:
    logger.error(f"Failed to initialize GitHub Integration: {str(e)}")
    logger.error("Please check your private key format and App ID")
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

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle GitHub webhook events"""
    try:
        # Log the incoming request
        logger.info(f"Received webhook. Headers: {dict(request.headers)}")
        
        # Verify webhook signature
        signature = request.headers.get('X-Hub-Signature-256')
        if not verify_webhook_signature(request.get_data(), signature):
            logger.error("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 401

        # Get event type
        event_type = request.headers.get('X-GitHub-Event', 'ping')
        logger.info(f"Processing event type: {event_type}")

        # Handle ping event
        if event_type == 'ping':
            return jsonify({"message": "Pong!"}), 200

        # Handle installation event
        if event_type == 'installation':
            payload = request.json
            logger.info(f"Received installation payload: {payload}")
            
            if payload.get('action') not in ['created', 'added']:
                return jsonify({"message": "Ignored installation action"}), 200

            installation_id = payload['installation']['id']
            logger.info(f"Processing installation ID: {installation_id}")

            # Get installation token
            installation_token = git_integration.get_access_token(installation_id).token
            github_client = Github(installation_token)

            # Process repositories
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
        logger.error(f"Error processing webhook: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    # Use 0.0.0.0 to make the server publicly accessible
    app.run(host='0.0.0.0', port=PORT)