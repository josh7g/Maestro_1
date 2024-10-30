from flask import Flask, request, jsonify
import os
from github import Github, GithubIntegration
import subprocess
import logging
from dotenv import load_dotenv
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

APP_ID = os.getenv('GITHUB_APP_ID')
WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
PORT = os.getenv('RENDER_PORT', 5000)

# GitHub Integration instance
PRIVATE_KEY = os.getenv("GITHUB_APP_PRIVATE_KEY")
if not PRIVATE_KEY:
    raise ValueError("GITHUB_APP_PRIVATE_KEY environment variable not set or empty")

git_integration = GithubIntegration(APP_ID, PRIVATE_KEY)

def fetch_public_key(app_id):
    """
    Fetch the public key for webhook verification from GitHub.
    """
    try:
        # Get a JWT for authenticating as the GitHub App itself
        jwt_token = git_integration.create_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        # Fetch the public key using GitHub's REST API
        response = requests.get(f"https://api.github.com/app/hook/config", headers=headers)
        response.raise_for_status()

        # Extract and return the public key in PEM format
        public_key_pem = response.json()["public_key"]
        
        # Add header and footer if missing
        if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
            public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key_pem}\n-----END PUBLIC KEY-----"
        
        return public_key_pem

    except Exception as e:
        logger.error(f"Error fetching public key: {str(e)}")
        return None

def verify_signature(public_key_pem, payload, signature):
    """
    Verify the webhook signature using the provided public key.
    """
    try:
        # Convert the key from string to bytes and load it
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        # Verify the signature (assuming the signature is in a base64-encoded string)
        public_key.verify(
            signature.encode("utf-8"),  # Convert signature to bytes
            payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Error verifying signature: {str(e)}")
        return False

def trigger_semgrep_analysis(repo_url):
    """
    Function to clone the repository and run Semgrep scan.
    """
    try:
        # Clone the repository
        repo_name = repo_url.split('/')[-1]
        clone_dir = f"/tmp/{repo_name}"
        subprocess.run(["git", "clone", repo_url, clone_dir], check=True)

        # Run Semgrep analysis
        result = subprocess.run(["semgrep", "--config=auto", clone_dir], capture_output=True, text=True)

        # Process the results (you can customize this part)
        logger.info("Semgrep Output:\n%s", result.stdout)
        return result.stdout

    except subprocess.CalledProcessError as e:
        logger.error("Error running Semgrep: %s", e.stderr)
        return None

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """
    Handle the GitHub webhook events.
    """
    event_type = request.headers.get('X-GitHub-Event', 'ping')
    
    logger.info(f"Received event: {event_type}")

    if event_type == 'installation':
        try:
            payload = request.json
            installation_id = payload['installation']['id']
            
            # Fetch the public key for verifying the webhook
            public_key_pem = fetch_public_key(APP_ID)
            if not public_key_pem:
                return jsonify({"error": "Could not fetch public key"}), 500

            # Get the access token for the installation
            access_token = git_integration.get_access_token(installation_id).token
            github_client = Github(access_token)

            # Fetch the installed repositories
            repositories = payload['repositories']
            for repo in repositories:
                repo_full_name = repo['full_name']
                repo_url = f"https://github.com/{repo_full_name}.git"
                semgrep_output = trigger_semgrep_analysis(repo_url)
                logger.info(f"Semgrep Output for {repo_full_name}: {semgrep_output}")

        except Exception as e:
            logger.error(f"Error processing installation event: {str(e)}")
            return jsonify({"error": "Internal Server Error"}), 500

    return jsonify({"message": "Webhook received"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(PORT))
