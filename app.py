from flask import Flask, request, jsonify
import os
from github import Github, GithubIntegration
import subprocess
import logging
from dotenv import load_dotenv

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
