# app.py
from flask import Flask, request, jsonify
import os
from github import Github, GithubIntegration
import subprocess

app = Flask(__name__)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

APP_ID = os.getenv('GITHUB_APP_ID')
WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
PRIVATE_KEY_PATH = os.getenv('GITHUB_PRIVATE_KEY_PATH')
PORT = os.getenv('RENDER_PORT', 5000)

# GitHub Integration instance
with open(PRIVATE_KEY_PATH, 'r') as key_file:
    private_key = key_file.read()

git_integration = GithubIntegration(APP_ID, private_key)

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
        print("Semgrep Output:", result.stdout)
        return result.stdout

    except subprocess.CalledProcessError as e:
        print("Error running Semgrep:", e)
        return None

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """
    Handle the GitHub webhook events.
    """
    event_type = request.headers.get('X-GitHub-Event', 'ping')

    if event_type == 'installation':
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
            print(f"Semgrep Output for {repo_full_name}:", semgrep_output)

    return jsonify({"message": "Webhook received"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(PORT))
