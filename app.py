from flask import Flask, request, jsonify
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
from github import Github, GithubIntegration
from dotenv import load_dotenv

app = Flask(__name__)

# Set up logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more detailed logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def debug_private_key():
    """Debug function to check private key formatting"""
    private_key = os.getenv('GITHUB_APP_PRIVATE_KEY', '')
    logger.debug("Private key length: %d", len(private_key))
    logger.debug("First 50 characters: %s", private_key[:50])
    logger.debug("Last 50 characters: %s", private_key[-50:])
    logger.debug("Contains BEGIN marker: %s", "BEGIN RSA PRIVATE KEY" in private_key)
    logger.debug("Contains END marker: %s", "END RSA PRIVATE KEY" in private_key)
    logger.debug("Number of newlines: %d", private_key.count('\n'))
    return private_key

def initialize_github_integration():
    """Initialize GitHub Integration with better error handling"""
    try:
        app_id = os.getenv('GITHUB_APP_ID')
        logger.debug("App ID: %s", app_id)
        
        private_key = debug_private_key()
        
        # Clean up the private key
        if '\\n' in private_key:
            private_key = private_key.replace('\\n', '\n')
        
        # Ensure the key has proper markers and formatting
        if not private_key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            private_key = '-----BEGIN RSA PRIVATE KEY-----\n' + private_key
        if not private_key.endswith('-----END RSA PRIVATE KEY-----'):
            private_key = private_key + '\n-----END RSA PRIVATE KEY-----'
        
        # Add newline after BEGIN if missing
        private_key = private_key.replace('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----\n')
        # Add newline before END if missing
        private_key = private_key.replace('-----END RSA PRIVATE KEY-----', '\n-----END RSA PRIVATE KEY-----')
        
        logger.debug("Attempting to create GithubIntegration instance...")
        return GithubIntegration(
            integration_id=int(app_id),
            private_key=private_key,
        )
    except ValueError as ve:
        logger.error("ValueError in initialize_github_integration: %s", str(ve))
        raise
    except Exception as e:
        logger.error("Error in initialize_github_integration: %s", str(e))
        raise

# Initialize GitHub Integration
try:
    git_integration = initialize_github_integration()
    logger.info("Successfully initialized GitHub Integration")
except Exception as e:
    logger.error("Failed to initialize GitHub Integration: %s", str(e))
    raise

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle GitHub webhook events"""
    try:
        # Log headers for debugging
        logger.debug("Received headers: %s", dict(request.headers))
        
        event_type = request.headers.get('X-GitHub-Event', 'ping')
        logger.info(f"Received event: {event_type}")

        if event_type == 'ping':
            return jsonify({"message": "Pong!"}), 200

        if event_type == 'installation':
            try:
                payload = request.json
                logger.debug("Received payload: %s", payload)
                
                installation_id = payload['installation']['id']
                logger.debug("Installation ID: %s", installation_id)
                
                # Test the GitHub Integration
                token = git_integration.get_access_token(installation_id)
                logger.debug("Successfully got access token")
                
                # Rest of your webhook handling code...
                return jsonify({"message": "Webhook processed successfully"}), 200
                
            except KeyError as ke:
                logger.error(f"Missing key in payload: {str(ke)}")
                return jsonify({"error": f"Missing required field: {str(ke)}"}), 400
            except Exception as e:
                logger.error(f"Error processing installation event: {str(e)}")
                return jsonify({"error": str(e)}), 500

        return jsonify({"message": "Event received"}), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/debug-key', methods=['GET'])
def debug_key_endpoint():
    """Endpoint to check key formatting (Remove in production!)"""
    try:
        debug_private_key()
        return jsonify({
            "message": "Debug information logged",
            "app_id": os.getenv('GITHUB_APP_ID'),
            "key_exists": bool(os.getenv('GITHUB_APP_PRIVATE_KEY'))
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('RENDER_PORT', 5000))
    app.run(host='0.0.0.0', port=port)