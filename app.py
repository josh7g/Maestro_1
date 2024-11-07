# app.py
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
from flask_migrate import Migrate
from models import db, AnalysisResult
from sqlalchemy import or_  

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

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

if not DATABASE_URL:
    DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/semgrep_analysis'

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Create tables at startup
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully!")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")

def format_private_key(key_data):
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")
        
        key_data = key_data.strip()
        
        if '\\n' in key_data:
            parts = key_data.split('\\n')
            key_data = '\n'.join(part.strip() for part in parts if part.strip())
        elif '\n' not in key_data:
            key_length = len(key_data)
            if key_length < 64:
                raise ValueError("Key content too short")
            
            if not key_data.startswith('-----BEGIN'):
                key_data = (
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(key_data[i:i+64] for i in range(0, len(key_data), 64)) +
                    '\n-----END RSA PRIVATE KEY-----'
                )
        
        if not key_data.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            key_data = '-----BEGIN RSA PRIVATE KEY-----\n' + key_data
        if not key_data.endswith('-----END RSA PRIVATE KEY-----'):
            key_data = key_data + '\n-----END RSA PRIVATE KEY-----'
        
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

def trigger_semgrep_analysis(repo_url, installation_token):
    """Run Semgrep analysis and save results to database"""
    clone_dir = None
    repo_name = repo_url.split('github.com/')[-1].replace('.git', '')
    
    try:
        repo_url_with_auth = f"https://x-access-token:{installation_token}@github.com/{repo_name}.git"
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"
        
        # Create initial database entry
        analysis = AnalysisResult(
            repository_name=repo_name,
            status='in_progress'
        )
        db.session.add(analysis)
        db.session.commit()
        
        clean_directory(clone_dir)
        
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
            
            # Update database entry with results
            analysis.status = 'completed'
            analysis.results = semgrep_output
            db.session.commit()
            
            logger.info(f"Semgrep analysis completed successfully for {repo_name}")
            return semgrep_process.stdout
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {str(e)}")
            analysis.status = 'failed'
            analysis.error = f"Invalid Semgrep output: {str(e)}"
            db.session.commit()
            return None

    except Exception as e:
        logger.error(f"Analysis error for {repo_name}: {str(e)}")
        if 'analysis' in locals():
            analysis.status = 'failed'
            analysis.error = str(e)
            db.session.commit()
        return None
    finally:
        if clone_dir:
            clean_directory(clone_dir)

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
                
                if severity not in formatted_response['findings_by_severity']:
                    formatted_response['findings_by_severity'][severity] = []
                formatted_response['findings_by_severity'][severity].append(formatted_finding)
                
                if category not in formatted_response['findings_by_category']:
                    formatted_response['findings_by_category'][category] = []
                formatted_response['findings_by_category'][category].append(formatted_finding)
                
            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                formatted_response['errors'].append(f"Error processing finding: {str(e)}")

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

# GitHub App configuration
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

# API Routes
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

        # Handle both installation and installation_repositories events
        if event_type in ['installation', 'installation_repositories']:
            payload = request.json
            
            # For installation_repositories, check for 'added' repositories
            # For installation, check for 'created' or 'added' action
            valid_actions = ['created', 'added']
            if event_type == 'installation_repositories':
                # Check if there are added repositories
                if not payload.get('repositories_added'):
                    return jsonify({
                        'success': True,
                        'message': 'No repositories added'
                    })
            elif payload.get('action') not in valid_actions:
                return jsonify({
                    'success': True,
                    'message': 'Event ignored'
                })

            installation_id = payload['installation']['id']
            logger.info(f"Processing installation ID: {installation_id}")

            try:
                installation_token = git_integration.get_access_token(installation_id).token
            except Exception as e:
                logger.error(f"Failed to get installation token: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Failed to authenticate with GitHub',
                        'details': str(e)
                    }
                }), 500

            # Get repositories based on event type
            if event_type == 'installation_repositories':
                repositories = payload.get('repositories_added', [])
            else:
                repositories = payload.get('repositories', [])

            processed_repos = []
            
            for repo in repositories:
                repo_full_name = repo['full_name']
                repo_url = f"https://github.com/{repo_full_name}.git"
                
                logger.info(f"Analyzing repository: {repo_full_name}")
                semgrep_output = trigger_semgrep_analysis(repo_url, installation_token)
                
                if semgrep_output:
                    processed_repos.append(repo_full_name)
                    logger.info(f"Analysis completed for {repo_full_name}")

            return jsonify({
                'success': True,
                'data': {
                    'message': 'Analysis completed',
                    'repositories_analyzed': processed_repos
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

        repositories = payload.get('repositories', [])
        processed_repos = []
            
        for repo in repositories:
                repo_full_name = repo['full_name']
                repo_url = f"https://github.com/{repo_full_name}.git"
                
                logger.info(f"Analyzing repository: {repo_full_name}")
                semgrep_output = trigger_semgrep_analysis(repo_url, installation_token)
                
                if semgrep_output:
                    processed_repos.append(repo_full_name)
                    logger.info(f"Analysis completed for {repo_full_name}")
                    
        return jsonify({
                'success': True,
                'data': {
                    'message': 'Analysis completed',
                    'repositories_analyzed': processed_repos
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
    
@app.route('/api/v1/analysis/scan', methods=['POST'])
def scan_repository():
    """Scan a specific repository"""
    try:
        payload = request.json
        if not payload or 'owner' not in payload or 'repo' not in payload or 'installation_id' not in payload:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Missing required fields: owner, repo, and installation_id',
                    'code': 'INVALID_PAYLOAD'
                }
            }), 400

        owner = payload['owner']
        repo = payload['repo']
        installation_id = payload['installation_id']
        repo_name = f"{owner}/{repo}"
        repo_url = f"https://github.com/{repo_name}.git"

        try:
            installation_token = git_integration.get_access_token(installation_id).token
        except Exception as e:
            logger.error(f"Failed to get installation token: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Invalid installation ID',
                    'details': str(e)
                }
            }), 404

        semgrep_output = trigger_semgrep_analysis(repo_url, installation_token)
        
        if semgrep_output:
            return jsonify({
                'success': True,
                'data': {
                    'message': 'Analysis initiated successfully',
                    'repository': repo_name,
                    'status': 'completed'
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Analysis failed',
                    'code': 'ANALYSIS_FAILED'
                }
            }), 500

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to initiate scan',
                'details': str(e)
            }
        }), 500
    
@app.route('/api/v1/analysis/status', methods=['GET'])
def get_all_analyses():
    """Get status of all analyses with pagination"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', 10))
        
        pagination = AnalysisResult.query.order_by(
            AnalysisResult.timestamp.desc()
        ).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        analyses = [{
            'repository': result.repository_name,
            'timestamp': result.timestamp.isoformat(),
            'status': result.status,
            'error': result.error,
            'summary': {
                'total_findings': len(result.results.get('results', [])) if result.results else 0,
                'status': 'completed' if result.results else 'failed'
            }
        } for result in pagination.items]
        
        return jsonify({
            'success': True,
            'data': {
                'analyses': analyses,
                'pagination': {
                    'current_page': page,
                    'total_pages': pagination.pages,
                    'total_items': pagination.total,
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
        result = AnalysisResult.query.filter_by(
            repository_name=repo_name
        ).order_by(
            AnalysisResult.timestamp.desc()
        ).first()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analysis found',
                    'code': 'ANALYSIS_NOT_FOUND'
                }
            }), 404
        
        if result.status == 'failed':
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Analysis failed',
                    'details': result.error,
                    'code': 'ANALYSIS_FAILED'
                }
            }), 400
            
        formatted_results = format_semgrep_results(result.results)
        
        return jsonify({
            'success': True,
            'data': {
                'repository': {
                    'name': repo_name,
                    'owner': owner,
                    'repo': repo
                },
                'metadata': {
                    'timestamp': result.timestamp.isoformat(),
                    'status': result.status,
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
        result = AnalysisResult.query.filter_by(
            repository_name=repo_name
        ).order_by(
            AnalysisResult.timestamp.desc()
        ).first()
        
        if not result or not result.results:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analysis found',
                    'code': 'ANALYSIS_NOT_FOUND'
                }
            }), 404
            
        formatted_results = format_semgrep_results(result.results)
        findings = formatted_results['findings']
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f['severity'] == severity]
        if category:
            findings = [f for f in findings if f['category'] == category]
            
        # Manual pagination
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
                    'timestamp': result.timestamp.isoformat(),
                    'status': result.status
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



# Keep the original GET endpoint for single user
@app.route('/api/v1/users/<github_user>/top-vulnerabilities', methods=['GET'])
def get_user_top_vulnerabilities(github_user):
    """Get top vulnerabilities for a single GitHub user"""
    return process_vulnerabilities([github_user])

# Add new POST endpoint for multiple users
@app.route('/api/v1/users/top-vulnerabilities', methods=['POST'])
def get_multiple_users_vulnerabilities():
    """Get top vulnerabilities for multiple GitHub users"""
    try:
        request_data = request.get_json()
        if not request_data or 'users' not in request_data:
            # If no users specified, get all repositories
            return process_vulnerabilities([])
            
        users = request_data['users']
        if not isinstance(users, list):
            users = [users]
        
        # Clean and validate users
        users = [user.strip() for user in users if isinstance(user, str) and user.strip()]
        return process_vulnerabilities(users)
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to process request',
                'details': str(e)
            }
        }), 500

def process_vulnerabilities(users=None):
    """Process vulnerabilities for given users or all repositories if users is empty"""
    try:
        # Base query for completed analyses
        base_query = AnalysisResult.query.filter(
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None)
        )

        # If users are specified, filter by those users
        if users:
            user_filters = [AnalysisResult.repository_name.like(f'{user}/%') for user in users]
            base_query = base_query.filter(or_(*user_filters))

        # Get all analyses ordered by timestamp
        analyses = base_query.order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analyses found',
                    'code': 'NO_ANALYSES_FOUND'
                }
            }), 404

        # Process and format vulnerabilities
        all_vulnerabilities = []
        seen_vulns = set()  # Track unique vulnerabilities

        for analysis in analyses:
            try:
                formatted_results = format_semgrep_results(analysis.results)
                repo_name = analysis.repository_name
                
                for finding in formatted_results.get('findings', []):
                    # Create a unique identifier for the vulnerability
                    vuln_id = f"{repo_name}_{finding.get('file')}_{finding.get('start', {}).get('line', '0')}"
                    
                    # Skip if we've already seen this vulnerability
                    if vuln_id in seen_vulns:
                        continue
                    
                    seen_vulns.add(vuln_id)
                    
                    vulnerability = {
                        'category': finding.get('category', 'security'),
                        'code_snippet': finding.get('code_snippet', ''),
                        'file': finding.get('file'),
                        'fix_recommendations': {
                            'description': finding.get('fix_recommendations', {}).get('description', ''),
                            'references': finding.get('fix_recommendations', {}).get('references', [])
                        },
                        'line_range': finding.get('line_range'),
                        'message': finding.get('message'),
                        'repository': {
                            'analyzed_at': analysis.timestamp.isoformat(),
                            'full_name': repo_name,
                            'name': repo_name.split('/')[-1]
                        },
                        'security_references': {
                            'cwe': finding.get('security_references', {}).get('cwe', []),
                            'owasp': finding.get('security_references', {}).get('owasp', [])
                        },
                        'severity': finding.get('severity'),
                        'vulnerability_id': finding.get('id')
                    }
                    
                    all_vulnerabilities.append(vulnerability)
                    
            except Exception as e:
                logger.error(f"Error processing analysis for {analysis.repository_name}: {str(e)}")
                continue

        # Sort vulnerabilities by severity and timestamp
        severity_order = {
            'ERROR': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'WARNING': 4,
            'INFO': 5
        }

        all_vulnerabilities.sort(
            key=lambda x: (
                severity_order.get(x['severity'], 999),
                x['repository']['analyzed_at']
            ),
            reverse=True
        )

        # Calculate statistics
        severity_counts = {}
        for vuln in all_vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        unique_repos = {vuln['repository']['full_name'] for vuln in all_vulnerabilities}
        
        response_data = {
            'success': True,
            'data': {
                'metadata': {
                    'total_vulnerabilities': len(all_vulnerabilities),
                    'total_repositories': len(unique_repos),
                    'severity_breakdown': severity_counts,
                },
                'top_vulnerabilities': all_vulnerabilities
            }
        }

        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error processing vulnerabilities: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to process vulnerabilities',
                'details': str(e)
            }
        }), 500
    
@app.route('/api/v1/users/<github_user>/debug-findings', methods=['GET'])
def debug_raw_findings(github_user):
    """Debug endpoint to see raw findings data"""
    try:
        analysis = AnalysisResult.query.filter(
            AnalysisResult.repository_name.like(f'{github_user}/%')
        ).order_by(
            AnalysisResult.timestamp.desc()
        ).first()
        
        if not analysis:
            return jsonify({
                'success': False,
                'error': 'No analysis found'
            })
            
        return jsonify({
            'success': True,
            'data': {
                'repository': analysis.repository_name,
                'timestamp': analysis.timestamp.isoformat(),
                'raw_results': analysis.results
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })    
@app.route('/api/v1/vulnerabilities/file', methods=['GET'])
def get_vulnerable_file():
    """
    Get the contents of a vulnerable file from GitHub
    Query parameters:
    - owner: Repository owner
    - repo: Repository name
    - path: File path
    - installation_id: GitHub App installation ID
    - line_start: Starting line of vulnerability (optional)
    - line_end: Ending line of vulnerability (optional)
    """
    try:
        # Get query parameters
        owner = request.args.get('owner')
        repo = request.args.get('repo')
        file_path = request.args.get('path')
        installation_id = request.args.get('installation_id')
        line_start = request.args.get('line_start', type=int)
        line_end = request.args.get('line_end', type=int)

        # Validate required parameters
        if not all([owner, repo, file_path, installation_id]):
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Missing required parameters',
                    'code': 'MISSING_PARAMETERS'
                }
            }), 400

        try:
            # Get installation token
            installation_token = git_integration.get_access_token(installation_id).token
            gh = Github(installation_token)
            
            # Get repository and file contents
            repository = gh.get_repo(f"{owner}/{repo}")
            file_content = repository.get_contents(file_path)
            
            if not file_content:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'File not found',
                        'code': 'FILE_NOT_FOUND'
                    }
                }), 404

            # Decode content
            content = file_content.decoded_content.decode('utf-8')
            lines = content.splitlines()
            
            # Get file metadata
            file_info = {
                'name': file_content.name,
                'path': file_content.path,
                'size': file_content.size,
                'sha': file_content.sha,
                'url': file_content.html_url,
                'total_lines': len(lines)
            }

            # If line range is specified, extract only those lines
            if line_start is not None and line_end is not None:
                # Adjust for 0-based indexing
                line_start = max(0, line_start - 1)
                line_end = min(len(lines), line_end)
                
                # Get context (5 lines before and after)
                context_start = max(0, line_start - 5)
                context_end = min(len(lines), line_end + 5)
                
                content_lines = lines[context_start:context_end]
                
                # Mark the vulnerability range
                line_markers = []
                for i in range(len(content_lines)):
                    actual_line = context_start + i + 1
                    is_vulnerable = line_start + 1 <= actual_line <= line_end
                    line_markers.append({
                        'line_number': actual_line,
                        'is_vulnerable': is_vulnerable
                    })

                response_content = '\n'.join(content_lines)
            else:
                response_content = content
                line_markers = [{'line_number': i + 1, 'is_vulnerable': False} for i in range(len(lines))]

            return jsonify({
                'success': True,
                'data': {
                    'file_info': file_info,
                    'content': response_content,
                    'line_markers': line_markers,
                    'metadata': {
                        'repository': {
                            'owner': owner,
                            'name': repo,
                            'full_name': f"{owner}/{repo}"
                        },
                        'vulnerability_context': {
                            'line_start': line_start + 1 if line_start is not None else None,
                            'line_end': line_end if line_end is not None else None
                        }
                    }
                }
            })

        except Exception as e:
            logger.error(f"GitHub API error: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Failed to fetch file from GitHub',
                    'details': str(e)
                }
            }), 500

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'details': str(e)
            }
        }), 500

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    port = int(os.getenv('PORT', 10000))
    if os.getenv('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=port)
    else:
        app.run(host='127.0.0.1', port=port, debug=True)

