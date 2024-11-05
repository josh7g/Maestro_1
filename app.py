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

@app.route('/api/v1/users/<github_user>/top-vulnerabilities', methods=['GET'])
def get_user_top_vulnerabilities(github_user):
    """Get top 5 vulnerabilities for a specific GitHub user, grouped by repository"""
    try:
        if not github_user:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'GitHub username is required',
                    'code': 'MISSING_USERNAME'
                }
            }), 400

        # Get all analyses for the specific user's repositories
        analyses = AnalysisResult.query.filter(
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None),
            AnalysisResult.repository_name.like(f'{github_user}/%')
        ).order_by(
            AnalysisResult.timestamp.desc()
        ).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'No analyses found for user {github_user}',
                    'code': 'NO_ANALYSES_FOUND'
                }
            }), 404

        # Add debug logging
        logger.info(f"Found {len(analyses)} analyses for user {github_user}")

        # Define severity order for sorting
        severity_order = {
            'ERROR': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'WARNING': 4,
            'INFO': 5
        }

        # Track repositories and their latest analysis timestamp
        repo_latest_analysis = {}
        all_findings = []

        # First pass: find latest analysis for each repo
        for analysis in analyses:
            repo_name = analysis.repository_name
            if repo_name not in repo_latest_analysis or analysis.timestamp > repo_latest_analysis[repo_name]['timestamp']:
                repo_latest_analysis[repo_name] = {
                    'timestamp': analysis.timestamp,
                    'findings': []
                }
                logger.info(f"Latest analysis for {repo_name}: {analysis.timestamp}")

        # Second pass: collect findings from latest analyses only
        for analysis in analyses:
            repo_name = analysis.repository_name
            if analysis.timestamp == repo_latest_analysis[repo_name]['timestamp']:
                try:
                    formatted_results = format_semgrep_results(analysis.results)
                    logger.info(f"Processing findings for {repo_name}")
                    
                    for finding in formatted_results.get('findings', []):
                        # Debug log the finding structure
                        logger.debug(f"Raw finding: {finding}")
                        
                        # Generate a unique ID using available fields
                        finding_id = f"{repo_name.replace('/', '_')}_{finding.get('check_id', '')}_{finding.get('file', 'unknown')}_{finding.get('start', {}).get('line', '0')}"
                        
                        formatted_finding = {
                            'id': finding_id,
                            'file': finding.get('path', finding.get('file', 'unknown')),
                            'severity': finding.get('extra', {}).get('severity', finding.get('severity', 'UNKNOWN')),
                            'message': finding.get('extra', {}).get('message', finding.get('message', '')),
                            'code_snippet': finding.get('extra', {}).get('lines', finding.get('code_snippet', '')),
                            'line_range': f"{finding.get('start', {}).get('line', '0')}-{finding.get('end', {}).get('line', '0')}",
                            'category': finding.get('extra', {}).get('metadata', {}).get('category', 'security'),
                            'security_references': {
                                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', [])
                            },
                            'fix_recommendations': {
                                'description': finding.get('extra', {}).get('metadata', {}).get('message', ''),
                                'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                            }
                        }
                        
                        repo_latest_analysis[repo_name]['findings'].append(formatted_finding)
                        all_findings.append(formatted_finding)
                        
                except Exception as e:
                    logger.error(f"Error processing findings for {repo_name}: {str(e)}")
                    logger.error("Raw results:", analysis.results)
                    continue

        # Sort findings within each repository
        for repo_data in repo_latest_analysis.values():
            repo_data['findings'].sort(key=lambda x: (
                severity_order.get(x['severity'], 999)
            ))

        # Format the findings by repository
        grouped_vulnerabilities = {}
        for repo_name, repo_data in repo_latest_analysis.items():
            if repo_data['findings']:
                grouped_vulnerabilities[repo_name] = {
                    'repository_info': {
                        'name': repo_name.split('/')[1],
                        'full_name': repo_name,
                        'analyzed_at': repo_data['timestamp'].isoformat()
                    },
                    'vulnerabilities': repo_data['findings'][:5]  # Limit to top 5 per repo
                }

        return jsonify({
            'success': True,
            'data': {
                'github_user': github_user,
                'metadata': {
                    'total_repositories_analyzed': len(repo_latest_analysis),
                    'total_vulnerabilities_found': len(all_findings)
                },
                'repositories': grouped_vulnerabilities,
                'summary': {
                    'severity_breakdown': {
                        severity: len([f for f in all_findings if f['severity'] == severity])
                        for severity in severity_order.keys()
                    }
                }
            }
        })

    except Exception as e:
        logger.error(f"Error getting user top vulnerabilities: {str(e)}")
        logger.error("Full traceback:", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to fetch top vulnerabilities',
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

@app.route('/api/v1/cleanup/old-scans', methods=['POST'])
def cleanup_old_scans():
    """Delete old scans keeping only the latest scan for each repository"""
    try:
        with db.session.begin():
            # Get all distinct repository names
            distinct_repos = db.session.query(
                AnalysisResult.repository_name
            ).distinct().all()
            
            deleted_count = 0
            retained_scans = []
            
            for (repo_name,) in distinct_repos:
                # Get all scans for this repository, ordered by timestamp
                repo_scans = AnalysisResult.query.filter(
                    AnalysisResult.repository_name == repo_name
                ).order_by(
                    AnalysisResult.timestamp.desc()
                ).all()
                
                if len(repo_scans) > 1:
                    # Keep the first (latest) scan and delete the rest
                    latest_scan = repo_scans[0]
                    retained_scans.append({
                        'repository': latest_scan.repository_name,
                        'timestamp': latest_scan.timestamp.isoformat()
                    })
                    
                    # Delete older scans
                    for old_scan in repo_scans[1:]:
                        db.session.delete(old_scan)
                        deleted_count += 1
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'data': {
                    'message': 'Cleanup completed successfully',
                    'scans_deleted': deleted_count,
                    'retained_scans': retained_scans
                }
            })
                
    except Exception as e:
        logger.error(f"Error during scan cleanup: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to cleanup old scans',
                'details': str(e)
            }
        }), 500

# Optional: Add an endpoint to cleanup scans for a specific user
@app.route('/api/v1/users/<github_user>/cleanup-scans', methods=['POST'])
def cleanup_user_scans(github_user):
    """Delete old scans for a specific user's repositories"""
    try:
        with db.session.begin():
            # Get all distinct repository names for the user
            distinct_repos = db.session.query(
                AnalysisResult.repository_name
            ).filter(
                AnalysisResult.repository_name.like(f'{github_user}/%')
            ).distinct().all()
            
            deleted_count = 0
            retained_scans = []
            
            for (repo_name,) in distinct_repos:
                # Get all scans for this repository, ordered by timestamp
                repo_scans = AnalysisResult.query.filter(
                    AnalysisResult.repository_name == repo_name
                ).order_by(
                    AnalysisResult.timestamp.desc()
                ).all()
                
                if len(repo_scans) > 1:
                    # Keep the first (latest) scan and delete the rest
                    latest_scan = repo_scans[0]
                    retained_scans.append({
                        'repository': latest_scan.repository_name,
                        'timestamp': latest_scan.timestamp.isoformat()
                    })
                    
                    # Delete older scans
                    for old_scan in repo_scans[1:]:
                        db.session.delete(old_scan)
                        deleted_count += 1
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'data': {
                    'message': f'Cleanup completed for user {github_user}',
                    'scans_deleted': deleted_count,
                    'retained_scans': retained_scans
                }
            })
                
    except Exception as e:
        logger.error(f"Error during user scan cleanup: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': {
                'message': f'Failed to cleanup scans for user {github_user}',
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

