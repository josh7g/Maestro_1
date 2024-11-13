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
from models import db, AnalysisResult
from sqlalchemy import or_, text
import traceback
import requests
from scanner import ChunkedScanner, ScanConfig, scan_repository_handler, validate_environment

# Load environment variables in development
if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Database configuration with better error handling
try:
    DATABASE_URL = os.getenv('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is not set")

    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 30,
        'pool_recycle': 1800,
    }

    # Initialize database
    db.init_app(app)
except Exception as e:
    logger.error(f"Database configuration error: {str(e)}")
    raise

# Initialize database and run migrations
def init_database():
    """Initialize database with error handling"""
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully!")

            # Test database connection
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            logger.info("Database connection successful")

            # Check if user_id column exists
            try:
                db.session.execute(text("""
                    DO $$ 
                    BEGIN
                        IF NOT EXISTS (
                            SELECT column_name 
                            FROM information_schema.columns 
                            WHERE table_name='analysis_results' AND column_name='user_id'
                        ) THEN
                            ALTER TABLE analysis_results 
                            ADD COLUMN user_id VARCHAR(255);
                            
                            CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                            ON analysis_results (user_id);
                        END IF;
                    END $$;
                """))
                db.session.commit()
                logger.info("Database schema is up to date")

            except Exception as column_error:
                logger.error(f"Error managing schema: {str(column_error)}")
                db.session.rollback()
                raise

        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            logger.error(traceback.format_exc())
            raise
        finally:
            db.session.remove()
def format_private_key(key_data: str) -> str:
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")
        
        key_data = key_data.strip()
        
        # Handle newlines
        if '\\n' in key_data:
            parts = key_data.split('\\n')
            key_data = '\n'.join(part.strip() for part in parts if part.strip())
        elif '\n' not in key_data:
            # Format long string into proper key format
            key_length = len(key_data)
            if key_length < 64:
                raise ValueError("Key content too short")
            
            if not key_data.startswith('-----BEGIN'):
                key_data = (
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(key_data[i:i+64] for i in range(0, len(key_data), 64)) +
                    '\n-----END RSA PRIVATE KEY-----'
                )
        
        # Ensure proper header and footer
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

def init_github():
    """Initialize GitHub integration with error handling"""
    try:
        APP_ID = os.getenv('GITHUB_APP_ID')
        WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
        PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
        
        if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
            raise ValueError("Missing required GitHub environment variables")
        
        formatted_key = format_private_key(PRIVATE_KEY)
        git_integration = GithubIntegration(
            integration_id=int(APP_ID),
            private_key=formatted_key,
        )
        logger.info("GitHub Integration initialized successfully")
        return git_integration
    except Exception as e:
        logger.error(f"GitHub integration error: {str(e)}")
        raise
# Initialize GitHub integration
def init_github():
    """Initialize GitHub integration with error handling"""
    try:
        APP_ID = os.getenv('GITHUB_APP_ID')
        WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
        PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
        
        if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
            raise ValueError("Missing required GitHub environment variables")
        
        formatted_key = format_private_key(PRIVATE_KEY)
        git_integration = GithubIntegration(
            integration_id=int(APP_ID),
            private_key=formatted_key,
        )
        logger.info("GitHub Integration initialized successfully")
        return git_integration
    except Exception as e:
        logger.error(f"GitHub integration error: {str(e)}")
        raise

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with system status"""
    try:
        # Check database connection
        db.session.execute(text('SELECT 1'))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # Check semgrep installation
    try:
        semgrep_version = subprocess.check_output(
            ['semgrep', '--version'], 
            stderr=subprocess.STDOUT
        ).decode().strip()
        semgrep_status = "installed"
    except Exception as e:
        semgrep_status = f"not installed: {str(e)}"

    # System information
    import psutil
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return jsonify({
        'status': 'healthy' if db_status == "healthy" and semgrep_status == "installed" else 'degraded',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'components': {
            'database': db_status,
            'semgrep': semgrep_status
        },
        'system': {
            'memory_used_percent': memory.percent,
            'disk_used_percent': disk.percent,
            'cpu_percent': psutil.cpu_percent(interval=1)
        }
    })

@app.route('/api/v1/analysis/scan', methods=['POST'])
async def scan_repository():
    """Scan a specific repository with enhanced error handling and monitoring"""
    start_time = datetime.now()
    
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Content-Type must be application/json',
                    'code': 'INVALID_CONTENT_TYPE'
                }
            }), 400

        payload = request.get_json()
        
        # Validate required fields
        required_fields = ['owner', 'repo', 'installation_id', 'user_id']
        missing_fields = [field for field in required_fields if field not in payload]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'Missing required fields: {", ".join(missing_fields)}',
                    'code': 'MISSING_REQUIRED_FIELDS'
                }
            }), 400

        # Extract and validate field values
        owner = str(payload['owner']).strip()
        repo = str(payload['repo']).strip()
        installation_id = str(payload['installation_id']).strip()
        user_id = str(payload['user_id']).strip()

        if not all([owner, repo, installation_id, user_id]):
            return jsonify({
                'success': False,
                'error': {
                    'message': 'All required fields must have non-empty values',
                    'code': 'INVALID_FIELD_VALUES'
                }
            }), 400

        repo_name = f"{owner}/{repo}"
        repo_url = f"https://github.com/{repo_name}.git"

        # Verify GitHub installation token
        try:
            installation_token = git_integration.get_access_token(
                int(installation_id)
            ).token
        except Exception as e:
            logger.error(f"GitHub authentication failed: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Invalid installation ID or GitHub authentication failed',
                    'code': 'GITHUB_AUTH_ERROR',
                    'details': str(e)
                }
            }), 401

        # Create database entry
        try:
            analysis = AnalysisResult(
                repository_name=repo_name,
                user_id=user_id,
                status='in_progress'
            )
            db.session.add(analysis)
            db.session.commit()
            logger.info(f"Created analysis record {analysis.id} for {repo_name}")
            
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Failed to create analysis record',
                    'code': 'DATABASE_ERROR',
                    'details': str(e)
                }
            }), 500

        # Run the scanner
        try:
            scan_results = await scan_repository_handler(repo_url, installation_token, user_id)
            
            # Update database with results
            if scan_results['success']:
                analysis.status = 'completed'
                analysis.results = scan_results['data']
            else:
                analysis.status = 'failed'
                analysis.error = scan_results['error']['message']

            analysis.completed_at = datetime.now()
            analysis.duration_seconds = (datetime.now() - start_time).total_seconds()
            
            db.session.commit()
            logger.info(f"Updated analysis record {analysis.id} with status {analysis.status}")

            return jsonify({
                'success': scan_results['success'],
                'data': {
                    'message': 'Analysis completed' if scan_results['success'] else 'Analysis failed',
                    'repository': repo_name,
                    'user_id': user_id,
                    'analysis_id': analysis.id,
                    'status': analysis.status,
                    'duration_seconds': analysis.duration_seconds
                }
            })

        except Exception as e:
            analysis.status = 'failed'
            analysis.error = str(e)
            analysis.completed_at = datetime.now()
            analysis.duration_seconds = (datetime.now() - start_time).total_seconds()
            db.session.commit()
            
            logger.error(f"Scan failed for {repo_name}: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Scan failed',
                    'code': 'SCAN_ERROR',
                    'details': str(e)
                }
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': {
                'message': 'Unexpected error processing scan request',
                'code': 'UNEXPECTED_ERROR',
                'details': str(e)
            }
        }), 500

# Initialize the application
try:
    # Validate environment
    if not validate_environment():
        raise RuntimeError("Environment validation failed")

    # Initialize database
    init_database()
    
    # Initialize GitHub integration
    git_integration = init_github()
    
    logger.info("Application initialized successfully")
    
except Exception as e:
    logger.error(f"Application initialization failed: {str(e)}")
    logger.error(traceback.format_exc())
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
    
@app.route('/api/v1/analysis/scan', methods=['POST'])
async def scan_repository():
    """Scan a specific repository with mandatory user ID"""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Content-Type must be application/json',
                    'code': 'INVALID_CONTENT_TYPE'
                }
            }), 400

        payload = request.get_json()
        
        # Required fields including user_id
        required_fields = ['owner', 'repo', 'installation_id', 'user_id']
        missing_fields = [field for field in required_fields if field not in payload]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'Missing required fields: {", ".join(missing_fields)}',
                    'code': 'MISSING_REQUIRED_FIELDS'
                }
            }), 400

        # Validate field values
        owner = str(payload['owner']).strip()
        repo = str(payload['repo']).strip()
        installation_id = str(payload['installation_id']).strip()
        user_id = str(payload['user_id']).strip()

        # Additional validation
        if not all([owner, repo, installation_id, user_id]):
            return jsonify({
                'success': False,
                'error': {
                    'message': 'All required fields must have non-empty values',
                    'code': 'INVALID_FIELD_VALUES',
                    'details': {
                        'owner': bool(owner),
                        'repo': bool(repo),
                        'installation_id': bool(installation_id),
                        'user_id': bool(user_id)
                    }
                }
            }), 400

        repo_name = f"{owner}/{repo}"
        repo_url = f"https://github.com/{repo_name}.git"

        try:
            # Verify the installation token
            installation_token = git_integration.get_access_token(
                int(installation_id)
            ).token
        except Exception as e:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Invalid installation ID or GitHub authentication failed',
                    'code': 'GITHUB_AUTH_ERROR',
                    'details': str(e)
                }
            }), 401

        # Create database entry
        try:
            analysis = AnalysisResult(
                repository_name=repo_name,
                user_id=user_id,
                status='in_progress'
            )
            db.session.add(analysis)
            db.session.commit()
            logger.info(f"Created analysis record for user {user_id}, repository {repo_name}")
        except Exception as e:
            logger.error(f"Database error creating analysis record: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Failed to create analysis record',
                    'code': 'DATABASE_ERROR',
                    'details': str(e)
                }
            }), 500

        # Run the scanner
        try:
            scan_results = await scan_repository_handler(repo_url, installation_token, user_id)
            
            # Update database with results
            if scan_results['success']:
                analysis.status = 'completed'
                analysis.results = scan_results['data']
            else:
                analysis.status = 'failed'
                analysis.error = scan_results['error']['message']

            db.session.commit()
            logger.info(f"Updated analysis record {analysis.id} with status {analysis.status}")

            return jsonify({
                'success': scan_results['success'],
                'data': {
                    'message': 'Analysis completed' if scan_results['success'] else 'Analysis failed',
                    'repository': repo_name,
                    'user_id': user_id,
                    'analysis_id': analysis.id,
                    'status': analysis.status
                }
            })

        except Exception as e:
            analysis.status = 'failed'
            analysis.error = str(e)
            db.session.commit()
            
            logger.error(f"Scan failed for {repo_name}: {str(e)}")
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Scan failed',
                    'code': 'SCAN_ERROR',
                    'details': str(e)
                }
            }), 500

    except Exception as e:
        logger.error(f"Scan endpoint error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': {
                'message': 'Unexpected error processing scan request',
                'code': 'UNEXPECTED_ERROR',
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
                    'status': result.status,
                    'semgrep_version': formatted_results['summary']['semgrep_version']
                },
                'summary': {
                    'files_scanned': formatted_results['summary']['total_files_scanned'],
                    'scan_status': formatted_results['summary']['scan_status'],
                    'total_findings': formatted_results['summary']['total_findings']
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


@app.route('/api/v1/users/top-vulnerabilities', methods=['GET'])
def get_user_vulnerabilities():
    """
    Get top vulnerabilities for a user by user_id with optional repository filter
    Query parameters:
    - user_id: Required - User's unique identifier
    - repository: Optional - Full repository name (e.g., 'Winmart-Store/backend')
    """
    try:
        user_id = request.args.get('user_id')
        repository = request.args.get('repository')

        if not user_id:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Missing user_id parameter',
                    'code': 'MISSING_USER_ID'
                }
            }), 400

        logger.info(f"Fetching vulnerabilities for user_id: {user_id}")
        if repository:
            logger.info(f"Filtering for repository: {repository}")

        # Query analyses for this user_id
        query = db.session.query(AnalysisResult).filter(
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None),
            AnalysisResult.user_id == user_id
        )

        # Add repository filter if provided
        if repository:
            query = query.filter(AnalysisResult.repository_name == repository)

        analyses = query.order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            error_message = 'No analyses found for this user'
            if repository:
                error_message += f' in repository {repository}'
            return jsonify({
                'success': False,
                'error': {
                    'message': error_message,
                    'code': 'NO_ANALYSES_FOUND'
                }
            }), 404

        # Process and format vulnerabilities
        all_vulnerabilities = []
        seen_vulns = set()

        for analysis in analyses:
            try:
                formatted_results = format_semgrep_results(analysis.results)
                repo_name = analysis.repository_name
                
                for finding in formatted_results.get('findings', []):
                    vuln_id = f"{repo_name}_{finding.get('file')}_{finding.get('start', {}).get('line', '0')}"
                    
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
                        'line_range': {
                            'start': finding.get('line_start'),
                            'end': finding.get('line_end')
                        },
                        'message': finding.get('message'),
                        'repository': {
                            'analyzed_at': analysis.timestamp.isoformat(),
                            'full_name': repo_name,
                            'name': repo_name.split('/')[-1]
                        },
                        'security_references': {
                            'cwe': finding.get('cwe', []),
                            'owasp': finding.get('owasp', [])
                        },
                        'severity': finding.get('severity'),
                        'vulnerability_id': finding.get('id')
                    }
                    
                    all_vulnerabilities.append(vulnerability)
                    
            except Exception as e:
                logger.error(f"Error processing analysis for {analysis.repository_name}: {str(e)}")
                continue

        # Sort vulnerabilities
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
        category_counts = {}
        repository_counts = {}

        for vuln in all_vulnerabilities:
            # Count by severity
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by category
            category = vuln['category']
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # Count by repository
            repo = vuln['repository']['full_name']
            repository_counts[repo] = repository_counts.get(repo, 0) + 1

        unique_repos = {vuln['repository']['full_name'] for vuln in all_vulnerabilities}
        
        return jsonify({
            'success': True,
            'data': {
                'metadata': {
                    'user_id': user_id,
                    'repository': repository if repository else None,  # Include repository filter in metadata
                    'total_vulnerabilities': len(all_vulnerabilities),
                    'total_repositories': len(unique_repos),
                    'severity_breakdown': severity_counts,
                    'category_breakdown': category_counts,
                    'repository_breakdown': repository_counts,
                    'last_scan': max(analysis.timestamp for analysis in analyses).isoformat() if analyses else None
                },
                'vulnerabilities': all_vulnerabilities
            }
        })

    except Exception as e:
        logger.error(f"Error processing vulnerabilities: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to process vulnerabilities',
                'details': str(e)
            }
        }), 500
    
  
@app.route('/api/v1/vulnerabilities/file', methods=['GET'])
def get_vulnerable_file():
    try:
        user_id = request.args.get('user_id')
        installation_id = request.args.get('installation_id')
        repository_name = request.args.get('repository_name')
        file_path = request.args.get('file_path')

        if not user_id or not installation_id:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Missing required parameters. Both user_id and installation_id are required.',
                    'code': 'MISSING_PARAMETERS'
                }
            }), 400

        query = db.session.query(AnalysisResult).filter(
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None),
            AnalysisResult.user_id == user_id
        )

        if repository_name:
            query = query.filter(AnalysisResult.repository_name == repository_name)

        analyses = query.order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analyses found for this user',
                    'code': 'NO_ANALYSES_FOUND'
                }
            }), 404

        try:
            installation_token = git_integration.get_access_token(int(installation_id)).token
            gh = Github(installation_token)
        except Exception as token_error:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Failed to authenticate with GitHub',
                    'details': str(token_error)
                }
            }), 401

        vulnerable_files = []

        for analysis in analyses:
            try:
                formatted_results = format_semgrep_results(analysis.results)
                repository = gh.get_repo(analysis.repository_name)
                
                # Get version information
                version_info = {
                    'tags': [],
                    'latest_tag': None,
                    'releases': [],
                    'latest_release': None
                }

                # Get tags
                try:
                    tags = list(repository.get_tags())
                    if tags:
                        version_info['tags'] = [{
                            'name': tag.name,
                            'sha': tag.commit.sha,
                            'date': tag.commit.commit.author.date.isoformat()
                        } for tag in tags[:5]]  # Get latest 5 tags
                        version_info['latest_tag'] = version_info['tags'][0]
                except Exception as tag_error:
                    logger.error(f"Error getting tags: {str(tag_error)}")

                # Get releases
                try:
                    releases = list(repository.get_releases())
                    if releases:
                        version_info['releases'] = [{
                            'name': release.title,
                            'tag_name': release.tag_name,
                            'date': release.created_at.isoformat(),
                            'is_prerelease': release.prerelease
                        } for release in releases[:5]]  # Get latest 5 releases
                        version_info['latest_release'] = version_info['releases'][0]
                except Exception as release_error:
                    logger.error(f"Error getting releases: {str(release_error)}")

                default_branch = repository.default_branch
                latest_commit = repository.get_branch(default_branch).commit
                commit_sha = latest_commit.sha

                for finding in formatted_results.get('findings', []):
                    current_file = finding.get('file')
                    
                    if file_path and current_file != file_path:
                        continue

                    try:
                        file_content = repository.get_contents(current_file, ref=commit_sha)
                        content = file_content.decoded_content.decode('utf-8')
                        lines = content.splitlines()
                        
                        file_info = {
                            'path': current_file,
                            'content': content,
                            'total_lines': len(lines),
                            'repository': {
                                'name': repository.name,
                                'full_name': repository.full_name,
                                'default_branch': default_branch,
                                'version_info': version_info,  # Added version info here
                                'current_commit': {
                                    'sha': commit_sha,
                                    'url': f"https://github.com/{repository.full_name}/commit/{commit_sha}",
                                    'timestamp': latest_commit.commit.author.date.isoformat()
                                }
                            },
                            'vulnerability': {
                                'type': finding.get('id'),
                                'severity': finding.get('severity'),
                                'category': finding.get('category'),
                                'message': finding.get('message'),
                                'line_range': {
                                    'start': finding.get('line_start'),
                                    'end': finding.get('line_end')
                                },
                                'code_snippet': finding.get('code_snippet'),
                                'fix_recommendations': finding.get('fix_recommendations', {}),
                                'security_references': {
                                    'cwe': finding.get('cwe', []),
                                    'owasp': finding.get('owasp', [])
                                }
                            }
                        }
                        
                        vulnerable_files.append(file_info)
                        
                    except Exception as file_error:
                        logger.error(f"Error processing file {current_file}: {str(file_error)}")
                        continue
                    
            except Exception as analysis_error:
                logger.error(f"Error processing analysis {analysis.id}: {str(analysis_error)}")
                continue

        return jsonify({
            'success': True,
            'data': {
                'metadata': {
                    'user_id': user_id,
                    'total_files': len(vulnerable_files),
                    'scan_timestamp': analyses[0].timestamp.isoformat() if analyses else None
                },
                'files': vulnerable_files
            }
        })

    except Exception as e:
        logger.error(f"Error getting vulnerable files: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to get vulnerable files',
                'details': str(e)
            }
        }), 500

@app.route('/api/v1/analysis/verify/<user_id>', methods=['GET'])
def verify_user_analyses(user_id):
    """Verify analyses for a specific user_id"""
    try:
        # Query all analyses for this user_id
        analyses = AnalysisResult.query.filter_by(user_id=user_id).all()
        
        if not analyses:
            return jsonify({
                'success': True,
                'data': {
                    'message': 'No analyses found for this user ID',
                    'user_id': user_id,
                    'count': 0
                }
            })
        
        # Format the results
        results = []
        for analysis in analyses:
            results.append({
                'id': analysis.id,
                'repository_name': analysis.repository_name,
                'user_id': analysis.user_id,
                'timestamp': analysis.timestamp.isoformat(),
                'status': analysis.status
            })
        
        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'count': len(results),
                'analyses': results
            }
        })
        
    except Exception as e:
        logger.error(f"Error verifying analyses: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to verify analyses',
                'details': str(e)
            }
        }), 500

@app.route('/api/v1/analysis/latest', methods=['GET'])
def get_latest_analyses():
    """Get the most recent analyses with user IDs"""
    try:
        # Get the 10 most recent analyses
        analyses = AnalysisResult.query.order_by(
            AnalysisResult.timestamp.desc()
        ).limit(10).all()
        
        results = []
        for analysis in analyses:
            results.append({
                'id': analysis.id,
                'repository_name': analysis.repository_name,
                'user_id': analysis.user_id,
                'timestamp': analysis.timestamp.isoformat(),
                'status': analysis.status
            })
        
        return jsonify({
            'success': True,
            'data': {
                'count': len(results),
                'analyses': results
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting latest analyses: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to get latest analyses',
                'details': str(e)
            }
        }), 500
@app.route('/api/v1/analysis/test-access', methods=['POST'])
def test_repository_access():
    """Test repository access before attempting analysis"""
    try:
        payload = request.json
        if not payload or 'owner' not in payload or 'repo' not in payload or 'installation_id' not in payload:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Missing required fields',
                    'code': 'INVALID_PAYLOAD'
                }
            }), 400

        owner = payload['owner']
        repo = payload['repo']
        installation_id = payload['installation_id']
        
        try:
            # Get installation token
            installation_token = git_integration.get_access_token(installation_id).token
            
            # Test repository access
            test_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {
                'Authorization': f'Bearer {installation_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            import requests
            response = requests.get(test_url, headers=headers)
            
            return jsonify({
                'success': True,
                'data': {
                    'status_code': response.status_code,
                    'repository': f"{owner}/{repo}",
                    'accessible': response.status_code == 200,
                    'details': response.json() if response.status_code == 200 else response.text
                }
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'ACCESS_ERROR'
                }
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'message': str(e),
                'code': 'TEST_FAILED'
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

