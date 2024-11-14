from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc
from models import db, AnalysisResult
from collections import defaultdict
import os
import logging
from pathlib import Path
import tempfile
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

api = Blueprint('api', __name__, url_prefix='/api/v1')

@api.route('/repos/<owner>/<repo>/results', methods=['GET'])
def get_repo_results(owner, repo):
    repository = f"{owner}/{repo}"
    
    # Get latest analysis result
    result = AnalysisResult.query.filter_by(
        repository_name=repository
    ).order_by(
        desc(AnalysisResult.timestamp)
    ).first()

    if not result:
        return jsonify({
            'success': False,
            'error': 'No analysis results found'
        }), 404

    # Get filters from query params
    severity = request.args.get('severity', '').upper()
    category = request.args.get('category', '')
    page = int(request.args.get('page', 1))
    per_page = min(100, int(request.args.get('limit', 10)))

    findings = result.results.get('findings', [])

    # Apply filters
    if severity:
        findings = [f for f in findings if f.get('severity') == severity]
    if category:
        findings = [f for f in findings if f.get('category') == category]

    # Paginate
    total_findings = len(findings)
    findings = findings[(page-1)*per_page:page*per_page]

    return jsonify({
        'success': True,
        'data': {
            'repository': repository,
            'timestamp': result.timestamp.isoformat(),
            'findings': findings,
            'summary': result.results.get('summary', {}),
            'metadata': result.results.get('metadata', {}),
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_findings,
                'pages': (total_findings + per_page - 1) // per_page
            }
        }
    })

@api.route('/users/<user_id>/top-vulnerabilities', methods=['GET'])
def get_top_vulnerabilities(user_id):
    try:
        analyses = AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None)
        ).order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {'message': 'No analyses found'}
            }), 404

        # Track statistics
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        repo_counts = defaultdict(int)
        unique_vulns = {}

        for analysis in analyses:
            findings = analysis.results.get('findings', [])
            repo_name = analysis.repository_name
            
            for finding in findings:
                vuln_id = finding.get('id')
                if vuln_id not in unique_vulns:
                    unique_vulns[vuln_id] = {
                        'vulnerability_id': vuln_id,
                        'severity': finding.get('severity'),
                        'category': finding.get('category'),
                        'message': finding.get('message'),
                        'code_snippet': finding.get('code_snippet'),
                        'file': finding.get('file'),
                        'line_range': {
                            'start': finding.get('line_start'),
                            'end': finding.get('line_end')
                        },
                        'security_references': {
                            'cwe': finding.get('cwe', []),
                            'owasp': finding.get('owasp', [])
                        },
                        'fix_recommendations': {
                            'description': finding.get('fix_recommendations', ''),
                            'references': finding.get('references', [])
                        },
                        'repository': {
                            'name': repo_name.split('/')[-1],
                            'full_name': repo_name,
                            'analyzed_at': analysis.timestamp.isoformat()
                        }
                    }
                    
                    severity_counts[finding.get('severity')] += 1
                    category_counts[finding.get('category')] += 1
                    repo_counts[repo_name] += 1

        return jsonify({
            'success': True,
            'data': {
                'metadata': {
                    'user_id': user_id,
                    'total_vulnerabilities': len(unique_vulns),
                    'total_repositories': len(repo_counts),
                    'severity_breakdown': severity_counts,
                    'category_breakdown': category_counts,
                    'repository_breakdown': repo_counts,
                    'last_scan': analyses[0].timestamp.isoformat() if analyses else None,
                    'repository': None  # For compatibility with existing format
                },
                'vulnerabilities': list(unique_vulns.values())
            }
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@api.route('/files/<owner>/<repo>/<user_id>/<path:filename>', methods=['GET'])
def get_file_content(owner: str, repo: str, user_id: str, filename: str):
    try:
        repository = f"{owner}/{repo}"
        
        # Find the most recent repo directory
        base_dir = Path(tempfile.gettempdir())
        repo_dirs = list(base_dir.glob("scanner_*/repo_*"))
        if not repo_dirs:
            return jsonify({
                'success': False,
                'error': {'message': 'Repository not found'}
            }), 404
            
        repo_dir = sorted(repo_dirs, key=lambda x: x.stat().st_mtime)[-1]
        file_path = repo_dir / filename
        
        # Security check
        if not str(file_path).startswith(str(repo_dir)):
            return jsonify({
                'success': False,
                'error': {'message': 'Invalid file path'}
            }), 400
            
        if not file_path.exists():
            return jsonify({
                'success': False,
                'error': {'message': 'File not found'}
            }), 404
            
        with open(file_path, 'r') as f:
            file_content = f.read()
            
        # Get version from analysis results
        result = AnalysisResult.query.filter_by(
            user_id=user_id,
            repository_name=repository
        ).order_by(desc(AnalysisResult.timestamp)).first()
        
        version = "1.0"
        if result and result.results.get('metadata', {}).get('version'):
            version = result.results['metadata']['version']
            
        return jsonify({
            'success': True,
            'data': {
                'file': file_content,
                'user_id': user_id,
                'version': version,
                'reponame': repository,
                'filename': filename
            }
        })

    except Exception as e:
        logger.error(f"Error reading file content: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500