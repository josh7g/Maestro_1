from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc
from models import db, AnalysisResult
from collections import defaultdict

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
        # Only get completed analyses with non-null results
        analyses = AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None)
        ).order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No valid analyses found',
                    'code': 'NO_ANALYSES_FOUND'
                }
            }), 404

        # Process and aggregate vulnerabilities
        vulnerability_stats = defaultdict(lambda: {
            'count': 0,
            'severity': '',
            'category': '',
            'cwe': set(),
            'owasp': set(),
            'affected_repos': set()
        })

        for analysis in analyses:
            try:
                findings = analysis.results.get('findings', [])
                if not findings:  # Skip if no findings
                    continue
                    
                for finding in findings:
                    vuln_id = finding.get('id')
                    if vuln_id:
                        stats = vulnerability_stats[vuln_id]
                        stats['count'] += 1
                        stats['severity'] = finding.get('severity', '')
                        stats['category'] = finding.get('category', '')
                        stats['cwe'].update(finding.get('cwe', []))
                        stats['owasp'].update(finding.get('owasp', []))
                        stats['affected_repos'].add(analysis.repository_name)
            except Exception as e:
                logger.error(f"Error processing analysis {analysis.id}: {str(e)}")
                continue

        # Convert to list and sort
        vulnerabilities = [
            {
                'id': vuln_id,
                'count': stats['count'],
                'severity': stats['severity'],
                'category': stats['category'],
                'cwe': list(stats['cwe']),
                'owasp': list(stats['owasp']),
                'affected_repos': list(stats['affected_repos'])
            }
            for vuln_id, stats in vulnerability_stats.items()
        ]

        vulnerabilities.sort(key=lambda x: x['count'], reverse=True)

        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }
        })

    except Exception as e:
        logger.error(f"Error processing vulnerabilities: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to process vulnerabilities',
                'details': str(e)
            }
        }), 500