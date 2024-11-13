from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.hybrid import hybrid_property
from typing import Dict, Any

db = SQLAlchemy()

class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'

    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False, index=True)
    user_id = db.Column(db.String(255), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))
    results = db.Column(JSON)  # Using PostgreSQL JSON type
    error = db.Column(db.Text)
    
    # Add some useful hybrid properties
    @hybrid_property
    def is_completed(self) -> bool:
        """Check if analysis is completed"""
        return self.status == 'completed'
    
    @hybrid_property
    def has_errors(self) -> bool:
        """Check if analysis has errors"""
        return bool(self.error)
    
    @hybrid_property
    def findings_count(self) -> int:
        """Get total number of findings"""
        if self.results and isinstance(self.results, dict):
            return len(self.results.get('results', []))
        return 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary with type hints"""
        return {
            'id': self.id,
            'repository_name': self.repository_name,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
            'error': self.error,
            'is_completed': self.is_completed,
            'has_errors': self.has_errors,
            'findings_count': self.findings_count
        }
    
    @classmethod
    def create_analysis(cls, repository_name: str, user_id: str) -> 'AnalysisResult':
        """Factory method to create new analysis"""
        analysis = cls(
            repository_name=repository_name,
            user_id=user_id,
            status='in_progress'
        )
        db.session.add(analysis)
        db.session.commit()
        return analysis
    
    def update_status(self, status: str, error: str = None) -> None:
        """Update analysis status"""
        self.status = status
        if error:
            self.error = error
        db.session.commit()
    
    def update_results(self, results: Dict[str, Any]) -> None:
        """Update analysis results"""
        self.results = results
        self.status = 'completed'
        db.session.commit()

    def __repr__(self) -> str:
        return f'<AnalysisResult {self.repository_name} ({self.status})>'