# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()

# First, let's modify the AnalysisResult model to include user_id
class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'

    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String(255), nullable=True)  # Added user_id field
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))
    results = db.Column(db.JSON)
    error = db.Column(db.Text)

    
    def to_dict(self):
        return {
            'id': self.id,
            'repository_name': self.repository_name,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
            'error': self.error
        }
    
    