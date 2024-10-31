import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Worker processes
workers = 1  # For Render's free tier
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 2

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Process naming
proc_name = 'gunicorn_semgrep'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190