import os

bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
workers = 1
worker_class = 'sync'
worker_connections = 1000
timeout = 300  # Increased to 5 minutes
keepalive = 2
accesslog = '-'
errorlog = '-'
loglevel = 'info'