timeout = 600

# Workers configuration
workers = 2
worker_class = 'gthread'
threads = 4

# Keep the worker alive longer
graceful_timeout = 600
keep_alive = 65

# Bind to all interfaces
bind = "0.0.0.0:10000"

# Logger configurations
accesslog = "-"
errorlog = "-"
loglevel = "info"