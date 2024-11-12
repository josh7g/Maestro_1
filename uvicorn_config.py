# uvicorn_config.py
import os
import uvicorn
import multiprocessing

class UvicornConfig:
    # Server configs
    host = "0.0.0.0"
    port = int(os.getenv('PORT', '10000'))
    
    # Worker configs
    workers = 1  # Keeping it same as your gunicorn config
    worker_class = "uvicorn.workers.UvicornWorker"
    
    # Connection configs
    timeout_keep_alive = 2  # Similar to your keepalive
    timeout = 300  # Same 5-minute timeout
    
    # Logging configs
    log_level = "info"
    access_log = True
    use_colors = False
    
    # Resource limits
    limit_max_requests = 0  # No limit, same as default gunicorn
    limit_concurrency = 1000  # Similar to your worker_connections
    
    # SSL configs (if needed)
    ssl_keyfile = None
    ssl_certfile = None

config = {
    "host": UvicornConfig.host,
    "port": UvicornConfig.port,
    "workers": UvicornConfig.workers,
    "timeout": UvicornConfig.timeout,
    "timeout_keep_alive": UvicornConfig.timeout_keep_alive,
    "log_level": UvicornConfig.log_level,
    "access_log": UvicornConfig.access_log,
    "limit_concurrency": UvicornConfig.limit_concurrency,
}

# Update your Render start command to use this config:
# uvicorn app:asgi_app --config uvicorn_config.py