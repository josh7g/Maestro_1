from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
import logging
import asyncio
from scanner import SecurityScanner, scan_repository_handler  # import scanning logic
from typing import Optional
from sqlalchemy.orm import Session

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for optimized startup"""
    try:
        logger.info("Starting application initialization")
        yield
    finally:
        logger.info("Shutting down application")

# Create FastAPI app with lifespan
app = FastAPI(lifespan=lifespan)

@app.on_event("startup")
async def startup_event():
    """Handle heavy initialization in background"""
    async def background_init():
        try:
            # Your initialization code here
            pass
        except Exception as e:
            logger.error(f"Background initialization error: {e}")

    asyncio.create_task(background_init())

# Move all endpoints here from scanner.py
@app.post("/api/v1/scan")
async def scan_repository(repo_url: str, installation_token: str, user_id: str):
    """Endpoint to scan a repository"""
    try:
        result = await scan_repository_handler(
            repo_url=repo_url,
            installation_token=installation_token,
            user_id=user_id
        )
        
        if not result['success']:
            raise HTTPException(
                status_code=400,
                detail=result.get('error', {'message': 'Scan failed'})
            )
            
        return result
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal server error", "error": str(e)}
        )

@app.get("/api/v1/analysis/{owner}/{repo}/result")
async def get_analysis_findings(owner: str, repo: str):
    pass

