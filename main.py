import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from config import settings
from database.database import init_db
from services.ml_engine import get_ml_engine
from services.signature_engine import SignatureEngine
from services.network_monitor import NetworkMonitor
from services.event_broker import EventBroker
from database.database import SessionLocal
from routers import auth, url, alerts, admin
from routers import network as network_router
from routers import file as file_router
from utils import make_response

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global instances
ml_engine = None
signature_engine = None
network_monitor = None
event_broker = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager for startup and shutdown.
    """
    global ml_engine, signature_engine, network_monitor, event_broker
    
    # ==================== STARTUP ====================
    logger.info("Starting ShieldGuard API...")
    
    try:
        # Initialize database
        logger.info("Initializing database...")
        init_db()
        
        # Load ML models
        logger.info("Loading ML models...")
        ml_engine = get_ml_engine()
        status = ml_engine.get_status()
        logger.info(f"ML Engine status: {status}")
        
        # Initialize signature engine
        logger.info(f"Initializing signature engine at {settings.SIGNATURE_DB_PATH}...")
        signature_engine = SignatureEngine(settings.SIGNATURE_DB_PATH)
        sig_stats = signature_engine.get_stats()
        logger.info(f"Signature database: {sig_stats['total']} signatures loaded")
        
        # Initialize event broker
        event_broker = EventBroker()
        logger.info("Event broker initialized")
        
        # Initialize network monitor
        network_monitor = NetworkMonitor()
        
        # Store in app state for access in routes
        app.state.ml_engine = ml_engine
        app.state.signature_engine = signature_engine
        app.state.event_broker = event_broker
        app.state.network_monitor = network_monitor
        
        # Start network monitor if enabled
        if settings.ENABLE_PROCESS_MONITOR:
            logger.info("Starting network monitor...")
            await network_monitor.start(SessionLocal, event_broker)
        
        logger.info("ShieldGuard API started successfully")
        
    except Exception as e:
        logger.error(f"Startup error: {e}", exc_info=True)
        raise
    
    yield
    
    # ==================== SHUTDOWN ====================
    logger.info("Shutting down ShieldGuard API...")
    
    try:
        if network_monitor and network_monitor.monitoring:
            await network_monitor.stop()
        logger.info("Shutdown completed successfully")
    except Exception as e:
        logger.error(f"Shutdown error: {e}", exc_info=True)


# Create FastAPI app
app = FastAPI(
    title="ShieldGuard API",
    version="1.0.0",
    description="Predictive antivirus system backend",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "app://.",
        "file://"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(url.router)
app.include_router(network_router.router)
app.include_router(file_router.router)
app.include_router(alerts.router)
app.include_router(admin.router)


# Health check endpoint (no auth required)
@app.get("/health")
async def health_check(request: Request):
    """
    Health check endpoint for monitoring API availability and ML model status.
    """
    ml_engine_status = request.app.state.ml_engine.get_status()
    
    response = {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "models": ml_engine_status
    }
    
    return make_response(data=response)


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    response = make_response(
        data=None,
        error="Internal server error"
    )
    
    return JSONResponse(
        status_code=500,
        content=response.model_dump()
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.API_PORT,
        log_level="info"
    )
