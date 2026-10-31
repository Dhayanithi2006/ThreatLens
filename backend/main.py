"""
ThreatLens - Enterprise Email Threat Investigation Platform
FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router as api_router
from backend.api.graphops_routes import router as graphops_router
from backend.api.governance_routes import router as governance_router
from backend.api.collector_routes import router as collector_router
from backend.graphops.client import close_graphops_client
from backend.graphops.kafka_worker import get_kafka_worker
from backend.core.config import STATIC_DIR, CORS_ORIGINS

logger = logging.getLogger("threatlens.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Application startup: start Kafka consumer background worker
    worker = None
    try:
        worker = get_kafka_worker()
        worker.start_background()
        if worker.mock_mode:
            logger.warning(
                "Kafka consumer worker started in mock mode (broker unreachable at %s).",
                worker.bootstrap_servers,
            )
        else:
            logger.info(
                "Kafka consumer worker started in live mode on broker %s (group: %s).",
                worker.bootstrap_servers,
                worker.group_id,
            )
    except Exception as e:
        logger.error("Failed to initialize or start Kafka consumer worker: %s", e, exc_info=True)

    yield

    # Application shutdown: safely stop Kafka worker and close graph database connection pool
    try:
        if worker is not None:
            worker.stop()
            logger.info("Kafka consumer worker stopped successfully.")
    except Exception as e:
        logger.error("Error stopping Kafka consumer worker during shutdown: %s", e, exc_info=True)
    finally:
        try:
            close_graphops_client()
            logger.info("GraphOps database connection pool closed successfully.")
        except Exception as e:
            logger.error("Error closing GraphOps database client during shutdown: %s", e, exc_info=True)


app = FastAPI(
    title="ThreatLens API",
    description="Enterprise Email Threat Investigation, Forensics, Threat Intelligence & Campaign Correlation Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# Explicit environment-appropriate CORS policy (disallows wildcard with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include API router (existing routes)
app.include_router(api_router, prefix="/api/v1")

# Include GraphOps router (additive security graph routes)
app.include_router(graphops_router, prefix="/api/v1/graphops", tags=["GraphOps"])

# Include Governance & Controls router
app.include_router(governance_router)

# Include Remote Windows Collector router
app.include_router(collector_router, prefix="/api/v1/collector", tags=["Collector"])

# Mount Static Frontend
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")

@app.get("/")
def root():
    return {
        "message": "Welcome to ThreatLens API",
        "docs_url": "/docs",
        "frontend_url": "/static/index.html"
    }
