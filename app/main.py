"""Main FastAPI application."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time

from app.api import api_router
from app.core.config import get_settings
from app.core.logging import setup_logging, get_logger
from app.db.session import init_db, close_db
from app.messaging.connection import get_rabbitmq_connection, close_rabbitmq_connection
from app.messaging.consumer import LogConsumer
from app.processing.ingestion import LogIngestionEngine
from app.monitoring.metrics import get_metrics_collector, metrics_endpoint

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Get settings
settings = get_settings()

# Background task for consuming messages
consumer_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("application_starting", app_name=settings.app_name, version=settings.app_version)

    # Initialize database
    init_db()
    logger.info("database_initialized")

    # Initialize RabbitMQ connection
    try:
        rabbitmq = await get_rabbitmq_connection()
        logger.info("rabbitmq_connected")

        # Start consumer in background
        global consumer_task
        if settings.enable_real_time_processing:
            consumer_task = asyncio.create_task(start_consumer(rabbitmq))
            logger.info("log_consumer_started")

    except Exception as e:
        logger.error("rabbitmq_initialization_failed", error=str(e))

    yield

    # Shutdown
    logger.info("application_shutting_down")

    # Stop consumer
    if consumer_task:
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass

    # Close connections
    await close_rabbitmq_connection()
    await close_db()

    logger.info("application_shutdown_complete")


async def start_consumer(rabbitmq):
    """Start log consumer."""
    from app.db.session import async_session_factory

    consumer = LogConsumer(rabbitmq)

    async def message_handler(message: dict) -> None:
        """Handle incoming log message."""
        metrics = get_metrics_collector()
        metrics.record_message_consumed()

        async with async_session_factory() as session:
            try:
                engine = LogIngestionEngine(session)
                log_entry = await engine.process_message(message)

                metrics.record_log_ingested(
                    log_entry.service_name, log_entry.log_level
                )
                metrics.record_log_processed()

            except Exception as e:
                logger.error("message_handler_error", error=str(e), exc_info=True)
                metrics.record_log_failed()

    await consumer.start_consuming(message_handler)


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Log Analysis System Microservice for Developer Foundry 2.0 (AIMA)",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    lifespan=lifespan,
)

# CORS middleware
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=settings.cors_methods,
        allow_headers=settings.cors_headers,
    )


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests and collect metrics."""
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time

    logger.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration=f"{duration:.3f}s",
    )

    # Record metrics
    metrics = get_metrics_collector()
    metrics.record_api_request(request.method, request.url.path, response.status_code)

    return response


# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True,
    )

    return JSONResponse(
        status_code=500,
        content={
            "status_code": 500,
            "message": "Internal server error",
            "errors": [str(exc)] if settings.debug else ["An unexpected error occurred"],
        },
    )


# Include routers
app.include_router(api_router)

# Metrics endpoint
app.get(settings.metrics_path)(metrics_endpoint)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "environment": settings.environment,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        reload=settings.is_development,
    )
