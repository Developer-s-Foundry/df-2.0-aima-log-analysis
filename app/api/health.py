"""Health check endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.db.session import get_db
from app.core.config import get_settings

router = APIRouter()


@router.get("/")
async def health_check() -> dict:
    """Basic health check endpoint."""
    settings = get_settings()
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)) -> dict:
    """Readiness check including database connectivity."""
    try:
        # Check database connection
        await db.execute(text("SELECT 1"))

        return {"status": "ready", "database": "connected"}
    except Exception as e:
        return {"status": "not_ready", "database": "disconnected", "error": str(e)}
