"""Log management API endpoints - Monitoring and Control Only.

This API provides monitoring and operational control endpoints.
Log analysis happens automatically via RabbitMQ message consumption.

Architecture:
- Logs come from RabbitMQ (Log Management Service - Team B)
- Analysis happens automatically in IngestionService
- Results sent to Alert System (Team A) and Recommendation System (Team E)
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth_external import get_current_user
from app.core.logging import get_logger
from app.db.session import get_db
from app.schemas.log_schemas import (
    LogEntryResponse,
    LogListResponse,
    APIResponse,
)
from app.services.log_service import LogService
from app.core.config import get_settings

router = APIRouter()
logger = get_logger(__name__)


@router.get("/logs", response_model=LogListResponse)
async def get_logs(
    service_name: Optional[str] = Query(None),
    log_level: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> LogListResponse:
    """
    Retrieve processed logs with filtering and pagination.

    **Purpose**: Monitoring and debugging only.
    **Note**: Log analysis happens automatically via RabbitMQ.

    Requires JWT authentication.
    """
    log_service = LogService(db)

    offset = (page - 1) * page_size

    logs, total = await log_service.get_logs(
        service_name=service_name,
        log_level=log_level,
        start_date=start_date,
        end_date=end_date,
        limit=page_size,
        offset=offset,
    )

    total_pages = (total + page_size - 1) // page_size

    return LogListResponse(
        data=[LogEntryResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        pages=total_pages,
    )


@router.get("/logs/{log_id}", response_model=LogEntryResponse)
async def get_log(
    log_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> LogEntryResponse:
    """
    Retrieve a specific log entry by ID.

    **Purpose**: Debugging and detailed investigation.

    Requires JWT authentication.
    """
    log_service = LogService(db)
    log = await log_service.get_log_by_id(log_id)

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found"
        )

    return LogEntryResponse.model_validate(log)


@router.get("/ai/status", response_model=APIResponse)
async def get_ai_status(
    current_user: dict = Depends(get_current_user),
) -> APIResponse:
    """
    Get current AI processing status and configuration.

    Returns:
    - AI enabled status (if disabled, system uses basic analysis)
    - Configuration details
    - Processing mode

    Note: When AI fails, system automatically falls back to basic analysis.
    """
    settings = get_settings()
    ai_enabled = getattr(settings, 'ai_analysis_enabled', True)
    
    return APIResponse(
        data={
            "ai_enabled": ai_enabled,
            "processing_mode": (
                "AI with automatic fallback" if ai_enabled else "Basic analysis only"
            ),
            "ai_timeout_seconds": getattr(settings, 'ai_timeout_seconds', 10),
            "ai_retry_attempts": getattr(settings, 'ai_retry_attempts', 2),
            "ai_confidence_threshold": getattr(settings, 'ai_confidence_threshold', 0.5),
            "real_time_processing": getattr(settings, 'enable_real_time_processing', True),
            "note": "When AI fails, system automatically uses basic analysis as fallback",
        },
        status_code=200,
        message="AI status retrieved successfully",
    )


@router.post("/ai/toggle", response_model=APIResponse)
async def toggle_ai_processing(
    enable_ai: bool = Query(..., description="Enable or disable AI processing"),
    current_user: dict = Depends(get_current_user),
) -> APIResponse:
    """
    Toggle AI processing on/off.

    This endpoint allows you to:
    - Enable AI processing: Uses AI analysis with automatic fallback to basic analysis if AI fails
    - Disable AI processing: Uses only basic analysis

    Changes are applied immediately to new log processing.

    Note: Fallback to basic analysis is ALWAYS enabled when AI is on.
    When AI fails, the system automatically uses basic analysis to ensure continuous operation.
    """
    settings = get_settings()
    
    settings.ai_analysis_enabled = enable_ai
    
    logger.info(
        "ai_processing_toggled",
        ai_enabled=enable_ai,
        processing_mode=(
            "AI with automatic fallback" if enable_ai else "Basic analysis only"
        ),
        user=current_user.get("sub", "unknown"),
    )
    
    return APIResponse(
        data={
            "ai_enabled": enable_ai,
            "processing_mode": (
                "AI with automatic fallback" if enable_ai else "Basic analysis only"
            ),
            "message": f"AI processing {'enabled' if enable_ai else 'disabled'} successfully",
            "note": (
                "Fallback to basic analysis is automatic when AI fails. "
                "Changes apply to new log processing."
            ),
        },
        status_code=200,
        message=f"AI processing {'enabled' if enable_ai else 'disabled'}",
    )


@router.get("/stats", response_model=APIResponse)
async def get_processing_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> APIResponse:
    """
    Get processing statistics and system metrics.

    Returns:
    - Total logs processed
    - Logs by level (last 24 hours)
    - Error rates
    - Processing status
    """
    log_service = LogService(db)
    
    # Get total logs
    _, total_logs = await log_service.get_logs(limit=1)
    
    # Get logs by level (last 24 hours)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(hours=24)

    _, error_count = await log_service.get_logs(
        log_level="ERROR",
        start_date=start_date,
        end_date=end_date,
        limit=1
    )

    _, warning_count = await log_service.get_logs(
        log_level="WARNING",
        start_date=start_date,
        end_date=end_date,
        limit=1
    )

    _, info_count = await log_service.get_logs(
        log_level="INFO",
        start_date=start_date,
        end_date=end_date,
        limit=1
    )

    total_24h = error_count + warning_count + info_count
    error_rate = (error_count / total_24h * 100) if total_24h > 0 else 0

    return APIResponse(
        data={
            "total_logs": total_logs,
            "last_24_hours": {
                "total": total_24h,
                "error_count": error_count,
                "warning_count": warning_count,
                "info_count": info_count,
                "error_rate": round(error_rate, 2),
            },
            "processing_status": {
                "ai_enabled": getattr(get_settings(), 'ai_analysis_enabled', True),
                "real_time_processing": getattr(
                    get_settings(), 'enable_real_time_processing', True
                ),
            },
        },
        status_code=200,
        message="Processing statistics retrieved successfully",
    )
