"""Log management API endpoints."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.db.session import get_db
from app.schemas.log_schemas import (
    LogEntryResponse,
    LogListResponse,
    APIResponse,
)
from app.services.log_service import LogService

router = APIRouter()


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
    """Get a specific log entry by ID."""
    log_service = LogService(db)

    log = await log_service.get_log_by_id(log_id)

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Log entry not found"
        )

    return LogEntryResponse.model_validate(log)


@router.get("/logs/summary", response_model=APIResponse)
async def get_logs_summary(
    service_name: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> APIResponse:
    """
    Fetch aggregated insights and summary by service.

    Returns analysis metrics and common errors.
    """
    log_service = LogService(db)

    logs, _ = await log_service.get_logs(
        service_name=service_name,
        start_date=start_date,
        end_date=end_date,
        limit=10000,  # Large limit for analysis
    )

    # Calculate summary
    from app.processing.analyzer import LogAnalyzer

    analyzer = LogAnalyzer()
    analysis = analyzer.analyze_logs(logs)

    return APIResponse(
        data=analysis,
        status_code=200,
        message="Log summary retrieved successfully",
    )
