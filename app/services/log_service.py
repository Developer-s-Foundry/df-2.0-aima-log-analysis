"""Service for log entry operations."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.log_entry import LogEntry
from app.schemas.log_schemas import LogEntryCreate

logger = get_logger(__name__)


class LogService:
    """Handles log entry business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize service with database session."""
        self.db = db

    async def create_log_entry(self, log_data: LogEntryCreate) -> LogEntry:
        """
        Create a new log entry.

        Args:
            log_data: Log entry data

        Returns:
            Created log entry
        """
        log_entry = LogEntry(
            service_name=log_data.service_name,
            log_level=log_data.log_level,
            message=log_data.message,
            timestamp=log_data.timestamp,
            raw_data=log_data.raw_data,
            processed=False,
        )

        self.db.add(log_entry)
        await self.db.commit()
        await self.db.refresh(log_entry)

        logger.info(
            "log_entry_created",
            log_id=str(log_entry.id),
            service=log_data.service_name,
            level=log_data.log_level,
        )

        return log_entry

    async def get_log_by_id(self, log_id: UUID) -> Optional[LogEntry]:
        """Get log entry by ID."""
        result = await self.db.execute(select(LogEntry).where(LogEntry.id == log_id))
        return result.scalar_one_or_none()

    async def get_logs(
        self,
        service_name: Optional[str] = None,
        log_level: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        processed: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[List[LogEntry], int]:
        """
        Get filtered log entries with pagination.

        Returns:
            Tuple of (log entries list, total count)
        """
        # Build query with filters
        conditions = []

        if service_name:
            conditions.append(LogEntry.service_name == service_name)
        if log_level:
            conditions.append(LogEntry.log_level == log_level.upper())
        if start_date:
            conditions.append(LogEntry.timestamp >= start_date)
        if end_date:
            conditions.append(LogEntry.timestamp <= end_date)
        if processed is not None:
            conditions.append(LogEntry.processed == processed)

        # Get total count
        count_query = select(func.count()).select_from(LogEntry)
        if conditions:
            count_query = count_query.where(and_(*conditions))

        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Get paginated results
        query = select(LogEntry).order_by(LogEntry.timestamp.desc())

        if conditions:
            query = query.where(and_(*conditions))

        query = query.limit(limit).offset(offset)

        result = await self.db.execute(query)
        logs = list(result.scalars().all())

        return logs, total

    async def update_log_analysis(
        self,
        log_id: UUID,
        analysis_summary: Optional[str] = None,
        error_score: Optional[float] = None,
        anomaly_score: Optional[float] = None,
        pattern_id: Optional[str] = None,
    ) -> Optional[LogEntry]:
        """Update log entry with analysis results."""
        log_entry = await self.get_log_by_id(log_id)

        if not log_entry:
            return None

        if analysis_summary:
            log_entry.analysis_summary = analysis_summary
        if error_score is not None:
            log_entry.error_score = error_score
        if anomaly_score is not None:
            log_entry.anomaly_score = anomaly_score
        if pattern_id:
            log_entry.pattern_id = pattern_id

        log_entry.processed = True

        await self.db.commit()
        await self.db.refresh(log_entry)

        return log_entry

    async def get_unprocessed_logs(self, limit: int = 100) -> List[LogEntry]:
        """Get unprocessed log entries for batch processing."""
        query = (
            select(LogEntry)
            .where(LogEntry.processed.is_(False))
            .order_by(LogEntry.timestamp.asc())
            .limit(limit)
        )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_error_count_by_service(
        self, service_name: str, start_date: datetime, end_date: datetime
    ) -> int:
        """Get count of error-level logs for a service in a time period."""
        query = (
            select(func.count())
            .select_from(LogEntry)
            .where(
                and_(
                    LogEntry.service_name == service_name,
                    LogEntry.log_level == "ERROR",
                    LogEntry.timestamp >= start_date,
                    LogEntry.timestamp <= end_date,
                )
            )
        )

        result = await self.db.execute(query)
        return result.scalar() or 0
