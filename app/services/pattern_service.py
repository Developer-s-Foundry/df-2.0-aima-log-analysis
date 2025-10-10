"""Service for pattern operations."""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pattern import Pattern
from app.core.logging import get_logger

logger = get_logger(__name__)


class PatternService:
    """Handles pattern business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize service with database session."""
        self.db = db

    async def create_or_update_pattern(
        self,
        pattern_id: str,
        pattern_type: str,
        template: str,
        description: str,
        service_name: Optional[str] = None,
        occurrence_count: int = 1,
        frequency_score: float = 0.0,
        severity_score: float = 0.0,
        cluster_id: Optional[int] = None,
        example_message: Optional[str] = None,
        is_anomaly: bool = False,
    ) -> Pattern:
        """Create new pattern or update existing one."""
        # Check if pattern exists
        query = select(Pattern).where(Pattern.pattern_id == pattern_id)
        result = await self.db.execute(query)
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing pattern
            existing.occurrence_count += occurrence_count
            existing.frequency_score = frequency_score
            existing.severity_score = severity_score
            pattern = existing
        else:
            # Create new pattern
            pattern = Pattern(
                pattern_id=pattern_id,
                pattern_type=pattern_type,
                template=template,
                description=description,
                service_name=service_name,
                occurrence_count=occurrence_count,
                frequency_score=frequency_score,
                severity_score=severity_score,
                cluster_id=cluster_id,
                example_message=example_message,
                is_anomaly=is_anomaly,
                is_active=True,
            )
            self.db.add(pattern)

        await self.db.commit()
        await self.db.refresh(pattern)

        logger.info(
            "pattern_saved",
            pattern_id=pattern_id,
            occurrences=pattern.occurrence_count,
        )

        return pattern

    async def get_active_patterns(
        self, service_name: Optional[str] = None, limit: int = 100
    ) -> List[Pattern]:
        """Get active patterns, optionally filtered by service."""
        query = select(Pattern).where(Pattern.is_active == True)

        if service_name:
            query = query.where(Pattern.service_name == service_name)

        query = query.order_by(Pattern.occurrence_count.desc()).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())
