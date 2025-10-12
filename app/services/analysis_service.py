"""Service for analysis result operations."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.core.logging import get_logger

logger = get_logger(__name__)


class AnalysisService:
    """Handles analysis result business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize service with database session."""
        self.db = db

    async def create_analysis_result(
        self,
        service_name: str,
        analysis_start: datetime,
        analysis_end: datetime,
        total_logs: int,
        error_count: int,
        warning_count: int,
        info_count: int,
        error_rate: float,
        summary: str,
        common_errors: Optional[List[str]] = None,
        anomalies_detected: int = 0,
        anomaly_details: Optional[List[dict]] = None,
        recommendations: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Create a new analysis result."""
        result = AnalysisResult(
            service_name=service_name,
            analysis_start=analysis_start,
            analysis_end=analysis_end,
            total_logs=total_logs,
            error_count=error_count,
            warning_count=warning_count,
            info_count=info_count,
            error_rate=error_rate,
            summary=summary,
            common_errors=json.dumps(common_errors) if common_errors else None,
            anomalies_detected=anomalies_detected,
            anomaly_details=json.dumps(anomaly_details) if anomaly_details else None,
            recommendations=json.dumps(recommendations) if recommendations else None,
            alert_sent=False,
            recommendation_sent=False,
        )

        self.db.add(result)
        await self.db.commit()
        await self.db.refresh(result)

        logger.info(
            "analysis_result_created",
            result_id=str(result.id),
            service=service_name,
            error_rate=error_rate,
        )

        return result

    async def get_latest_analysis(
        self, service_name: str
    ) -> Optional[AnalysisResult]:
        """Get latest analysis result for a service."""
        query = (
            select(AnalysisResult)
            .where(AnalysisResult.service_name == service_name)
            .order_by(AnalysisResult.analysis_end.desc())
            .limit(1)
        )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_alert_sent(self, result_id: UUID) -> None:
        """Mark that alert has been sent for this result."""
        query = select(AnalysisResult).where(AnalysisResult.id == result_id)
        result = await self.db.execute(query)
        analysis = result.scalar_one_or_none()

        if analysis:
            analysis.alert_sent = True
            await self.db.commit()

    async def mark_recommendation_sent(self, result_id: UUID) -> None:
        """Mark that recommendation has been sent for this result."""
        query = select(AnalysisResult).where(AnalysisResult.id == result_id)
        result = await self.db.execute(query)
        analysis = result.scalar_one_or_none()

        if analysis:
            analysis.recommendation_sent = True
            await self.db.commit()
