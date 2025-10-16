"""Service for pattern operations."""

from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.log_entry import LogEntry
from app.models.pattern import Pattern
from app.processing.pattern_detector import PatternDetector

logger = get_logger(__name__)


class PatternService:
    """Handles pattern business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize service with database session."""
        self.db = db
        self.pattern_detector = PatternDetector()

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
        query = select(Pattern).where(Pattern.is_active.is_(True))

        if service_name:
            query = query.where(Pattern.service_name == service_name)

        query = query.order_by(Pattern.occurrence_count.desc()).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def detect_and_store_patterns(
        self,
        logs: List[LogEntry],
        service_name: Optional[str] = None,
        min_occurrences: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Detect patterns from logs using PatternDetector and store them in database.

        Args:
            logs: List of log entries to analyze
            service_name: Optional service name filter
            min_occurrences: Minimum occurrences to be considered a pattern

        Returns:
            List of stored pattern data
        """
        if not logs:
            return []

        # Use PatternDetector to detect patterns
        detected_patterns = self.pattern_detector.detect_patterns(
            logs, min_occurrences=min_occurrences
        )

        # Store patterns in database
        stored_patterns = []
        for pattern_data in detected_patterns:
            pattern = await self.create_or_update_pattern(
                pattern_id=pattern_data.get("pattern_id", f"pattern_{hash(pattern_data.get('template', ''))}"),
                pattern_type=pattern_data.get("severity", "INFO"),
                template=pattern_data.get("template", ""),
                description=pattern_data.get("description", f"Pattern: {pattern_data.get('template', '')[:50]}..."),
                service_name=service_name,
                occurrence_count=pattern_data.get("occurrences", 1),
                frequency_score=pattern_data.get("frequency_score", 0.0),
                severity_score=pattern_data.get("severity_score", 0.0),
                example_message=pattern_data.get("example_message"),
                is_anomaly=pattern_data.get("is_anomaly", False),
            )

            stored_patterns.append({
                "pattern_id": pattern.pattern_id,
                "template": pattern.template,
                "description": pattern.description,
                "occurrences": pattern.occurrence_count,
                "frequency_score": pattern.frequency_score,
                "severity_score": pattern.severity_score,
                "is_anomaly": pattern.is_anomaly,
                "created_at": pattern.created_at.isoformat(),
            })

        logger.info(
            "patterns_detected_and_stored",
            total_logs=len(logs),
            patterns_found=len(stored_patterns),
            service_name=service_name,
        )

        return stored_patterns

    async def get_patterns_for_logs(
        self,
        logs: List[LogEntry],
        service_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get patterns that match the given logs.

        Args:
            logs: List of log entries
            service_name: Optional service name filter

        Returns:
            List of matching patterns
        """
        # Get stored patterns
        stored_patterns = await self.get_active_patterns(service_name=service_name)

        # Find patterns that match the logs
        matching_patterns = []
        for pattern in stored_patterns:
            for log in logs:
                if pattern.template in log.message or log.message in pattern.template:
                    matching_patterns.append({
                        "pattern_id": pattern.pattern_id,
                        "template": pattern.template,
                        "description": pattern.description,
                        "occurrences": pattern.occurrence_count,
                        "frequency_score": pattern.frequency_score,
                        "severity_score": pattern.severity_score,
                        "is_anomaly": pattern.is_anomaly,
                        "matched_log_id": str(log.id),
                        "matched_log_message": log.message,
                    })
                    break

        return matching_patterns

    async def analyze_pattern_trends(
        self,
        service_name: Optional[str] = None,
        days_back: int = 7,
    ) -> Dict[str, Any]:
        """
        Analyze pattern trends over time.

        Args:
            service_name: Optional service name filter
            days_back: Number of days to look back

        Returns:
            Pattern trend analysis
        """
        # Get patterns from the last N days
        patterns = await self.get_active_patterns(service_name=service_name, limit=1000)

        # Analyze trends
        pattern_types = {}
        severity_distribution = {}
        anomaly_count = 0

        for pattern in patterns:
            # Count by type
            pattern_types[pattern.pattern_type] = pattern_types.get(pattern.pattern_type, 0) + 1

            # Severity distribution
            severity_range = f"{int(pattern.severity_score * 10) * 10}-{int(pattern.severity_score * 10) * 10 + 10}"
            severity_distribution[severity_range] = severity_distribution.get(severity_range, 0) + 1

            # Count anomalies
            if pattern.is_anomaly:
                anomaly_count += 1

        return {
            "total_patterns": len(patterns),
            "pattern_types": pattern_types,
            "severity_distribution": severity_distribution,
            "anomaly_count": anomaly_count,
            "anomaly_percentage": (anomaly_count / len(patterns) * 100) if patterns else 0,
            "analysis_period_days": days_back,
        }
