"""Log entry database model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class LogEntry(BaseModel):
    """
    Represents a processed log entry.

    Stores parsed and analyzed log data from various microservices.
    """

    __tablename__ = "log_entries"

    # Core log fields
    service_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True, comment="Source microservice name"
    )

    log_level: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True, comment="Log level (INFO, WARN, ERROR)"
    )

    message: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Log message content"
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True, comment="Log creation time"
    )

    # Analysis fields
    analysis_summary: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Extracted insight or pattern description"
    )

    error_score: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True, comment="Severity rating of log issue (0.0-1.0)"
    )

    anomaly_score: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True, comment="Anomaly detection score (0.0-1.0)"
    )

    pattern_id: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, index=True, comment="Associated pattern identifier"
    )

    # Metadata
    raw_data: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Original raw log data (JSON)"
    )

    processed: Mapped[bool] = mapped_column(
        default=False, nullable=False, index=True, comment="Processing status"
    )

    # Indexes for query optimization
    __table_args__ = (
        Index("idx_service_timestamp", "service_name", "timestamp"),
        Index("idx_level_timestamp", "log_level", "timestamp"),
        Index("idx_error_score", "error_score"),
        Index("idx_processed_timestamp", "processed", "timestamp"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<LogEntry(id={self.id}, service={self.service_name}, "
            f"level={self.log_level}, timestamp={self.timestamp})>"
        )
