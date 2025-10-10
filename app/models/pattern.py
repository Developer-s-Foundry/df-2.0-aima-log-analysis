"""Pattern database model for log pattern recognition."""

from typing import Optional

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class Pattern(BaseModel):
    """
    Represents a detected log pattern.

    Stores recurring patterns identified through clustering and analysis.
    """

    __tablename__ = "patterns"

    # Pattern identification
    pattern_id: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True, comment="Unique pattern ID"
    )

    pattern_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Pattern type (error, warning, info, anomaly)",
    )

    # Pattern details
    template: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Pattern template or signature"
    )

    description: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Human-readable pattern description"
    )

    # Service association
    service_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Associated service (null for cross-service patterns)",
    )

    # Statistics
    occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, comment="Number of times pattern occurred"
    )

    frequency_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, comment="Pattern frequency score (0.0-1.0)"
    )

    severity_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, comment="Pattern severity score (0.0-1.0)"
    )

    # Clustering information
    cluster_id: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, comment="Associated cluster ID from ML clustering"
    )

    # Pattern metadata
    example_message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Example log message matching this pattern"
    )

    tags: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array of pattern tags"
    )

    is_anomaly: Mapped[bool] = mapped_column(
        default=False, nullable=False, index=True, comment="Whether pattern is anomalous"
    )

    is_active: Mapped[bool] = mapped_column(
        default=True, nullable=False, index=True, comment="Whether pattern is currently active"
    )

    # Indexes for query optimization
    __table_args__ = (
        Index("idx_pattern_service", "pattern_type", "service_name"),
        Index("idx_frequency_severity", "frequency_score", "severity_score"),
        Index("idx_active_type", "is_active", "pattern_type"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<Pattern(id={self.pattern_id}, type={self.pattern_type}, "
            f"service={self.service_name}, occurrences={self.occurrence_count})>"
        )
