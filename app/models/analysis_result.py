"""Analysis result database model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class AnalysisResult(BaseModel):
    """
    Represents aggregated analysis results for a service.

    Stores summary insights, error rates, and recommendations.
    """

    __tablename__ = "analysis_results"

    # Service identification
    service_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True, comment="Target microservice name"
    )

    # Time window
    analysis_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, comment="Analysis period start time"
    )

    analysis_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, comment="Analysis period end time"
    )

    # Metrics
    total_logs: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Total number of logs analyzed"
    )

    error_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Number of error-level logs"
    )

    warning_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Number of warning-level logs"
    )

    info_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Number of info-level logs"
    )

    error_rate: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, comment="Error rate percentage"
    )

    # Analysis insights
    summary: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Human-readable analysis summary"
    )

    common_errors: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array of common error messages"
    )

    anomalies_detected: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Number of anomalies detected"
    )

    anomaly_details: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array of anomaly descriptions"
    )

    # Recommendations
    recommendations: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array of recommendations"
    )

    alert_sent: Mapped[bool] = mapped_column(
        default=False, nullable=False, comment="Whether alert was sent to Alert System"
    )

    recommendation_sent: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Whether sent to Recommendation System",
    )

    # Indexes for query optimization
    __table_args__ = (
        Index("idx_service_period", "service_name", "analysis_start", "analysis_end"),
        Index("idx_error_rate", "error_rate"),
        Index("idx_analysis_end", "analysis_end"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<AnalysisResult(id={self.id}, service={self.service_name}, "
            f"error_rate={self.error_rate}%, total_logs={self.total_logs})>"
        )
