"""Pydantic schemas for log-related data validation."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class LogEntryCreate(BaseModel):
    """Schema for creating a log entry."""

    service_name: str = Field(..., min_length=1, max_length=255)
    log_level: str = Field(..., min_length=1, max_length=50)
    message: str = Field(..., min_length=1)
    timestamp: datetime
    raw_data: Optional[str] = None

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()

    model_config = {"from_attributes": True}


class LogEntryResponse(BaseModel):
    """Schema for log entry response."""

    id: UUID
    service_name: str
    log_level: str
    message: str
    timestamp: datetime
    analysis_summary: Optional[str] = None
    error_score: Optional[float] = None
    anomaly_score: Optional[float] = None
    pattern_id: Optional[str] = None
    processed: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class LogListResponse(BaseModel):
    """Schema for paginated log list response."""

    data: List[LogEntryResponse]
    total: int
    page: int
    page_size: int
    pages: int

    model_config = {"from_attributes": True}


class AnalysisResultResponse(BaseModel):
    """Schema for analysis result response."""

    id: UUID
    service_name: str
    analysis_start: datetime
    analysis_end: datetime
    total_logs: int
    error_count: int
    warning_count: int
    info_count: int
    error_rate: float
    summary: str
    common_errors: Optional[str] = None
    anomalies_detected: int
    anomaly_details: Optional[str] = None
    recommendations: Optional[str] = None
    alert_sent: bool
    recommendation_sent: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisSummaryResponse(BaseModel):
    """Schema for aggregated analysis summary."""

    service: str
    total_logs: int
    error_rate: float
    common_errors: List[str]
    anomalies_detected: int
    recommendations: List[str]
    period_start: datetime
    period_end: datetime

    model_config = {"from_attributes": True}


class APIResponse(BaseModel):
    """Standard API response wrapper."""

    data: Optional[dict | list] = None
    status_code: int
    message: str
    errors: Optional[List[str]] = None

    model_config = {"from_attributes": True}
