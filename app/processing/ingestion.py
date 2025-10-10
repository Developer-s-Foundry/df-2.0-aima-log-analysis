"""Log ingestion engine for processing incoming messages."""

import json
from datetime import datetime
from typing import Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.log_entry import LogEntry
from app.services.log_service import LogService

logger = get_logger(__name__)


class LogIngestionEngine:
    """
    Processes and ingests log messages into the database.

    Handles message parsing, validation, and storage.
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize ingestion engine."""
        self.db = db
        self.log_service = LogService(db)

    async def process_message(self, message: Dict[str, Any]) -> LogEntry:
        """
        Process incoming log message and store in database.

        Args:
            message: Log message from RabbitMQ

        Returns:
            Created log entry

        Raises:
            ValueError: If message is invalid
        """
        try:
            # Extract message data
            data = message.get("data", {})

            service_name = data.get("service_name")
            log_level = data.get("log_level")
            log_message = data.get("message")
            timestamp_str = data.get("timestamp")

            # Parse timestamp
            timestamp = self._parse_timestamp(timestamp_str)

            # Create log entry
            from app.schemas.log_schemas import LogEntryCreate

            log_data = LogEntryCreate(
                service_name=service_name,
                log_level=log_level,
                message=log_message,
                timestamp=timestamp,
                raw_data=json.dumps(message),
            )

            log_entry = await self.log_service.create_log_entry(log_data)

            logger.info(
                "log_ingested",
                log_id=str(log_entry.id),
                service=service_name,
                level=log_level,
            )

            return log_entry

        except Exception as e:
            logger.error("ingestion_error", error=str(e), message=message, exc_info=True)
            raise

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse timestamp string to datetime.

        Supports ISO 8601 format with or without 'Z' suffix.
        """
        if not timestamp_str:
            return datetime.utcnow()

        # Remove 'Z' suffix if present
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1]

        try:
            return datetime.fromisoformat(timestamp_str)
        except ValueError:
            logger.warning("timestamp_parse_failed", timestamp=timestamp_str)
            return datetime.utcnow()
