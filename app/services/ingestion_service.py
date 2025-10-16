"""Service for log ingestion with AI capabilities and fallback mechanisms."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.messaging.connection import RabbitMQConnection
from app.messaging.publisher import MessagePublisher
from app.models.log_entry import LogEntry
from app.monitoring.metrics import get_metrics_collector
from app.processing.ai_analyzer import AIAnalyzer
from app.processing.analyzer import LogAnalyzer
from app.processing.anomaly_detector import AnomalyDetector
from app.processing.pattern_detector import PatternDetector
from app.schemas.log_schemas import LogEntryCreate
from app.services.analysis_service import AnalysisService
from app.services.log_service import LogService
from app.services.pattern_service import PatternService

logger = get_logger(__name__)


class IngestionService:
    """
    Service for processing and ingesting log messages with AI capabilities.

    Features:
    - AI-powered analysis with fallback to basic analysis
    - Pattern detection and storage
    - Anomaly detection
    - Comprehensive error handling
    - Metrics collection
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize ingestion service."""
        self.db = db
        self.settings = get_settings()

        # Core services
        self.log_service = LogService(db)
        self.analysis_service = AnalysisService(db)
        self.pattern_service = PatternService(db)

        # Processing modules
        self.ai_analyzer = AIAnalyzer()
        self.log_analyzer = LogAnalyzer()
        self.pattern_detector = PatternDetector()
        self.anomaly_detector = AnomalyDetector()

        # Metrics
        self.metrics = get_metrics_collector()

        # Message publisher for alerts and recommendations
        self.rabbitmq_connection = RabbitMQConnection()
        self.publisher = MessagePublisher(self.rabbitmq_connection)

        # AI configuration
        self.ai_enabled = getattr(self.settings, "ai_analysis_enabled", True)

    async def process_message(
        self, message: Dict[str, Any], use_ai: Optional[bool] = None
    ) -> LogEntry:
        """
        Process incoming log message with optional AI enhancement.

        Args:
            message: Log message from RabbitMQ
            use_ai: Override AI setting (None = use default)

        Returns:
            Processed and stored log entry

        Raises:
            ValueError: If message is invalid
        """
        try:
            # Extract and validate message data
            log_data = self._extract_log_data(message)

            # Create log entry
            log_entry = await self.log_service.create_log_entry(log_data)

            # Record basic metrics
            self.metrics.record_log_ingested(log_entry.service_name, log_entry.log_level)

            # Determine if we should use AI
            should_use_ai = use_ai if use_ai is not None else self.ai_enabled

            # Process with AI or fallback
            if should_use_ai:
                await self._process_with_ai(log_entry)
            else:
                await self._process_with_basic_analysis(log_entry)

            # Record successful processing
            self.metrics.record_log_processed()

            logger.info(
                "log_processed_successfully",
                log_id=str(log_entry.id),
                service=log_entry.service_name,
                level=log_entry.log_level,
                ai_enabled=should_use_ai,
            )

            return log_entry

        except Exception as e:
            self.metrics.record_log_failed()
            logger.error(
                "log_processing_failed",
                error=str(e),
                message=message,
                exc_info=True,
            )
            raise

    def _extract_log_data(self, message: Dict[str, Any]) -> LogEntryCreate:
        """Extract and validate log data from message."""
        data = message.get("data", {})

        # Required fields
        service_name = data.get("service_name")
        log_level = data.get("log_level", "INFO")
        message_text = data.get("message", "")
        timestamp_str = data.get("timestamp")

        if not service_name:
            raise ValueError("service_name is required")
        if not message_text:
            raise ValueError("message is required")

        # Parse timestamp
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        return LogEntryCreate(
            service_name=service_name,
            log_level=log_level.upper(),
            message=message_text,
            timestamp=timestamp,
            raw_data=json.dumps(data),
        )

    async def _process_with_ai(self, log_entry: LogEntry) -> None:
        """
        Process log entry with AI analysis and automatic fallback to basic analysis if AI fails.
        """
        try:
            # Try AI analysis first
            ai_result = await self.ai_analyzer.analyze_log(log_entry)

            # Update log entry with AI insights
            await self.log_service.update_log_analysis(
                log_id=log_entry.id,
                analysis_summary=ai_result.get("root_cause", ""),
                error_score=self._calculate_error_score(log_entry.log_level, ai_result),
                anomaly_score=ai_result.get("anomaly_score", 0.0),
            )

            # Store pattern if detected
            if ai_result.get("pattern_detected"):
                await self._store_ai_pattern(log_entry, ai_result)

            # Check for immediate alerts
            if self._should_trigger_alert(log_entry, ai_result):
                await self._trigger_immediate_alert(log_entry, ai_result)

            logger.info(
                "ai_analysis_completed",
                log_id=str(log_entry.id),
                intent=ai_result.get("intent"),
                confidence=ai_result.get("confidence", 0.0),
            )

        except Exception as e:
            logger.warning(
                "ai_analysis_failed_using_basic_analysis",
                log_id=str(log_entry.id),
                error=str(e),
            )

            # ALWAYS fallback to basic analysis when AI fails
            # This ensures the system keeps working even if AI is down
            await self._process_with_basic_analysis(log_entry)

    async def _process_with_basic_analysis(self, log_entry: LogEntry) -> None:
        """Process log entry with basic analysis only."""
        try:
            # Basic log analysis
            basic_analysis = self.log_analyzer.analyze_logs([log_entry])

            # Update log entry
            await self.log_service.update_log_analysis(
                log_id=log_entry.id,
                analysis_summary=basic_analysis.get("summary", ""),
                error_score=self._calculate_error_score(log_entry.log_level),
            )

            # Detect patterns
            patterns = self.pattern_detector.detect_patterns([log_entry], min_occurrences=1)
            if patterns:
                await self._store_basic_patterns(log_entry, patterns)

            logger.info(
                "basic_analysis_completed",
                log_id=str(log_entry.id),
                summary=basic_analysis.get("summary", "")[:100],
            )

        except Exception as e:
            logger.error(
                "basic_analysis_failed",
                log_id=str(log_entry.id),
                error=str(e),
            )

            # Minimal processing - just mark as processed
            await self.log_service.update_log_analysis(
                log_id=log_entry.id,
                analysis_summary="Basic analysis failed",
                error_score=self._calculate_error_score(log_entry.log_level),
            )

    async def _store_ai_pattern(self, log_entry: LogEntry, ai_result: Dict[str, Any]) -> None:
        """Store pattern detected by AI analysis."""
        try:
            pattern_id = f"ai_pattern_{hash(log_entry.message)}"

            await self.pattern_service.create_or_update_pattern(
                pattern_id=pattern_id,
                pattern_type=log_entry.log_level,
                template=ai_result.get("pattern_template", log_entry.message),
                description=ai_result.get(
                    "pattern_description", f"AI-detected pattern: {log_entry.message[:50]}..."
                ),
                service_name=log_entry.service_name,
                occurrence_count=1,
                frequency_score=0.5,
                severity_score=ai_result.get("severity_score", 0.5),
                example_message=log_entry.message,
                is_anomaly=ai_result.get("is_anomaly", False),
            )

        except Exception as e:
            logger.warning("pattern_storage_failed", log_id=str(log_entry.id), error=str(e))

    async def _store_basic_patterns(
        self, log_entry: LogEntry, patterns: List[Dict[str, Any]]
    ) -> None:
        """Store patterns detected by basic analysis."""
        try:
            for pattern_data in patterns:
                pattern_id = f"basic_pattern_{hash(pattern_data.get('template', ''))}"

                await self.pattern_service.create_or_update_pattern(
                    pattern_id=pattern_id,
                    pattern_type=log_entry.log_level,
                    template=pattern_data.get("template", ""),
                    description=pattern_data.get(
                        "description", f"Basic pattern: {pattern_data.get('template', '')[:50]}..."
                    ),
                    service_name=log_entry.service_name,
                    occurrence_count=pattern_data.get("occurrences", 1),
                    frequency_score=pattern_data.get("frequency_score", 0.0),
                    severity_score=pattern_data.get("severity_score", 0.0),
                    example_message=log_entry.message,
                    is_anomaly=False,
                )

        except Exception as e:
            logger.warning("basic_pattern_storage_failed", log_id=str(log_entry.id), error=str(e))

    def _calculate_error_score(
        self, log_level: str, ai_result: Optional[Dict[str, Any]] = None
    ) -> float:
        """Calculate error score based on log level and AI analysis."""
        base_scores = {
            "CRITICAL": 1.0,
            "FATAL": 1.0,
            "ERROR": 0.8,
            "WARNING": 0.4,
            "WARN": 0.4,
            "INFO": 0.1,
            "DEBUG": 0.0,
        }

        base_score = base_scores.get(log_level.upper(), 0.5)

        if ai_result and "severity_score" in ai_result:
            # Blend AI severity with base score
            ai_score = ai_result["severity_score"]
            return (base_score + ai_score) / 2

        return base_score

    def _should_trigger_alert(self, log_entry: LogEntry, ai_result: Dict[str, Any]) -> bool:
        """Determine if an immediate alert should be triggered."""
        # High severity logs
        if log_entry.log_level in ["CRITICAL", "FATAL"]:
            return True

        # AI-detected critical issues
        if ai_result.get("severity") == "CRITICAL":
            return True

        # High confidence anomalies
        if ai_result.get("is_anomaly", False) and ai_result.get("confidence", 0.0) > 0.8:
            return True

        return False

    async def _trigger_immediate_alert(
        self, log_entry: LogEntry, ai_result: Dict[str, Any]
    ) -> None:
        """Trigger immediate alert for critical issues."""
        try:
            # Determine alert type and severity
            alert_type = "critical_error"
            severity = "critical"

            if ai_result.get("is_anomaly", False):
                alert_type = "anomaly_detected"
                severity = "high" if ai_result.get("confidence", 0.0) > 0.8 else "medium"

            # Prepare alert details
            alert_details = {
                "log_id": str(log_entry.id),
                "timestamp": log_entry.timestamp.isoformat(),
                "ai_analysis": {
                    "intent": ai_result.get("intent"),
                    "root_cause": ai_result.get("root_cause"),
                    "severity": ai_result.get("severity"),
                    "confidence": ai_result.get("confidence"),
                },
                "recommendations": ai_result.get("recommendations", []),
            }

            # Publish alert to RabbitMQ
            success = await self.publisher.publish_to_alerts(
                service_name=log_entry.service_name,
                alert_type=alert_type,
                severity=severity,
                message=log_entry.message,
                details=alert_details,
            )

            if success:
                logger.critical(
                    "immediate_alert_published",
                    log_id=str(log_entry.id),
                    service=log_entry.service_name,
                    alert_type=alert_type,
                    severity=severity,
                )

                # Record alert metric
                self.metrics.record_alert_triggered(log_entry.service_name, log_entry.log_level)
            else:
                logger.error(
                    "alert_publish_failed",
                    log_id=str(log_entry.id),
                    service=log_entry.service_name,
                )

        except Exception as e:
            logger.error("alert_triggering_failed", log_id=str(log_entry.id), error=str(e))

    async def _publish_recommendations(
        self, service_name: str, patterns: List[Dict[str, Any]]
    ) -> None:
        """Publish recommendations based on detected patterns."""
        try:
            if not patterns:
                return

            # Calculate error rate and summary
            total_patterns = len(patterns)
            high_severity_patterns = [p for p in patterns if p.get("severity_score", 0) > 0.7]

            summary = f"Detected {total_patterns} recurring patterns in {service_name}"
            if high_severity_patterns:
                summary += f" with {len(high_severity_patterns)} high-severity issues"

            error_rate = (
                len(high_severity_patterns) / total_patterns if total_patterns > 0 else 0.0
            )

            # Extract common errors from patterns
            common_errors = []
            for pattern in patterns[:5]:  # Top 5 patterns
                if pattern.get("template"):
                    common_errors.append(pattern["template"][:100])  # First 100 chars

            # Publish recommendation
            success = await self.publisher.publish_to_recommendations(
                service_name=service_name,
                summary=summary,
                error_rate=error_rate,
                total_logs=total_patterns,
                common_errors=common_errors,
                anomalies=[p for p in patterns if p.get("is_anomaly", False)],
            )

            if success:
                logger.info(
                    "recommendations_published",
                    service=service_name,
                    patterns_count=total_patterns,
                    error_rate=error_rate,
                )
            else:
                logger.error(
                    "recommendations_publish_failed",
                    service=service_name,
                )

        except Exception as e:
            logger.error("recommendations_publishing_failed", service=service_name, error=str(e))

    async def _process_patterns_and_recommendations(self, log_entries: List[LogEntry]) -> None:
        """Process patterns and publish recommendations for processed logs."""
        try:
            # Group logs by service
            service_logs = {}
            for log_entry in log_entries:
                if log_entry.service_name not in service_logs:
                    service_logs[log_entry.service_name] = []
                service_logs[log_entry.service_name].append(log_entry)

            # Process patterns for each service
            for service_name, logs in service_logs.items():
                if len(logs) >= 3:  # Only process if we have enough logs
                    patterns = await self.pattern_service.detect_and_store_patterns(
                        logs=logs,
                        service_name=service_name,
                        min_occurrences=2,  # Lower threshold for testing
                    )

                    if patterns:
                        await self._publish_recommendations(service_name, patterns)

        except Exception as e:
            logger.error("pattern_processing_failed", error=str(e))

    async def process_batch(
        self, messages: List[Dict[str, Any]], use_ai: Optional[bool] = None
    ) -> List[LogEntry]:
        """
        Process multiple log messages in batch.

        Args:
            messages: List of log messages
            use_ai: Override AI setting

        Returns:
            List of processed log entries
        """
        processed_logs = []

        for message in messages:
            try:
                log_entry = await self.process_message(message, use_ai=use_ai)
                processed_logs.append(log_entry)
            except Exception as e:
                logger.error("batch_processing_failed", error=str(e), message=message)
                # Continue processing other messages

        logger.info(
            "batch_processing_completed",
            total_messages=len(messages),
            processed_count=len(processed_logs),
            failed_count=len(messages) - len(processed_logs),
        )

        # After processing all logs, detect patterns and publish recommendations
        if processed_logs:
            await self._process_patterns_and_recommendations(processed_logs)

        return processed_logs

    async def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            "ai_enabled": self.ai_enabled,
            "metrics": {
                "logs_processed": self.metrics.get_logs_processed_count(),
                "logs_failed": self.metrics.get_logs_failed_count(),
                "alerts_triggered": self.metrics.get_alerts_triggered_count(),
            },
        }
