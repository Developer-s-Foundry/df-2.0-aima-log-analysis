"""
Enhanced log ingestion with AI-powered analysis.

This module extends the existing ingestion engine to incorporate AI analysis.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.log_entry import LogEntry
from app.processing.ingestion import LogIngestionEngine
from app.processing.ai_analyzer import get_ai_analyzer
from app.processing.analyzer import LogAnalyzer
from app.processing.pattern_detector import PatternDetector
from app.processing.anomaly_detector import AnomalyDetector
from app.monitoring.metrics import get_metrics_collector

logger = get_logger(__name__)


class EnhancedLogIngestionEngine(LogIngestionEngine):
    """
    Enhanced log ingestion engine with AI capabilities.
    
    Extends the base LogIngestionEngine to add:
    - AI-powered intent detection
    - Intelligent root cause analysis
    - Contextual recommendations
    - Improved anomaly detection
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize enhanced ingestion engine."""
        super().__init__(db)
        self.ai_analyzer = get_ai_analyzer()
        self.log_analyzer = LogAnalyzer()
        self.pattern_detector = PatternDetector()
        self.anomaly_detector = AnomalyDetector()
        self.metrics = get_metrics_collector()

    async def process_message(self, message: Dict[str, Any]) -> LogEntry:
        """
        Process incoming log message with AI enhancement.
        
        Args:
            message: Log message from RabbitMQ
            
        Returns:
            Processed and stored log entry
        """
        # First, use the base processing (validation, parsing, storage)
        log_entry = await super().process_message(message)
        
        # Then enhance with AI analysis if applicable
        await self._enhance_with_ai(log_entry)
        
        return log_entry

    async def _enhance_with_ai(self, log_entry: LogEntry) -> None:
        """
        Enhance log entry with AI analysis.
        
        Args:
            log_entry: Log entry to analyze
        """
        try:
            # Get context for better analysis
            context = await self._gather_context(log_entry)
            
            # Perform AI analysis
            start_time = datetime.utcnow()
            ai_result = await self.ai_analyzer.analyze_log(log_entry, context)
            analysis_duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Store AI analysis results in metadata
            if log_entry.metadata is None:
                log_entry.metadata = {}
            
            log_entry.metadata.update({
                "ai_analysis": {
                    "intent": ai_result.get("intent"),
                    "root_cause": ai_result.get("root_cause"),
                    "severity": ai_result.get("severity"),
                    "impact": ai_result.get("impact"),
                    "recommendations": ai_result.get("recommendations"),
                    "confidence": ai_result.get("confidence"),
                    "analyzer": ai_result.get("analyzer"),
                    "analysis_duration_seconds": analysis_duration
                }
            })
            
            # Update database with enhanced metadata
            await self.db.commit()
            await self.db.refresh(log_entry)
            
            # Record metrics
            self.metrics.record_ai_analysis_completed(
                service_name=log_entry.service_name,
                analyzer=ai_result.get("analyzer", "unknown"),
                duration=analysis_duration
            )
            
            # If high-severity issue detected, trigger immediate alert
            if ai_result.get("impact") in ["HIGH", "CRITICAL"]:
                await self._trigger_immediate_alert(log_entry, ai_result)
            
            logger.info(
                "ai_enhancement_completed",
                log_id=str(log_entry.id),
                intent=ai_result.get("intent"),
                confidence=ai_result.get("confidence")
            )
            
        except Exception as e:
            logger.error(
                "ai_enhancement_failed",
                log_id=str(log_entry.id),
                error=str(e),
                exc_info=True
            )
            # Don't fail the entire ingestion if AI analysis fails
            self.metrics.record_ai_analysis_failed()

    async def _gather_context(self, log_entry: LogEntry) -> Dict[str, Any]:
        """
        Gather contextual information for better AI analysis.
        
        Args:
            log_entry: Current log entry
            
        Returns:
            Context dictionary with relevant information
        """
        from sqlalchemy import select, func, desc
        from datetime import timedelta
        
        context = {}
        
        try:
            # Get recent logs from same service
            time_window = datetime.utcnow() - timedelta(minutes=15)
            recent_logs_query = (
                select(LogEntry)
                .where(
                    LogEntry.service_name == log_entry.service_name,
                    LogEntry.timestamp >= time_window,
                    LogEntry.log_level.in_(["ERROR", "CRITICAL", "WARNING"])
                )
                .order_by(desc(LogEntry.timestamp))
                .limit(5)
            )
            
            result = await self.db.execute(recent_logs_query)
            recent_logs = result.scalars().all()
            
            if recent_logs:
                context["recent_logs"] = [
                    {
                        "message": log.message,
                        "level": log.log_level,
                        "timestamp": log.timestamp.isoformat()
                    }
                    for log in recent_logs
                ]
            
            # Get error rate for this service
            error_count_query = select(func.count(LogEntry.id)).where(
                LogEntry.service_name == log_entry.service_name,
                LogEntry.timestamp >= time_window,
                LogEntry.log_level == "ERROR"
            )
            error_count_result = await self.db.execute(error_count_query)
            error_count = error_count_result.scalar()
            
            total_count_query = select(func.count(LogEntry.id)).where(
                LogEntry.service_name == log_entry.service_name,
                LogEntry.timestamp >= time_window
            )
            total_count_result = await self.db.execute(total_count_query)
            total_count = total_count_result.scalar()
            
            if total_count > 0:
                error_rate = (error_count / total_count) * 100
                context["error_rate"] = f"{error_rate:.2f}%"
                
                if error_rate > 10:
                    context["system_state"] = "HIGH_ERROR_RATE"
                elif error_rate > 5:
                    context["system_state"] = "ELEVATED_ERROR_RATE"
                else:
                    context["system_state"] = "NORMAL"
            
            # Get similar patterns
            patterns = self.pattern_detector.detect_patterns(recent_logs)
            if patterns:
                context["known_patterns"] = len(patterns)
                context["most_common_pattern"] = patterns[0]["template"] if patterns else None
            
        except Exception as e:
            logger.error("context_gathering_failed", error=str(e))
            # Return empty context rather than failing
        
        return context

    async def _trigger_immediate_alert(
        self, 
        log_entry: LogEntry, 
        ai_result: Dict[str, Any]
    ) -> None:
        """
        Trigger immediate alert for high-severity issues.
        
        Args:
            log_entry: Log entry with critical issue
            ai_result: AI analysis results
        """
        try:
            from app.messaging.publisher import get_publisher
            
            publisher = get_publisher()
            
            alert_message = {
                "type": "critical_log_alert",
                "severity": "HIGH",
                "service_name": log_entry.service_name,
                "log_level": log_entry.log_level,
                "message": log_entry.message,
                "intent": ai_result.get("intent"),
                "root_cause": ai_result.get("root_cause"),
                "impact": ai_result.get("impact"),
                "recommendations": ai_result.get("recommendations", []),
                "timestamp": log_entry.timestamp.isoformat(),
                "log_id": str(log_entry.id)
            }
            
            await publisher.publish_alert(alert_message)
            
            logger.info(
                "immediate_alert_sent",
                log_id=str(log_entry.id),
                service=log_entry.service_name
            )
            
        except Exception as e:
            logger.error(
                "immediate_alert_failed",
                log_id=str(log_entry.id),
                error=str(e),
                exc_info=True
            )


# Helper function for easy migration
def create_ingestion_engine(db: AsyncSession, use_ai: bool = True) -> LogIngestionEngine:
    """
    Factory function to create the appropriate ingestion engine.
    
    Args:
        db: Database session
        use_ai: Whether to use AI-enhanced engine
        
    Returns:
        LogIngestionEngine instance (base or enhanced)
    """
    if use_ai:
        return EnhancedLogIngestionEngine(db)
    else:
        return LogIngestionEngine(db)

