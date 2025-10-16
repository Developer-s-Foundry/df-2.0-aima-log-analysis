"""Service for analysis result operations."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.analysis_result import AnalysisResult
from app.models.log_entry import LogEntry
from app.processing.ai_analyzer import AIAnalyzer
from app.processing.analyzer import LogAnalyzer
from app.processing.anomaly_detector import AnomalyDetector

logger = get_logger(__name__)


class AnalysisService:
    """Handles analysis result business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize service with database session."""
        self.db = db
        self.ai_analyzer = AIAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.log_analyzer = LogAnalyzer()

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

    async def perform_comprehensive_analysis(
        self,
        logs: List[LogEntry],
        service_name: str,
        use_ai: bool = True,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive analysis using all processing modules.

        Args:
            logs: List of log entries to analyze
            service_name: Service name for analysis
            use_ai: Whether to use AI analysis

        Returns:
            Comprehensive analysis results
        """
        if not logs:
            return {
                "total_logs": 0,
                "error_count": 0,
                "warning_count": 0,
                "info_count": 0,
                "error_rate": 0.0,
                "summary": "No logs to analyze",
                "ai_insights": [],
                "anomalies": [],
                "patterns": [],
            }

        analysis_start = datetime.utcnow()

        # 1. Basic log analysis
        basic_analysis = self.log_analyzer.analyze_logs(logs)

        # 2. AI Analysis (if enabled)
        ai_insights = []
        if use_ai:
            critical_logs = [log for log in logs if log.log_level in ["ERROR", "CRITICAL", "FATAL"]]
            for log in critical_logs[:5]:  # Analyze top 5 critical logs
                try:
                    ai_result = await self.ai_analyzer.analyze_log(log)
                    ai_insights.append({
                        "log_id": str(log.id),
                        "intent": ai_result.get("intent"),
                        "root_cause": ai_result.get("root_cause"),
                        "recommendations": ai_result.get("recommendations", []),
                        "confidence": ai_result.get("confidence", 0.0),
                    })
                except Exception as e:
                    logger.warning("ai_analysis_failed", log_id=str(log.id), error=str(e))

        # 3. Anomaly Detection
        anomalies = []
        if len(logs) >= 10:
            try:
                self.anomaly_detector.fit(logs)
                detected_anomalies = self.anomaly_detector.detect_anomalies(logs, contamination=0.1)
                for anomaly in detected_anomalies:
                    log = next((log for log in logs if log.id == anomaly["log_id"]), None)
                    if log:
                        anomalies.append({
                            "log_id": str(log.id),
                            "message": log.message,
                            "log_level": log.log_level,
                            "anomaly_score": anomaly["anomaly_score"],
                            "timestamp": log.timestamp.isoformat(),
                        })
            except Exception as e:
                logger.warning("anomaly_detection_failed", error=str(e))

        # 4. Calculate metrics
        error_count = len([log for log in logs if log.log_level in ["ERROR", "CRITICAL", "FATAL"]])
        warning_count = len([log for log in logs if log.log_level in ["WARNING", "WARN"]])
        info_count = len([log for log in logs if log.log_level == "INFO"])
        total_logs = len(logs)
        error_rate = (error_count / total_logs * 100) if total_logs > 0 else 0.0

        # 5. Create summary
        summary = f"Comprehensive analysis of {service_name} service. "
        summary += f"Analyzed {total_logs} logs with {error_count} errors ({error_rate:.1f}% error rate). "
        summary += f"Found {len(anomalies)} anomalies and {len(ai_insights)} AI insights."

        analysis_end = datetime.utcnow()

        return {
            "analysis_start": analysis_start.isoformat(),
            "analysis_end": analysis_end.isoformat(),
            "total_logs": total_logs,
            "error_count": error_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "error_rate": error_rate,
            "summary": summary,
            "ai_insights": ai_insights,
            "anomalies": anomalies,
            "basic_analysis": basic_analysis,
            "ai_enabled": use_ai,
        }

    async def analyze_log_with_ai(
        self,
        log: LogEntry,
        context_logs: Optional[List[LogEntry]] = None,
    ) -> Dict[str, Any]:
        """
        Perform AI analysis on a single log entry.

        Args:
            log: Log entry to analyze
            context_logs: Optional context logs for better analysis

        Returns:
            AI analysis results
        """
        context = None
        if context_logs:
            context = {
                "recent_logs": [
                    {
                        "message": log.message,
                        "level": log.log_level,
                        "timestamp": log.timestamp.isoformat()
                    }
                    for log in context_logs[:10] if log.id != log.id
                ]  # noqa: E501
            }

        try:
            ai_result = await self.ai_analyzer.analyze_log(log, context=context)
            return {
                "log_id": str(log.id),
                "log_message": log.message,
                "log_level": log.log_level,
                "service_name": log.service_name,
                "analysis": ai_result,
                "success": True,
            }
        except Exception as e:
            logger.error("ai_analysis_failed", log_id=str(log.id), error=str(e))
            return {
                "log_id": str(log.id),
                "log_message": log.message,
                "log_level": log.log_level,
                "service_name": log.service_name,
                "analysis": {
                    "intent": "UNKNOWN",
                    "root_cause": "Analysis failed",
                    "severity": log.log_level,
                    "confidence": 0.0,
                    "recommendations": ["Manual review required"],
                },
                "success": False,
                "error": str(e),
            }

    async def detect_anomalies_in_logs(
        self,
        logs: List[LogEntry],
        contamination: float = 0.1,
    ) -> List[Dict[str, Any]]:
        """
        Detect anomalies in a list of logs.

        Args:
            logs: List of log entries to analyze
            contamination: Expected proportion of anomalies

        Returns:
            List of detected anomalies
        """
        if len(logs) < 10:
            return []

        try:
            self.anomaly_detector.fit(logs)
            detected_anomalies = self.anomaly_detector.detect_anomalies(logs, contamination=contamination)

            anomaly_details = []
            for anomaly in detected_anomalies:
                log = next((log for log in logs if log.id == anomaly["log_id"]), None)
                if log:
                    anomaly_details.append({
                        "log_id": str(log.id),
                        "message": log.message,
                        "log_level": log.log_level,
                        "service_name": log.service_name,
                        "timestamp": log.timestamp.isoformat(),
                        "anomaly_score": anomaly["anomaly_score"],
                    })

            return anomaly_details

        except Exception as e:
            logger.error("anomaly_detection_failed", error=str(e))
            return []

    async def create_analysis_from_logs(
        self,
        logs: List[LogEntry],
        service_name: str,
        use_ai: bool = True,
    ) -> AnalysisResult:
        """
        Create analysis result from logs using all processing modules.

        Args:
            logs: List of log entries to analyze
            service_name: Service name for analysis
            use_ai: Whether to use AI analysis

        Returns:
            Created analysis result
        """
        # Perform comprehensive analysis
        analysis_data = await self.perform_comprehensive_analysis(logs, service_name, use_ai)

        # Extract recommendations from AI insights
        recommendations = []
        for insight in analysis_data["ai_insights"]:
            recommendations.extend(insight.get("recommendations", []))

        # Add anomaly recommendations
        if analysis_data["anomalies"]:
            recommendations.append("Investigate anomalous log entries")

        # Create analysis result
        analysis_result = await self.create_analysis_result(
            service_name=service_name,
            analysis_start=datetime.fromisoformat(analysis_data["analysis_start"]),
            analysis_end=datetime.fromisoformat(analysis_data["analysis_end"]),
            total_logs=analysis_data["total_logs"],
            error_count=analysis_data["error_count"],
            warning_count=analysis_data["warning_count"],
            info_count=analysis_data["info_count"],
            error_rate=analysis_data["error_rate"],
            summary=analysis_data["summary"],
            common_errors=analysis_data["basic_analysis"].get("common_errors", []),
            anomalies_detected=len(analysis_data["anomalies"]),
            anomaly_details=analysis_data["anomalies"],
            recommendations=list(set(recommendations)),  # Remove duplicates
        )

        logger.info(
            "comprehensive_analysis_created",
            result_id=str(analysis_result.id),
            service=service_name,
            total_logs=analysis_data["total_logs"],
            error_rate=analysis_data["error_rate"],
            anomalies=len(analysis_data["anomalies"]),
            ai_insights=len(analysis_data["ai_insights"]),
        )

        return analysis_result
