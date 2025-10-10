"""Core log analysis engine."""

import re
from collections import Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.log_entry import LogEntry

logger = get_logger(__name__)


class LogAnalyzer:
    """
    Analyzes log entries for patterns, errors, and insights.

    Provides intelligent log analysis and summarization.
    """

    def __init__(self) -> None:
        """Initialize analyzer."""
        self.settings = get_settings()

    def analyze_logs(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """
        Analyze a batch of log entries.

        Args:
            logs: List of log entries to analyze

        Returns:
            Analysis results dictionary
        """
        if not logs:
            return self._empty_analysis()

        total_logs = len(logs)
        error_count = sum(1 for log in logs if log.log_level == "ERROR")
        warning_count = sum(1 for log in logs if log.log_level in ["WARN", "WARNING"])
        info_count = sum(1 for log in logs if log.log_level == "INFO")

        error_rate = (error_count / total_logs * 100) if total_logs > 0 else 0.0

        # Extract common errors
        error_logs = [log for log in logs if log.log_level == "ERROR"]
        common_errors = self._extract_common_errors(error_logs)

        # Generate summary
        summary = self._generate_summary(
            total_logs, error_count, warning_count, error_rate, common_errors
        )

        return {
            "total_logs": total_logs,
            "error_count": error_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "error_rate": round(error_rate, 2),
            "common_errors": common_errors,
            "summary": summary,
        }

    def _extract_common_errors(self, error_logs: List[LogEntry], top_n: int = 5) -> List[str]:
        """Extract most common error messages."""
        if not error_logs:
            return []

        # Normalize error messages
        error_messages = [self._normalize_error_message(log.message) for log in error_logs]

        # Count occurrences
        error_counter = Counter(error_messages)

        # Get top N
        common = error_counter.most_common(top_n)

        return [error for error, count in common]

    def _normalize_error_message(self, message: str) -> str:
        """
        Normalize error message by removing dynamic parts.

        Replaces IDs, timestamps, numbers with placeholders.
        """
        # Remove UUIDs
        message = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "[UUID]", message
        )

        # Remove numbers
        message = re.sub(r"\b\d+\b", "[NUM]", message)

        # Remove URLs
        message = re.sub(r"https?://\S+", "[URL]", message)

        # Remove file paths
        message = re.sub(r"(/[\w./]+)+", "[PATH]", message)

        return message.strip()

    def _generate_summary(
        self,
        total: int,
        errors: int,
        warnings: int,
        error_rate: float,
        common_errors: List[str],
    ) -> str:
        """Generate human-readable summary."""
        parts = [f"Analyzed {total} log entries."]

        if error_rate > self.settings.error_rate_threshold:
            parts.append(
                f"High error rate detected: {error_rate:.1f}% "
                f"(threshold: {self.settings.error_rate_threshold}%)."
            )
        elif errors > 0:
            parts.append(f"Found {errors} error(s) and {warnings} warning(s).")
        else:
            parts.append("No errors detected.")

        if common_errors:
            parts.append(f"Most common errors: {', '.join(common_errors[:3])}.")

        return " ".join(parts)

    def _empty_analysis(self) -> Dict[str, Any]:
        """Return empty analysis result."""
        return {
            "total_logs": 0,
            "error_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "error_rate": 0.0,
            "common_errors": [],
            "summary": "No logs to analyze.",
        }

    def calculate_error_score(self, log: LogEntry) -> float:
        """
        Calculate severity score for a log entry.

        Args:
            log: Log entry

        Returns:
            Error score between 0.0 and 1.0
        """
        score = 0.0

        # Base score by level
        level_scores = {
            "DEBUG": 0.0,
            "INFO": 0.1,
            "WARN": 0.4,
            "WARNING": 0.4,
            "ERROR": 0.7,
            "CRITICAL": 0.9,
            "FATAL": 1.0,
        }

        score = level_scores.get(log.log_level, 0.5)

        # Increase score for critical keywords
        critical_keywords = [
            "exception",
            "fatal",
            "critical",
            "crash",
            "panic",
            "timeout",
            "connection refused",
            "out of memory",
        ]

        message_lower = log.message.lower()
        for keyword in critical_keywords:
            if keyword in message_lower:
                score = min(score + 0.1, 1.0)

        return round(score, 2)
