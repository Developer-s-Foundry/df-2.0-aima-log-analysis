"""Pattern detection and clustering for log entries."""

import re
from collections import defaultdict
from typing import List, Dict, Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.log_entry import LogEntry

logger = get_logger(__name__)


class PatternDetector:
    """Detects recurring patterns in log messages."""

    def __init__(self) -> None:
        """Initialize pattern detector."""
        self.settings = get_settings()

    def detect_patterns(self, logs: List[LogEntry]) -> List[Dict[str, Any]]:
        """
        Detect recurring patterns in logs.

        Args:
            logs: List of log entries

        Returns:
            List of detected patterns
        """
        if not logs:
            return []

        # Normalize messages and group by template
        templates = defaultdict(list)

        for log in logs:
            template = self._extract_template(log.message)
            templates[template].append(log)

        # Filter patterns by frequency
        patterns = []
        for template, matched_logs in templates.items():
            frequency = len(matched_logs)

            if frequency >= self.settings.min_pattern_frequency:
                pattern = {
                    "template": template,
                    "frequency": frequency,
                    "log_level": matched_logs[0].log_level,
                    "service_name": matched_logs[0].service_name,
                    "example_message": matched_logs[0].message,
                    "severity_score": self._calculate_severity(matched_logs),
                }
                patterns.append(pattern)

        # Sort by frequency
        patterns.sort(key=lambda x: x["frequency"], reverse=True)

        logger.info("pattern_detection_completed", total_patterns=len(patterns))

        return patterns

    def _extract_template(self, message: str) -> str:
        """
        Extract template from log message.

        Replaces dynamic parts with placeholders.
        """
        # Remove UUIDs
        template = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{UUID}", message
        )

        # Remove numbers
        template = re.sub(r"\b\d+\b", "{NUM}", template)

        # Remove quoted strings
        template = re.sub(r'"[^"]*"', '"{STR}"', template)
        template = re.sub(r"'[^']*'", "'{STR}'", template)

        # Remove URLs
        template = re.sub(r"https?://\S+", "{URL}", template)

        # Remove IP addresses
        template = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "{IP}", template)

        # Remove file paths
        template = re.sub(r"(/[\w./]+)+", "{PATH}", template)

        return template.strip()

    def _calculate_severity(self, logs: List[LogEntry]) -> float:
        """Calculate average severity for pattern."""
        level_scores = {
            "DEBUG": 0.1,
            "INFO": 0.2,
            "WARN": 0.5,
            "WARNING": 0.5,
            "ERROR": 0.8,
            "CRITICAL": 0.95,
            "FATAL": 1.0,
        }

        total_score = sum(level_scores.get(log.log_level, 0.5) for log in logs)
        return round(total_score / len(logs), 2)
