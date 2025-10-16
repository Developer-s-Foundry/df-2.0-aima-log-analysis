"""Anomaly detection using statistical methods."""

from typing import List

import numpy as np
from sklearn.ensemble import IsolationForest

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.log_entry import LogEntry

logger = get_logger(__name__)


class AnomalyDetector:
    """Detects anomalies in log patterns using ML."""

    def __init__(self) -> None:
        """Initialize anomaly detector."""
        self.settings = get_settings()
        self.model = IsolationForest(contamination=0.1, random_state=42)

    def detect_anomalies(self, logs: List[LogEntry]) -> List[tuple[LogEntry, float]]:
        """
        Detect anomalous log entries.

        Args:
            logs: List of log entries

        Returns:
            List of tuples (log_entry, anomaly_score)
        """
        if len(logs) < 10:  # Need minimum samples
            return []

        try:
            # Extract features
            features = self._extract_features(logs)

            if features.size == 0:
                return []

            # Fit and predict
            predictions = self.model.fit_predict(features)
            scores = self.model.score_samples(features)

            # Normalize scores to 0-1 range
            normalized_scores = self._normalize_scores(scores)

            # Filter anomalies
            anomalies = []
            for i, (pred, score) in enumerate(zip(predictions, normalized_scores)):
                if pred == -1 and score >= self.settings.anomaly_score_threshold:
                    anomalies.append((logs[i], score))

            logger.info("anomaly_detection_completed", total=len(logs), anomalies=len(anomalies))

            return anomalies

        except Exception as e:
            logger.error("anomaly_detection_failed", error=str(e), exc_info=True)
            return []

    def _extract_features(self, logs: List[LogEntry]) -> np.ndarray:
        """Extract numerical features from logs."""
        features = []

        for log in logs:
            # Feature vector
            feature = [
                1 if log.log_level == "ERROR" else 0,
                1 if log.log_level in ["WARN", "WARNING"] else 0,
                len(log.message),  # Message length
                log.message.count("exception"),
                log.message.count("error"),
                log.message.count("timeout"),
            ]
            features.append(feature)

        return np.array(features)

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Normalize anomaly scores to 0-1 range."""
        min_score = scores.min()
        max_score = scores.max()

        if max_score == min_score:
            return np.zeros_like(scores)

        return (scores - min_score) / (max_score - min_score)
