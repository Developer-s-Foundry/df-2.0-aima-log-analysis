"""Prometheus metrics collection."""

from fastapi import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from app.core.logging import get_logger

logger = get_logger(__name__)


class MetricsCollector:
    """Collects and exposes Prometheus metrics."""

    def __init__(self) -> None:
        """Initialize metrics collectors."""
        # Log ingestion metrics
        self.logs_ingested_total = Counter(
            "logs_ingested_total",
            "Total number of logs ingested",
            ["service_name", "log_level"],
        )

        self.logs_processed_total = Counter(
            "logs_processed_total", "Total number of logs processed successfully"
        )

        self.logs_failed_total = Counter(
            "logs_failed_total", "Total number of failed log processing attempts"
        )

        # Analysis metrics
        self.analysis_duration_seconds = Histogram(
            "analysis_duration_seconds",
            "Time spent analyzing logs",
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
        )

        self.anomalies_detected_total = Counter(
            "anomalies_detected_total", "Total number of anomalies detected"
        )

        self.patterns_detected_total = Counter(
            "patterns_detected_total", "Total number of patterns detected"
        )

        # Alert metrics
        self.alerts_triggered_total = Counter(
            "alerts_triggered_total",
            "Total number of alerts triggered",
            ["service_name", "log_level"],
        )

        # RabbitMQ metrics
        self.messages_consumed_total = Counter(
            "messages_consumed_total", "Total messages consumed from RabbitMQ"
        )

        self.messages_published_total = Counter(
            "messages_published_total",
            "Total messages published to RabbitMQ",
            ["queue_name"],
        )

        self.rabbitmq_connection_errors = Counter(
            "rabbitmq_connection_errors_total", "Total RabbitMQ connection errors"
        )

        # API metrics
        self.api_requests_total = Counter(
            "api_requests_total",
            "Total API requests",
            ["method", "endpoint", "status_code"],
        )

        self.api_request_duration_seconds = Histogram(
            "api_request_duration_seconds",
            "API request duration",
            ["method", "endpoint"],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0],
        )

        # System metrics
        self.active_consumers = Gauge("active_consumers", "Number of active RabbitMQ consumers")

        self.unprocessed_logs = Gauge("unprocessed_logs", "Number of unprocessed logs in database")

        logger.info("metrics_collector_initialized")

    def record_log_ingested(self, service_name: str, log_level: str) -> None:
        """Record log ingestion."""
        self.logs_ingested_total.labels(service_name=service_name, log_level=log_level).inc()

    def record_log_processed(self) -> None:
        """Record successful log processing."""
        self.logs_processed_total.inc()

    def record_log_failed(self) -> None:
        """Record failed log processing."""
        self.logs_failed_total.inc()

    def record_anomaly(self) -> None:
        """Record anomaly detection."""
        self.anomalies_detected_total.inc()

    def record_pattern(self) -> None:
        """Record pattern detection."""
        self.patterns_detected_total.inc()

    def record_alert_triggered(self, service_name: str, log_level: str) -> None:
        """Record alert triggered."""
        self.alerts_triggered_total.labels(service_name=service_name, log_level=log_level).inc()

    def record_message_consumed(self) -> None:
        """Record RabbitMQ message consumption."""
        self.messages_consumed_total.inc()

    def record_message_published(self, queue_name: str) -> None:
        """Record RabbitMQ message publication."""
        self.messages_published_total.labels(queue_name=queue_name).inc()

    def record_connection_error(self) -> None:
        """Record RabbitMQ connection error."""
        self.rabbitmq_connection_errors.inc()

    def record_api_request(self, method: str, endpoint: str, status_code: int) -> None:
        """Record API request."""
        self.api_requests_total.labels(
            method=method, endpoint=endpoint, status_code=status_code
        ).inc()

    def set_active_consumers(self, count: int) -> None:
        """Set number of active consumers."""
        self.active_consumers.set(count)

    def set_unprocessed_logs(self, count: int) -> None:
        """Set number of unprocessed logs."""
        self.unprocessed_logs.set(count)

    def get_logs_processed_count(self) -> int:
        """Get logs processed count."""
        return int(self.logs_processed_total._value.get())

    def get_logs_failed_count(self) -> int:
        """Get logs failed count."""
        return int(self.logs_failed_total._value.get())

    def get_alerts_triggered_count(self) -> int:
        """Get alerts triggered count."""
        return int(self.alerts_triggered_total._value.get())


# Global metrics collector instance
_metrics_collector: MetricsCollector | None = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector."""
    global _metrics_collector

    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()

    return _metrics_collector


async def metrics_endpoint() -> Response:
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
