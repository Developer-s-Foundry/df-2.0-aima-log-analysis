"""RabbitMQ publisher for sending analysis results."""

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional

import aio_pika
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import get_settings
from app.core.logging import get_logger
from app.messaging.connection import RabbitMQConnection

logger = get_logger(__name__)


class MessagePublisher:
    """
    Publishes analysis results and alerts to RabbitMQ queues.

    Handles message formatting, signature generation, and delivery.
    """

    def __init__(self, connection: RabbitMQConnection) -> None:
        """
        Initialize message publisher.

        Args:
            connection: RabbitMQ connection instance
        """
        self.connection = connection
        self.settings = get_settings()

    def _generate_signature(self, data: Dict[str, Any]) -> str:
        """
        Generate SHA-256 signature for message data.

        Args:
            data: Message data dictionary

        Returns:
            Hexadecimal signature string
        """
        data_str = json.dumps(data, sort_keys=True)
        signature = hashlib.sha256(data_str.encode()).hexdigest()
        return signature

    def _format_message(
        self,
        message_type: str,
        receiver: str,
        queue_name: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Format message according to system specification.

        Args:
            message_type: Type of message (analysis_result, alert, etc.)
            receiver: Receiver service name
            queue_name: Target queue name
            data: Message payload data

        Returns:
            Formatted message dictionary
        """
        message_data = {
            "type": message_type,
            "receiver": receiver,
            "sender": "log_analysis_service",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            **data,
        }

        message = {
            "data": message_data,
            "queue_name": queue_name,
            "signature": self._generate_signature(message_data),
        }

        return message

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def publish_to_recommendations(
        self,
        service_name: str,
        summary: str,
        error_rate: float,
        total_logs: int,
        common_errors: Optional[list] = None,
        anomalies: Optional[list] = None,
    ) -> bool:
        """
        Publish analysis result to Recommendation System (Team E).

        Args:
            service_name: Source service name
            summary: Analysis summary text
            error_rate: Error rate percentage
            total_logs: Total number of logs analyzed
            common_errors: List of common error messages
            anomalies: List of detected anomalies

        Returns:
            True if published successfully, False otherwise
        """
        try:
            await self.connection.ensure_connection()

            data = {
                "service_name": service_name,
                "summary": summary,
                "error_rate": error_rate,
                "total_logs": total_logs,
            }

            if common_errors:
                data["common_errors"] = common_errors

            if anomalies:
                data["anomalies"] = anomalies

            message = self._format_message(
                message_type="analysis_result",
                receiver="recommendation_service",
                queue_name=self.settings.recommendation_queue,
                data=data,
            )

            # Declare queue and publish
            queue = await self.connection.declare_queue(
                self.settings.recommendation_queue, durable=True
            )
            print("queue", queue)

            await self.connection.channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps(message).encode(),
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    content_type="application/json",
                ),
                routing_key=self.settings.recommendation_queue,
            )

            logger.info(
                "recommendation_published",
                service_name=service_name,
                error_rate=error_rate,
                queue=self.settings.recommendation_queue,
            )

            return True

        except Exception as e:
            logger.error(
                "recommendation_publish_failed",
                service_name=service_name,
                error=str(e),
                exc_info=True,
            )
            return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def publish_to_alerts(
        self,
        service_name: str,
        alert_type: str,
        severity: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Publish high-severity alert to Alert System (Team A).

        Args:
            service_name: Source service name
            alert_type: Type of alert (error_spike, anomaly, etc.)
            severity: Alert severity (low, medium, high, critical)
            message: Alert message
            details: Additional alert details

        Returns:
            True if published successfully, False otherwise
        """
        try:
            await self.connection.ensure_connection()

            data = {
                "service_name": service_name,
                "alert_type": alert_type,
                "severity": severity,
                "message": message,
            }

            if details:
                data["details"] = details

            message_payload = self._format_message(
                message_type="alert",
                receiver="alert_service",
                queue_name=self.settings.alerts_queue,
                data=data,
            )

            # Declare queue and publish
            queue = await self.connection.declare_queue(self.settings.alerts_queue, durable=True)

            print("queue", queue)

            await self.connection.channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps(message_payload).encode(),
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    content_type="application/json",
                    priority=5 if severity in ["high", "critical"] else 3,
                ),
                routing_key=self.settings.alerts_queue,
            )

            logger.info(
                "alert_published",
                service_name=service_name,
                alert_type=alert_type,
                severity=severity,
                queue=self.settings.alerts_queue,
            )

            return True

        except Exception as e:
            logger.error(
                "alert_publish_failed",
                service_name=service_name,
                alert_type=alert_type,
                error=str(e),
                exc_info=True,
            )
            return False
