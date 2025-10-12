"""RabbitMQ consumer for log ingestion."""

import asyncio
import json
from typing import Callable, Optional

from aio_pika.abc import AbstractIncomingMessage

from app.core.config import get_settings
from app.core.logging import get_logger
from app.messaging.connection import RabbitMQConnection

logger = get_logger(__name__)


class LogConsumer:
    """
    Consumes log messages from RabbitMQ queue.

    Processes incoming log entries with configurable message handlers.
    """

    def __init__(self, connection: RabbitMQConnection) -> None:
        """
        Initialize log consumer.

        Args:
            connection: RabbitMQ connection instance
        """
        self.connection = connection
        self.settings = get_settings()
        self._is_consuming = False
        self._consumer_tag: Optional[str] = None

    async def start_consuming(
        self, message_handler: Callable[[dict], None]
    ) -> None:
        """
        Start consuming messages from the log analysis queue.

        Args:
            message_handler: Async function to handle incoming messages
        """
        try:
            await self.connection.ensure_connection()

            # Declare the queue
            queue = await self.connection.declare_queue(
                self.settings.log_analysis_queue,
                durable=True,
                auto_delete=False,
            )

            logger.info(
                "consumer_starting",
                queue_name=self.settings.log_analysis_queue,
                prefetch_count=self.settings.rabbitmq_prefetch_count,
            )

            # Start consuming
            self._is_consuming = True

            async with queue.iterator() as queue_iter:
                async for message in queue_iter:
                    if not self._is_consuming:
                        break

                    await self._process_message(message, message_handler)

        except asyncio.CancelledError:
            logger.info("consumer_cancelled")
            self._is_consuming = False
        except Exception as e:
            logger.error("consumer_error", error=str(e), exc_info=True)
            self._is_consuming = False
            raise

    async def _process_message(
        self,
        message: AbstractIncomingMessage,
        handler: Callable[[dict], None],
    ) -> None:
        """
        Process a single message.

        Args:
            message: Incoming RabbitMQ message
            handler: Message handler function
        """
        try:
            # Decode message body
            body = message.body.decode("utf-8")
            data = json.loads(body)

            logger.debug(
                "message_received",
                message_id=message.message_id,
                delivery_tag=message.delivery_tag,
            )

            # Validate message structure
            if not self._validate_message(data):
                logger.warning(
                    "invalid_message_format",
                    message_id=message.message_id,
                    data=data,
                )
                await message.reject(requeue=False)
                return

            # Process message
            await handler(data)

            # Acknowledge message
            await message.ack()

            logger.debug(
                "message_processed",
                message_id=message.message_id,
                service_name=data.get("data", {}).get("service_name"),
            )

        except json.JSONDecodeError as e:
            logger.error(
                "message_json_decode_error",
                error=str(e),
                message_id=message.message_id,
            )
            await message.reject(requeue=False)

        except Exception as e:
            logger.error(
                "message_processing_error",
                error=str(e),
                message_id=message.message_id,
                exc_info=True,
            )
            # Requeue message for retry
            await message.reject(requeue=True)

    def _validate_message(self, data: dict) -> bool:
        """
        Validate message structure.

        Args:
            data: Message data dictionary

        Returns:
            True if message is valid, False otherwise
        """
        try:
            # Check required top-level fields
            if "data" not in data or "queue_name" not in data:
                return False

            message_data = data["data"]

            # Check required message fields
            required_fields = [
                "type",
                "receiver",
                "service_name",
                "log_level",
                "message",
                "timestamp"
                ]

            if not all(field in message_data for field in required_fields):
                return False

            # Validate log level
            valid_levels = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"]
            if message_data["log_level"].upper() not in valid_levels:
                return False

            # Validate receiver
            if message_data["receiver"] != "log_analysis_service":
                logger.warning(
                    "message_wrong_receiver",
                    receiver=message_data["receiver"],
                )
                return False

            return True

        except (KeyError, TypeError, AttributeError) as e:
            logger.error("message_validation_error", error=str(e))
            return False

    async def stop_consuming(self) -> None:
        """Stop consuming messages."""
        self._is_consuming = False
        logger.info("consumer_stopped")

    @property
    def is_consuming(self) -> bool:
        """Check if consumer is active."""
        return self._is_consuming
