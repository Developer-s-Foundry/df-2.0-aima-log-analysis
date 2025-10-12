"""RabbitMQ connection management with auto-reconnect."""

from typing import Optional

import aio_pika
from aio_pika import Channel
from aio_pika.abc import AbstractRobustConnection
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class RabbitMQConnection:
    """
    Manages RabbitMQ connection with automatic reconnection.

    Provides robust connection handling with exponential backoff retry logic.
    """

    def __init__(self) -> None:
        """Initialize RabbitMQ connection manager."""
        self.settings = get_settings()
        self._connection: Optional[AbstractRobustConnection] = None
        self._channel: Optional[Channel] = None
        self._is_connected = False

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        retry=retry_if_exception_type((ConnectionError, OSError)),
        reraise=True,
    )
    async def connect(self) -> None:
        """
        Establish connection to RabbitMQ.

        Raises:
            ConnectionError: If unable to connect after retries
        """
        try:
            logger.info(
                "rabbitmq_connecting",
                host=self.settings.rabbitmq_host,
                port=self.settings.rabbitmq_port,
            )

            self._connection = await aio_pika.connect_robust(
                host=self.settings.rabbitmq_host,
                port=self.settings.rabbitmq_port,
                login=self.settings.rabbitmq_user,
                password=self.settings.rabbitmq_password,
                virtualhost=self.settings.rabbitmq_vhost,
                connection_attempts=3,
                retry_delay=self.settings.rabbitmq_reconnect_delay,
            )

            self._channel = await self._connection.channel()
            await self._channel.set_qos(prefetch_count=self.settings.rabbitmq_prefetch_count)

            self._is_connected = True

            logger.info(
                "rabbitmq_connected",
                host=self.settings.rabbitmq_host,
                prefetch_count=self.settings.rabbitmq_prefetch_count,
            )

        except Exception as e:
            logger.error("rabbitmq_connection_failed", error=str(e), exc_info=True)
            self._is_connected = False
            raise ConnectionError(f"Failed to connect to RabbitMQ: {str(e)}")

    async def disconnect(self) -> None:
        """Close RabbitMQ connection gracefully."""
        try:
            if self._channel and not self._channel.is_closed:
                await self._channel.close()

            if self._connection and not self._connection.is_closed:
                await self._connection.close()

            self._is_connected = False
            logger.info("rabbitmq_disconnected")

        except Exception as e:
            logger.error("rabbitmq_disconnect_error", error=str(e))

    async def ensure_connection(self) -> None:
        """Ensure connection is active, reconnect if necessary."""
        if not self._is_connected or self._connection is None or self._connection.is_closed:
            logger.warning("rabbitmq_reconnecting")
            await self.connect()

    @property
    def connection(self) -> Optional[AbstractRobustConnection]:
        """Get RabbitMQ connection."""
        return self._connection

    @property
    def channel(self) -> Optional[Channel]:
        """Get RabbitMQ channel."""
        return self._channel

    @property
    def is_connected(self) -> bool:
        """Check if connected to RabbitMQ."""
        return self._is_connected and self._connection is not None and not self._connection.is_closed

    async def declare_queue(
        self, queue_name: str, durable: bool = True, auto_delete: bool = False
    ) -> aio_pika.Queue:
        """
        Declare a queue on RabbitMQ.

        Args:
            queue_name: Name of the queue
            durable: Whether queue survives broker restart
            auto_delete: Whether queue is deleted when no consumers

        Returns:
            Declared queue instance

        Raises:
            RuntimeError: If not connected
        """
        await self.ensure_connection()

        if self._channel is None:
            raise RuntimeError("Channel not initialized")

        queue = await self._channel.declare_queue(
            queue_name, durable=durable, auto_delete=auto_delete
        )

        logger.info("queue_declared", queue_name=queue_name, durable=durable)
        return queue

    async def declare_exchange(
        self,
        exchange_name: str,
        exchange_type: aio_pika.ExchangeType = aio_pika.ExchangeType.DIRECT,
        durable: bool = True,
    ) -> aio_pika.Exchange:
        """
        Declare an exchange on RabbitMQ.

        Args:
            exchange_name: Name of the exchange
            exchange_type: Type of exchange (direct, topic, fanout, headers)
            durable: Whether exchange survives broker restart

        Returns:
            Declared exchange instance

        Raises:
            RuntimeError: If not connected
        """
        await self.ensure_connection()

        if self._channel is None:
            raise RuntimeError("Channel not initialized")

        exchange = await self._channel.declare_exchange(
            exchange_name, type=exchange_type, durable=durable
        )

        logger.info(
            "exchange_declared",
            exchange_name=exchange_name,
            exchange_type=exchange_type.value,
        )
        return exchange


# Global connection instance
_rabbitmq_connection: Optional[RabbitMQConnection] = None


async def get_rabbitmq_connection() -> RabbitMQConnection:
    """Get or create global RabbitMQ connection instance."""
    global _rabbitmq_connection

    if _rabbitmq_connection is None:
        _rabbitmq_connection = RabbitMQConnection()
        await _rabbitmq_connection.connect()

    return _rabbitmq_connection


async def close_rabbitmq_connection() -> None:
    """Close global RabbitMQ connection."""
    global _rabbitmq_connection

    if _rabbitmq_connection is not None:
        await _rabbitmq_connection.disconnect()
        _rabbitmq_connection = None
