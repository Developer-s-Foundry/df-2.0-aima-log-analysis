"""Advanced error handling with circuit breaker, retries, and dead letter queue."""

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Any, Optional, Dict
from functools import wraps
import traceback

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern implementation.
    
    Prevents cascading failures by stopping requests to failing services.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout: int = 60
    ):
        """
        Initialize circuit breaker.
        
        Args:
            name: Circuit breaker name
            failure_threshold: Failures before opening circuit
            success_threshold: Successes needed to close circuit
            timeout: Seconds before trying again (open -> half-open)
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Async function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerError: If circuit is open
        """
        # Check if we should attempt the call
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info(
                    "circuit_breaker_half_open",
                    name=self.name,
                    message="Attempting to recover"
                )
            else:
                raise CircuitBreakerError(
                    f"Circuit breaker {self.name} is OPEN"
                )
        
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
            
        except Exception as e:
            self._on_failure()
            raise
    
    def _on_success(self) -> None:
        """Handle successful call."""
        self.failure_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self._close_circuit()
    
    def _on_failure(self) -> None:
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        self.success_count = 0
        
        if self.failure_count >= self.failure_threshold:
            self._open_circuit()
    
    def _open_circuit(self) -> None:
        """Open the circuit."""
        self.state = CircuitState.OPEN
        logger.warning(
            "circuit_breaker_opened",
            name=self.name,
            failure_count=self.failure_count,
            threshold=self.failure_threshold
        )
    
    def _close_circuit(self) -> None:
        """Close the circuit."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        logger.info(
            "circuit_breaker_closed",
            name=self.name,
            message="Circuit recovered"
        )
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if not self.last_failure_time:
            return True
        
        elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
        return elapsed >= self.timeout
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None
        }


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""
    pass


# Global circuit breakers
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    success_threshold: int = 2,
    timeout: int = 60
) -> CircuitBreaker:
    """Get or create a circuit breaker."""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(
            name=name,
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout
        )
    return _circuit_breakers[name]


def with_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    success_threshold: int = 2,
    timeout: int = 60
):
    """
    Decorator to add circuit breaker to async function.
    
    Usage:
        @with_circuit_breaker("database")
        async def query_database():
            ...
    """
    def decorator(func: Callable):
        circuit_breaker = get_circuit_breaker(
            name=name,
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout
        )
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await circuit_breaker.call(func, *args, **kwargs)
        
        return wrapper
    return decorator


def with_retry(
    max_attempts: int = 3,
    min_wait: int = 1,
    max_wait: int = 10,
    exceptions: tuple = (Exception,)
):
    """
    Decorator for retry logic with exponential backoff.
    
    Usage:
        @with_retry(max_attempts=3, exceptions=(ConnectionError,))
        async def risky_operation():
            ...
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type(exceptions),
        before_sleep=before_sleep_log(logger, "WARNING"),
        after=after_log(logger, "INFO")
    )


class DeadLetterQueue:
    """
    Dead letter queue for failed messages.
    
    Stores messages that failed processing for later analysis/retry.
    """

    def __init__(self):
        """Initialize dead letter queue."""
        self.failed_messages: list = []
        self.max_size = 1000
    
    async def add(
        self,
        message: Any,
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add failed message to DLQ.
        
        Args:
            message: Original message
            error: Exception that occurred
            context: Additional context
        """
        entry = {
            "message": message,
            "error": str(error),
            "error_type": type(error).__name__,
            "traceback": traceback.format_exc(),
            "timestamp": datetime.utcnow().isoformat(),
            "context": context or {}
        }
        
        self.failed_messages.append(entry)
        
        # Prevent unlimited growth
        if len(self.failed_messages) > self.max_size:
            self.failed_messages = self.failed_messages[-self.max_size:]
        
        logger.error(
            "message_added_to_dlq",
            error=str(error),
            message_type=type(message).__name__,
            dlq_size=len(self.failed_messages)
        )
    
    def get_messages(self, limit: Optional[int] = None) -> list:
        """Get messages from DLQ."""
        if limit:
            return self.failed_messages[-limit:]
        return self.failed_messages.copy()
    
    def clear(self) -> int:
        """Clear all messages from DLQ."""
        count = len(self.failed_messages)
        self.failed_messages.clear()
        logger.info("dlq_cleared", message_count=count)
        return count
    
    def size(self) -> int:
        """Get current DLQ size."""
        return len(self.failed_messages)


# Global DLQ instance
_dlq = DeadLetterQueue()


def get_dead_letter_queue() -> DeadLetterQueue:
    """Get the global dead letter queue."""
    return _dlq


class ErrorHandler:
    """Centralized error handling with categorization and recovery."""

    @staticmethod
    def categorize_error(error: Exception) -> str:
        """Categorize error for appropriate handling."""
        error_categories = {
            "database": [
                "asyncpg",
                "sqlalchemy",
                "connection",
                "database"
            ],
            "network": [
                "timeout",
                "connection",
                "socket",
                "unreachable"
            ],
            "rabbitmq": [
                "aio_pika",
                "pika",
                "amqp"
            ],
            "ai_service": [
                "openai",
                "anthropic",
                "groq",
                "rate_limit"
            ],
            "validation": [
                "validation",
                "pydantic",
                "invalid"
            ]
        }
        
        error_str = str(error).lower()
        error_type = type(error).__name__.lower()
        
        for category, keywords in error_categories.items():
            if any(kw in error_str or kw in error_type for kw in keywords):
                return category
        
        return "unknown"
    
    @staticmethod
    def is_retryable(error: Exception) -> bool:
        """Determine if error is retryable."""
        retryable_errors = [
            "timeout",
            "connection",
            "temporary",
            "rate_limit",
            "503",
            "502"
        ]
        
        error_str = str(error).lower()
        return any(keyword in error_str for keyword in retryable_errors)
    
    @staticmethod
    async def handle_error(
        error: Exception,
        context: Dict[str, Any],
        dlq: Optional[DeadLetterQueue] = None
    ) -> Dict[str, Any]:
        """
        Handle error with appropriate strategy.
        
        Args:
            error: Exception to handle
            context: Error context
            dlq: Dead letter queue (optional)
            
        Returns:
            Error handling result
        """
        category = ErrorHandler.categorize_error(error)
        retryable = ErrorHandler.is_retryable(error)
        
        logger.error(
            "error_handled",
            error=str(error),
            category=category,
            retryable=retryable,
            context=context,
            exc_info=True
        )
        
        # Add to DLQ if not retryable
        if not retryable and dlq:
            await dlq.add(
                message=context.get("message"),
                error=error,
                context=context
            )
        
        return {
            "error": str(error),
            "error_type": type(error).__name__,
            "category": category,
            "retryable": retryable,
            "timestamp": datetime.utcnow().isoformat()
        }


async def safe_execute(
    func: Callable,
    *args,
    fallback: Optional[Callable] = None,
    **kwargs
) -> tuple[bool, Any]:
    """
    Execute function safely with error handling.
    
    Args:
        func: Async function to execute
        *args: Function arguments
        fallback: Fallback function if main fails
        **kwargs: Function keyword arguments
        
    Returns:
        Tuple of (success, result)
    """
    try:
        result = await func(*args, **kwargs)
        return True, result
    except Exception as e:
        logger.error(
            "safe_execute_failed",
            function=func.__name__,
            error=str(e),
            exc_info=True
        )
        
        if fallback:
            try:
                result = await fallback(*args, **kwargs)
                return True, result
            except Exception as fallback_error:
                logger.error(
                    "fallback_failed",
                    error=str(fallback_error),
                    exc_info=True
                )
        
        return False, None


class HealthCheck:
    """System health monitoring and checks."""

    def __init__(self):
        """Initialize health check."""
        self.checks: Dict[str, Callable] = {}
    
    def register(self, name: str, check_func: Callable):
        """Register a health check function."""
        self.checks[name] = check_func
    
    async def check_all(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {}
        overall_healthy = True
        
        for name, check_func in self.checks.items():
            try:
                success, message = await check_func()
                results[name] = {
                    "healthy": success,
                    "message": message
                }
                if not success:
                    overall_healthy = False
            except Exception as e:
                results[name] = {
                    "healthy": False,
                    "message": f"Check failed: {str(e)}"
                }
                overall_healthy = False
        
        return {
            "healthy": overall_healthy,
            "checks": results,
            "timestamp": datetime.utcnow().isoformat()
        }


# Global health check instance
_health_check = HealthCheck()


def get_health_check() -> HealthCheck:
    """Get the global health check instance."""
    return _health_check

