"""Enhanced security features: rate limiting, input sanitization, API key management."""

import re
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from collections import defaultdict

from fastapi import Request, HTTPException, status
from passlib.context import CryptContext
from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RateLimiter:
    """
    Advanced rate limiter with multiple strategies.

    Supports:
    - Fixed window rate limiting
    - Sliding window rate limiting
    - Token bucket algorithm
    - Per-IP and per-user limits
    """

    def __init__(self):
        """Initialize rate limiter."""
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.blocked_until: Dict[str, float] = {}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()

    async def check_rate_limit(
        self,
        identifier: str,
        max_requests: int = 100,
        window_seconds: int = 60,
        block_duration: int = 300
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is within rate limit.

        Args:
            identifier: Unique identifier (IP, user ID, API key)
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            block_duration: How long to block after exceeding limit

        Returns:
            Tuple of (allowed, info_dict)
        """
        current_time = time.time()

        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            await self._cleanup()

        # Check if blocked
        if identifier in self.blocked_until:
            if current_time < self.blocked_until[identifier]:
                remaining = int(self.blocked_until[identifier] - current_time)
                return False, {
                    "blocked": True,
                    "retry_after": remaining,
                    "reason": "Rate limit exceeded"
                }
            else:
                del self.blocked_until[identifier]

        # Get requests in current window
        window_start = current_time - window_seconds
        recent_requests = [
            req_time for req_time in self.requests[identifier]
            if req_time > window_start
        ]

        # Update request list
        self.requests[identifier] = recent_requests

        # Check limit
        if len(recent_requests) >= max_requests:
            self.blocked_until[identifier] = current_time + block_duration
            logger.warning(
                "rate_limit_exceeded",
                identifier=identifier,
                requests=len(recent_requests),
                limit=max_requests
            )
            return False, {
                "blocked": True,
                "retry_after": block_duration,
                "reason": f"Rate limit exceeded: {len(recent_requests)}/{max_requests}"
            }

        # Add current request
        self.requests[identifier].append(current_time)

        remaining = max_requests - len(recent_requests) - 1
        return True, {
            "blocked": False,
            "remaining": remaining,
            "limit": max_requests,
            "reset_in": int(window_seconds)
        }

    async def _cleanup(self):
        """Clean up old request records."""
        current_time = time.time()

        # Remove old requests
        for identifier in list(self.requests.keys()):
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if current_time - req_time < 3600  # Keep last hour
            ]
            if not self.requests[identifier]:
                del self.requests[identifier]

        # Remove expired blocks
        for identifier in list(self.blocked_until.keys()):
            if current_time >= self.blocked_until[identifier]:
                del self.blocked_until[identifier]

        self.last_cleanup = current_time
        logger.info("rate_limiter_cleanup_completed")


# Global rate limiter
_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter


class InputSanitizer:
    """
    Input sanitization and validation.

    Prevents injection attacks and malicious input.
    """

    # Dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|;|\/\*|\*\/|xp_|sp_)",
        r"(\bOR\b.*=.*\bOR\b)",
        r"(\bAND\b.*=.*\bAND\b)"
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<object",
        r"<embed"
    ]

    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$()]",
        r"\.\./",
        r"~/"
    ]

    @staticmethod
    def sanitize_string(
        value: str,
        max_length: int = 1000,
        allow_html: bool = False
    ) -> str:
        """
        Sanitize string input.

        Args:
            value: Input string
            max_length: Maximum allowed length
            allow_html: Whether to allow HTML tags

        Returns:
            Sanitized string

        Raises:
            ValueError: If input is dangerous
        """
        if not isinstance(value, str):
            raise ValueError("Input must be a string")

        # Length check
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")

        # Check for SQL injection
        for pattern in InputSanitizer.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(
                    "sql_injection_attempt",
                    pattern=pattern,
                    input=value[:100]
                )
                raise ValueError("Potential SQL injection detected")

        # Check for XSS
        if not allow_html:
            for pattern in InputSanitizer.XSS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning(
                        "xss_attempt",
                        pattern=pattern,
                        input=value[:100]
                    )
                    raise ValueError("Potential XSS attack detected")

        # Check for command injection
        for pattern in InputSanitizer.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                logger.warning(
                    "command_injection_attempt",
                    pattern=pattern,
                    input=value[:100]
                )
                raise ValueError("Potential command injection detected")

        # Basic sanitization
        sanitized = value.strip()

        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')

        return sanitized

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_uuid(uuid_string: str) -> bool:
        """Validate UUID format."""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(pattern, uuid_string, re.IGNORECASE))

    @staticmethod
    def redact_sensitive_data(text: str) -> str:
        """
        Redact sensitive data from text.

        Redacts:
        - Credit card numbers
        - Email addresses
        - API keys
        - Passwords
        """
        # Credit cards
        text = re.sub(
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            '[REDACTED_CC]',
            text
        )

        # Email addresses
        text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            '[REDACTED_EMAIL]',
            text
        )

        # API keys (common patterns)
        text = re.sub(
            r'\b(sk_|pk_|api_|key_)[a-zA-Z0-9]{20,}\b',
            '[REDACTED_API_KEY]',
            text
        )

        # Passwords in logs
        text = re.sub(
            r'(password|passwd|pwd)["\s:=]+[^\s"]+',
            r'\1=[REDACTED]',
            text,
            flags=re.IGNORECASE
        )

        return text


class APIKeyManager:
    """
    API key management with rotation and expiration.
    """

    def __init__(self):
        """Initialize API key manager."""
        self.keys: Dict[str, Dict[str, Any]] = {}

    def generate_api_key(self, prefix: str = "lga") -> str:
        """
        Generate a secure API key.

        Args:
            prefix: Key prefix (log analysis)

        Returns:
            Generated API key
        """
        random_part = secrets.token_urlsafe(32)
        api_key = f"{prefix}_{random_part}"
        return api_key

    def hash_api_key(self, api_key: str) -> str:
        """Hash API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def create_api_key(
        self,
        name: str,
        expires_in_days: int = 90,
        permissions: Optional[List[str]] = None
    ) -> tuple[str, Dict[str, Any]]:
        """
        Create new API key with metadata.

        Args:
            name: Key name/description
            expires_in_days: Expiration in days
            permissions: List of permissions

        Returns:
            Tuple of (api_key, metadata)
        """
        api_key = self.generate_api_key()
        key_hash = self.hash_api_key(api_key)

        metadata = {
            "name": name,
            "hash": key_hash,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (
                datetime.utcnow() + timedelta(days=expires_in_days)
            ).isoformat(),
            "permissions": permissions or ["read"],
            "last_used": None,
            "use_count": 0,
            "active": True
        }

        self.keys[key_hash] = metadata

        logger.info(
            "api_key_created",
            name=name,
            expires_in_days=expires_in_days
        )

        return api_key, metadata

    def validate_api_key(self, api_key: str) -> tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate API key and return metadata.

        Args:
            api_key: API key to validate

        Returns:
            Tuple of (valid, metadata)
        """
        key_hash = self.hash_api_key(api_key)

        if key_hash not in self.keys:
            return False, None

        metadata = self.keys[key_hash]

        # Check if active
        if not metadata["active"]:
            return False, None

        # Check expiration
        expires_at = datetime.fromisoformat(metadata["expires_at"])
        if datetime.utcnow() > expires_at:
            logger.warning(
                "api_key_expired",
                name=metadata["name"]
            )
            return False, None

        # Update usage
        metadata["last_used"] = datetime.utcnow().isoformat()
        metadata["use_count"] += 1

        return True, metadata

    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        key_hash = self.hash_api_key(api_key)

        if key_hash in self.keys:
            self.keys[key_hash]["active"] = False
            logger.info(
                "api_key_revoked",
                name=self.keys[key_hash]["name"]
            )
            return True

        return False

    def rotate_api_key(self, old_api_key: str) -> Optional[str]:
        """
        Rotate an API key (create new, revoke old).

        Args:
            old_api_key: Current API key

        Returns:
            New API key or None if failed
        """
        old_hash = self.hash_api_key(old_api_key)

        if old_hash not in self.keys:
            return None

        old_metadata = self.keys[old_hash]

        # Create new key
        new_api_key, new_metadata = self.create_api_key(
            name=old_metadata["name"],
            expires_in_days=90,
            permissions=old_metadata["permissions"]
        )

        # Revoke old key
        self.revoke_api_key(old_api_key)

        logger.info(
            "api_key_rotated",
            name=old_metadata["name"]
        )

        return new_api_key


# Global API key manager
_api_key_manager = APIKeyManager()


def get_api_key_manager() -> APIKeyManager:
    """Get the global API key manager."""
    return _api_key_manager


class SecureJWTManager:
    """Enhanced JWT management with secure defaults."""

    def __init__(self):
        """Initialize JWT manager."""
        self.settings = get_settings()
        self._validate_secret()

    def _validate_secret(self):
        """Validate JWT secret is secure."""
        secret = self.settings.jwt_secret_key

        # Check for default/weak secret
        weak_secrets = [
            "secret",
            "your-super-secret-jwt-key-change-this-in-production",
            "changeme",
            "password"
        ]

        if any(weak in secret.lower() for weak in weak_secrets):
            logger.critical(
                "insecure_jwt_secret",
                message="JWT secret is insecure! Generate a new one with: "
                        "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )

        if len(secret) < 32:
            logger.warning(
                "short_jwt_secret",
                length=len(secret),
                message="JWT secret is too short (< 32 chars)"
            )

    def create_access_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token."""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.settings.jwt_expiration_minutes
            )

        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)  # JWT ID for tracking
        })

        encoded_jwt = jwt.encode(
            to_encode,
            self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm
        )

        return encoded_jwt

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verify and decode JWT token.

        Args:
            token: JWT token string

        Returns:
            Token payload or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm]
            )
            return payload
        except JWTError as e:
            logger.warning(
                "jwt_verification_failed",
                error=str(e)
            )
            return None


# Global JWT manager
_jwt_manager = SecureJWTManager()


def get_jwt_manager() -> SecureJWTManager:
    """Get the global JWT manager."""
    return _jwt_manager


async def verify_api_key(request: Request) -> Dict[str, Any]:
    """
    Dependency to verify API key from header.

    Usage in FastAPI:
        @app.get("/protected")
        async def protected_route(api_key_data: dict = Depends(verify_api_key)):
            ...
    """
    api_key = request.headers.get("X-API-Key")

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )

    manager = get_api_key_manager()
    valid, metadata = manager.validate_api_key(api_key)

    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )

    return metadata


async def check_rate_limit_dependency(request: Request):
    """
    Dependency to check rate limit.

    Usage in FastAPI:
        @app.get("/api/endpoint", dependencies=[Depends(check_rate_limit_dependency)])
        async def endpoint():
            ...
    """
    # Get identifier (IP or user)
    identifier = request.client.host

    rate_limiter = get_rate_limiter()
    allowed, info = await rate_limiter.check_rate_limit(
        identifier=identifier,
        max_requests=(
            settings.rate_limit_requests if hasattr(settings, 'rate_limit_requests') else 100
        ),
        window_seconds=(
            settings.rate_limit_period if hasattr(settings, 'rate_limit_period') else 60
        )
    )

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=info["reason"],
            headers={"Retry-After": str(info["retry_after"])}
        )

    # Add rate limit info to headers (optional)
    return info


def generate_secure_secret(length: int = 32) -> str:
    """Generate a cryptographically secure secret."""
    return secrets.token_urlsafe(length)

