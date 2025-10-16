"""Security utilities for JWT authentication and authorization."""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SecurityManager:
    """Manages JWT authentication and security operations."""

    def __init__(self) -> None:
        """Initialize security manager."""
        self.settings = get_settings()

    def create_access_token(
        self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.

        Args:
            data: Data to encode in the token
            expires_delta: Optional expiration time delta

        Returns:
            Encoded JWT token string
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.settings.jwt_expiration_minutes)

        to_encode.update({"exp": expire, "iat": datetime.utcnow()})

        encoded_jwt = jwt.encode(
            to_encode, self.settings.jwt_secret_key, algorithm=self.settings.jwt_algorithm
        )

        logger.info("access_token_created", expires_at=expire.isoformat())
        return encoded_jwt

    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm],
            )
            return payload
        except JWTError as e:
            logger.warning("jwt_decode_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify password against hashed password.

        Args:
            plain_password: Plain text password
            hashed_password: Hashed password

        Returns:
            True if password matches, False otherwise
        """
        return pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """
        Hash password.

        Args:
            password: Plain text password

        Returns:
            Hashed password
        """
        return pwd_context.hash(password)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> Dict[str, Any]:
    """
    Dependency to get current authenticated user from JWT token.

    Args:
        credentials: HTTP authorization credentials

    Returns:
        User information from token

    Raises:
        HTTPException: If authentication fails
    """
    security_manager = SecurityManager()
    token = credentials.credentials

    try:
        payload = security_manager.decode_token(token)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except Exception as e:
        logger.error("authentication_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def verify_api_gateway_token(token: str) -> bool:
    """
    Verify token signed by API Gateway.

    Args:
        token: JWT token from API Gateway

    Returns:
        True if token is valid, False otherwise
    """
    settings = get_settings()

    if not settings.api_gateway_public_key:
        logger.warning("api_gateway_public_key_not_configured")
        return False

    try:
        jwt.decode(
            token,
            settings.api_gateway_public_key,
            algorithms=["RS256"],
        )
        return True
    except JWTError as e:
        logger.warning("api_gateway_token_validation_failed", error=str(e))
        return False
