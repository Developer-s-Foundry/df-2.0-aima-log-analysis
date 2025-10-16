"""Simple external auth service integration."""

from typing import Any, Dict, Optional

import httpx
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
security = HTTPBearer()


async def validate_token_with_external_service(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate token with external auth service.

    Args:
        token: JWT token to validate

    Returns:
        User data if valid, None if invalid
    """
    settings = get_settings()

    if not settings.auth_service_url:
        return None

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                f"{settings.auth_service_url}/validate-token",
                json={"token": token},
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                logger.info("token_validated_with_external_service", user_id=data.get("user_id"))
                return data
            else:
                logger.warning("external_auth_validation_failed", status_code=response.status_code)
                return None

    except Exception as e:
        logger.error("external_auth_error", error=str(e))
        return None


def validate_local_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate JWT token locally.

    Args:
        token: JWT token to validate

    Returns:
        Token payload if valid, None if invalid
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        logger.info("token_validated_locally", user_id=payload.get("sub"))
        return payload
    except JWTError as e:
        logger.warning("local_jwt_validation_failed", error=str(e))
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> Dict[str, Any]:
    """
    Dependency to get current authenticated user.

    This function:
    1. First tries to validate with external auth service (if URL configured)
    2. Falls back to local JWT validation
    3. Raises 401 if both fail

    Args:
        credentials: HTTP authorization credentials

    Returns:
        User information from token

    Raises:
        HTTPException: If authentication fails
    """
    token = credentials.credentials
    settings = get_settings()

    # Try external auth service first (if configured)
    if settings.auth_service_url:
        user_data = await validate_token_with_external_service(token)
        if user_data:
            return user_data

    # Fallback to local validation
    user_data = validate_local_token(token)
    if user_data:
        return user_data

    # If both fail, raise authentication error
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
) -> Optional[Dict[str, Any]]:
    """
    Optional authentication dependency.

    Returns user data if authenticated, None if not.
    Useful for endpoints that work with or without authentication.

    Args:
        credentials: Optional HTTP authorization credentials

    Returns:
        User information if authenticated, None otherwise
    """
    if not credentials:
        return None

    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None


def create_test_token(user_id: str = "test-user", roles: list = None) -> str:
    """
    Create a test JWT token for development/testing.

    Args:
        user_id: User ID
        roles: List of user roles

    Returns:
        JWT token string
    """
    from datetime import datetime, timedelta

    settings = get_settings()

    payload = {
        "sub": user_id,
        "user_id": user_id,
        "roles": roles or ["user"],
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=settings.jwt_expiration_minutes),
    }

    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    logger.info("test_token_created", user_id=user_id)
    return token
