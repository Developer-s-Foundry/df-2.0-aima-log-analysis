"""Security middleware for request validation and protection."""

import time
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.logging import get_logger
from app.core.security_enhanced import InputSanitizer, get_rate_limiter

logger = get_logger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security middleware.

    Features:
    - Rate limiting
    - Input sanitization
    - Security headers
    - Request validation
    """

    def __init__(self, app, enable_rate_limiting: bool = True):
        """Initialize security middleware."""
        super().__init__(app)
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limiter = get_rate_limiter()
        self.sanitizer = InputSanitizer()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with security checks."""
        start_time = time.time()

        try:
            # 1. Rate limiting
            if self.enable_rate_limiting and not self._is_exempt_from_rate_limit(request):
                allowed, info = await self._check_rate_limit(request)
                if not allowed:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "status_code": 429,
                            "message": "Rate limit exceeded",
                            "retry_after": info.get("retry_after", 60),
                        },
                        headers={"Retry-After": str(info.get("retry_after", 60))},
                    )

            # 2. Input validation (for query params)
            if not await self._validate_input(request):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "status_code": 400,
                        "message": "Invalid or potentially malicious input detected",
                    },
                )

            # 3. Process request
            response = await call_next(request)

            # 4. Add security headers
            response = self._add_security_headers(response)

            # 5. Log request
            duration = time.time() - start_time
            logger.info(
                "security_middleware_processed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration=f"{duration:.3f}s",
                client=request.client.host if request.client else "unknown",
            )

            return response

        except Exception as e:
            logger.error(
                "security_middleware_error", error=str(e), path=request.url.path, exc_info=True
            )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status_code": 500, "message": "Internal server error"},
            )

    async def _check_rate_limit(self, request: Request) -> tuple[bool, dict]:
        """Check rate limit for request."""
        # Use IP as identifier (could also use user ID if authenticated)
        identifier = request.client.host if request.client else "unknown"

        # Different limits for different endpoints
        if "/api/" in request.url.path:
            max_requests = 100
            window = 60
        else:
            max_requests = 1000
            window = 60

        return await self.rate_limiter.check_rate_limit(
            identifier=identifier, max_requests=max_requests, window_seconds=window
        )

    async def _validate_input(self, request: Request) -> bool:
        """Validate request input."""
        try:
            # Validate query parameters
            for key, value in request.query_params.items():
                if isinstance(value, str):
                    self.sanitizer.sanitize_string(value, max_length=500)

            # Validate path parameters
            for key, value in request.path_params.items():
                if isinstance(value, str):
                    self.sanitizer.sanitize_string(value, max_length=200)

            return True

        except ValueError as e:
            logger.warning(
                "input_validation_failed",
                error=str(e),
                path=request.url.path,
                params=dict(request.query_params),
            )
            return False

    def _add_security_headers(self, response: Response) -> Response:
        """Add security headers to response."""
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HTTPS enforcement (if in production)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response

    def _is_exempt_from_rate_limit(self, request: Request) -> bool:
        """Check if request is exempt from rate limiting."""
        exempt_paths = ["/health", "/health/", "/docs", "/redoc", "/openapi.json"]
        return request.url.path in exempt_paths


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Validate request structure and content."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Validate request."""
        # Validate Content-Type for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if not content_type.startswith("application/json"):
                if request.url.path.startswith("/api/"):
                    return JSONResponse(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        content={
                            "status_code": 415,
                            "message": "Content-Type must be application/json",
                        },
                    )

        # Validate Content-Length
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                max_size = 10 * 1024 * 1024  # 10MB
                if length > max_size:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "status_code": 413,
                            "message": f"Request body too large (max {max_size} bytes)",
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)
