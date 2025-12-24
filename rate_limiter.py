import time
import asyncio
from collections import defaultdict
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimiter:
    """
    A simple in-memory rate limiter using the token bucket algorithm.
    """
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, Tuple[float, float]] = defaultdict(lambda: (0.0, 0.0))  # (tokens, last_request_time)
        self._lock = asyncio.Lock()

    async def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request from the given identifier is allowed based on rate limits.

        Args:
            identifier: A unique identifier for the client (e.g., IP address)

        Returns:
            bool: True if the request is allowed, False otherwise
        """
        async with self._lock:
            current_time = time.time()
            tokens, last_time = self.requests[identifier]

            # Add tokens based on time passed
            tokens = min(self.max_requests, tokens + (current_time - last_time) * (self.max_requests / self.window_seconds))

            if tokens >= 1:
                # Consume one token
                self.requests[identifier] = (tokens - 1, current_time)
                return True
            else:
                # Not enough tokens, update last time to current time so tokens can recover
                self.requests[identifier] = (tokens, current_time)
                return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that implements rate limiting.
    """
    def __init__(self, app, rate_limiter: RateLimiter | None = None):
        super().__init__(app)
        self.rate_limiter = rate_limiter or RateLimiter()

    async def dispatch(self, request: Request, call_next):
        # bypass whitelist
        whitelist_paths = ["/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"]
        if request.url.path in whitelist_paths:
            return await call_next(request)
        # bypass OPTIONS requests for CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)
        authorization: str = request.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            authorization = authorization[7:].strip()
        if not (authorization and len(authorization) > 0):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")

        # Check if request is allowed
        if not await self.rate_limiter.is_allowed(authorization):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(self.rate_limiter.window_seconds)}
            )

        # Proceed with the request
        response = await call_next(request)
        return response