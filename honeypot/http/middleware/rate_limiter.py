"""
IP-Based Sliding Window Rate Limiter.
Protects the LLM API budget from brute-force token exhaustion.
Returns a realistic Apache 429 page when an attacker exceeds the threshold.
"""

import time
from typing import Dict, List

from fastapi import Request
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import FAKE_HEADERS


class IPRateLimiter(BaseHTTPMiddleware):
    # Shared across middleware instances in the same process.
    _shared_hits: Dict[str, List[float]] = {}

    def __init__(self, app, max_requests: int = 30, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = self.__class__._shared_hits

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "0.0.0.0"
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune expired timestamps for this IP
        timestamps = [t for t in self._hits.get(ip, []) if t > cutoff]

        if len(timestamps) >= self.max_requests:
            return HTMLResponse(
                content=(
                    "<html><head><title>429 Too Many Requests</title></head>"
                    "<body><h1>Too Many Requests</h1>"
                    "<p>You have sent too many requests in a given amount of time.</p>"
                    "<hr><address>Apache/2.4.7 (Ubuntu) Server</address>"
                    "</body></html>"
                ),
                status_code=429,
                headers={**FAKE_HEADERS, "Retry-After": str(self.window_seconds)},
            )

        timestamps.append(now)
        self._hits[ip] = timestamps

        # Periodic cleanup: remove IPs with no recent activity
        if len(self._hits) > 10000:
            self._hits = {
                k: [t for t in v if t > cutoff]
                for k, v in self._hits.items()
                if any(t > cutoff for t in v)
            }

        return await call_next(request)
