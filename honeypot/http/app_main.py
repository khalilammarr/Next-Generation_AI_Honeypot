"""
GhostNet HTTP Honeypot — Enterprise Application Hub.
This is the FastAPI entry point. It wires together:
  - Rate Limiter Middleware (Layer 1 defense)
  - Static Deception Routes (zero-cost traps)
  - Dynamic AI Catch-All (LLM-powered deception via an OpenAI-compatible API, Groq by default)
"""

import logging
import os

from fastapi import FastAPI

from core.config import LOG_DIR, PERSONALITY_FILE, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from middleware.rate_limiter import IPRateLimiter
from api.routers import system, catch_all

# --- Logging Setup ---
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ghostnet")

if os.path.exists(PERSONALITY_FILE):
    logger.info("Personality file loaded from %s", PERSONALITY_FILE)
else:
    logger.warning("Personality file missing at %s; fallback prompt will be used", PERSONALITY_FILE)

# --- FastAPI Application ---
app = FastAPI(
    title="GhostNet HTTP Honeypot",
    docs_url=None,     # Hide Swagger UI
    redoc_url=None,    # Hide ReDoc
    openapi_url=None,  # Hide OpenAPI schema
)

# --- Layer 1: Rate Limiting Middleware ---
app.add_middleware(
    IPRateLimiter,
    max_requests=RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

# --- Static Routes (mounted FIRST — higher priority) ---
app.include_router(system.router)

# --- Dynamic AI Catch-All (mounted LAST — lowest priority) ---
app.include_router(catch_all.router)

logger.info("GhostNet HTTP Honeypot initialized. Rate limit: %d req/%ds",
            RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
