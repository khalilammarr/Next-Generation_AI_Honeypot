"""
Centralized Configuration (Thread-Safe, Environment-Driven).
API keys are NEVER hardcoded. If GROQ_API_KEY is missing, LLM calls fail gracefully.
"""

import os
from dotenv import load_dotenv
load_dotenv()

LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "http_honeypot.json")
PERSONALITY_FILE = "/app/personality.txt"

# --- API Configuration (Groq Migration) ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_MODEL_PRIMARY = os.environ.get("GROQ_MODEL_PRIMARY", "llama-3.1-8b-instant")
GROQ_MODEL_SECONDARY = os.environ.get("GROQ_MODEL_SECONDARY", "llama-3.1-8b-instant")

# --- LLM Performance Tuning ---
LLM_TIMEOUT_SECONDS = float(os.environ.get("LLM_TIMEOUT_SECONDS", "5.0"))
LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "512"))
LLM_CONCURRENCY = int(os.environ.get("LLM_CONCURRENCY", "20"))

# --- Cache & Cost Control ---
RESPONSE_CACHE_TTL_SECONDS = int(os.environ.get("RESPONSE_CACHE_TTL_SECONDS", "300"))
MAX_CACHE_ITEMS = int(os.environ.get("MAX_CACHE_ITEMS", "5000"))
MAX_RESPONSE_CHARS = int(os.environ.get("MAX_RESPONSE_CHARS", "15000"))

# --- Behavior Flags ---
THINKING_ENABLED = os.environ.get("THINKING_ENABLED", "false").lower() == "true"
FAST_SCANNER_MODE = os.environ.get("FAST_SCANNER_MODE", "true").lower() == "true"
METRICS_LOG_EVERY = int(os.environ.get("METRICS_LOG_EVERY", "50"))

# --- Rate Limiting ---
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))

# --- Apache Identity Masquerade ---
FAKE_HEADERS = {
    "Server": "Apache/2.4.7 (Ubuntu)",
    "X-Powered-By": "PHP/5.5.9-1ubuntu4.25",
    "Connection": "keep-alive",
}
