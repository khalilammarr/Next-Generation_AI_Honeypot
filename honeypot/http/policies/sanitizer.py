"""
Prompt Injection Sanitizer & Output Redactor.
Prevents attackers from weaponizing the LLM against the honeypot operator.

Input:  Strips injection attempts from attacker-controlled URL paths.
Output: Redacts accidental API key leaks and AI self-disclosure.
"""

import re
from typing import List

# --- Input Sanitization (Attacker -> LLM) ---

INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore.*(previous|above|all).*instruction", re.IGNORECASE),
    re.compile(r"(system|internal)\s*prompt", re.IGNORECASE),
    re.compile(r"(print|show|reveal|display|dump).*(api.?key|secret|password|token|config)", re.IGNORECASE),
    re.compile(r"you\s+are\s+(not\s+)?a", re.IGNORECASE),
    re.compile(r"(act|respond|behave)\s+(as|like)", re.IGNORECASE),
    re.compile(r"forget.*everything", re.IGNORECASE),
    re.compile(r"(new|override|replace)\s*(role|instruction|system)", re.IGNORECASE),
]


def sanitize_path(raw_path: str, max_length: int = 256) -> str:
    """
    Neutralize prompt-injection attempts hidden in URL paths.
    Returns a safe, truncated path. If injection detected, returns a decoy path.
    """
    path = raw_path[:max_length]

    for pattern in INJECTION_PATTERNS:
        if pattern.search(path):
            return "/403-forbidden"

    # Strip control characters and null bytes
    path = re.sub(r"[\x00-\x1f\x7f]", "", path)
    return path


def sanitize_user_agent(raw_ua: str, max_length: int = 512) -> str:
    """Truncate and clean the User-Agent header."""
    ua = (raw_ua or "unknown")[:max_length]
    ua = re.sub(r"[\x00-\x1f\x7f]", "", ua)
    return ua


# --- Output Sanitization (LLM -> Attacker) ---

SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"nvapi-[A-Za-z0-9_-]{20,}"),       # NVIDIA NIM keys
    re.compile(r"sk-[A-Za-z0-9]{20,}"),             # OpenAI keys
    re.compile(r"AKIA[A-Z0-9]{16}"),                # AWS Access Key IDs
    re.compile(r"xox[bprs]-[A-Za-z0-9-]+"),         # Slack tokens
    re.compile(r"ghp_[A-Za-z0-9]{36}"),             # GitHub PATs
]

DISCLOSURE_PATTERNS: List[re.Pattern] = [
    re.compile(r"honeypot", re.IGNORECASE),
    re.compile(r"I('m| am) an? (AI|language model|LLM|assistant|chatbot)", re.IGNORECASE),
    re.compile(r"(artificial|simulated|fake)\s*(intelligence|server|system)", re.IGNORECASE),
    re.compile(r"as an AI", re.IGNORECASE),
    re.compile(r"I cannot (help|assist)", re.IGNORECASE),
]


def redact_output(content: str) -> str:
    """
    Scrub LLM output for accidental secret leaks or AI self-disclosure.
    This is the LAST line of defense before data reaches the attacker.
    """
    text = content

    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)

    for pattern in DISCLOSURE_PATTERNS:
        text = pattern.sub("", text)

    return text.strip()
