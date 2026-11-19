import asyncio
import logging

from openai import OpenAI

from core.cache import TTLCache
from policies.response_policy import (
    cache_key,
    classify_request,
    fallback_html,
    sanitize_response,
    should_skip_llm,
    token_budget,
)
from policies.sanitizer import redact_output, sanitize_path, sanitize_user_agent
from policies.mime_router import build_format_hint
from core.config import (
    LLM_CONCURRENCY,
    LLM_MAX_TOKENS,
    LLM_TIMEOUT_SECONDS,
    METRICS_LOG_EVERY,
    GROQ_API_KEY,
    GROQ_BASE_URL,
    GROQ_MODEL_PRIMARY,
    GROQ_MODEL_SECONDARY,
    PERSONALITY_FILE,
    RESPONSE_CACHE_TTL_SECONDS,
    MAX_CACHE_ITEMS,
    THINKING_ENABLED,
)


class LLMOrchestrator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        if not GROQ_API_KEY:
            self.logger.warning("GROQ_API_KEY is empty; LLM calls will fail and fallback routing will be used.")

        self.client = OpenAI(base_url=GROQ_BASE_URL, api_key=GROQ_API_KEY, timeout=LLM_TIMEOUT_SECONDS)
        self.system_prompt = self._load_system_prompt()
        self.cache = TTLCache(ttl_seconds=RESPONSE_CACHE_TTL_SECONDS, max_items=MAX_CACHE_ITEMS)
        self.semaphore = asyncio.Semaphore(LLM_CONCURRENCY)
        self.metrics = {
            "total_requests": 0,
            "cache_hits": 0,
            "deterministic_fast": 0,
            "llm_success": 0,
            "llm_timeout": 0,
            "llm_error": 0,
            "fallback": 0,
        }

    def _bump_metric(self, key: str) -> None:
        self.metrics[key] = self.metrics.get(key, 0) + 1

    def _log_metrics_if_due(self) -> None:
        if self.metrics["total_requests"] % METRICS_LOG_EVERY == 0:
            self.logger.info("HTTP LLM routing metrics snapshot: %s", self.metrics)

    def metrics_snapshot(self) -> dict:
        return dict(self.metrics)

    def _load_system_prompt(self) -> str:
        try:
            with open(PERSONALITY_FILE, "r") as f:
                return f.read()
        except Exception as exc:
            self.logger.warning("Failed to load system prompt from %s: %s", PERSONALITY_FILE, exc)
            return "You are a vulnerable legacy web server."

    def _query_ai(self, path: str, method: str, user_agent: str, model_name: str, classification: str) -> str:
        # Sanitize attacker-controlled inputs before injecting into prompt
        safe_path = sanitize_path(path)
        safe_ua = sanitize_user_agent(user_agent)
        format_hint = build_format_hint(safe_path)

        prompt = (
            f"[KERNEL_CMD: PROCESS {method} {safe_path} UA: {safe_ua}. {format_hint}]"
        )

        # Build API call params — only add thinking control for models that support it
        api_params = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "top_p": 1.0,
            "max_tokens": min(token_budget(classification), LLM_MAX_TOKENS),
            "stream": False,
        }

        # Inject per-family reasoning controls to avoid hidden chain leakage.
        lowered = model_name.lower()
        if "nemotron" in lowered:
            api_params["extra_body"] = {
                "chat_template_kwargs": {"enable_thinking": THINKING_ENABLED},
                "reasoning_budget": 0 if not THINKING_ENABLED else token_budget(classification),
            }
        elif "glm" in lowered:
            api_params["extra_body"] = {
                "chat_template_kwargs": {
                    "enable_thinking": THINKING_ENABLED,
                    "clear_thinking": True,
                }
            }
        elif any(x in lowered for x in ["deepseek", "minimax"]):
            api_params["extra_body"] = {"chat_template_kwargs": {"thinking": THINKING_ENABLED}}

        completion = self.client.chat.completions.create(**api_params)
        raw_content = completion.choices[0].message.content or ""

        import re
        # Remove reasoning tags (<thought>/<think>) including malformed/unclosed variants.
        raw_content = re.sub(r"<(thought|think)>.*?(</\1>|$)", "", raw_content, flags=re.DOTALL).strip()
        
        sanitized = sanitize_response(raw_content)
        # Final security gate: redact any accidental key leaks or AI self-disclosure
        return redact_output(sanitized)

    async def get_response(self, path: str, method: str, user_agent: str):
        """
        Returns: (response_text, source, model_used, was_cached, was_fallback)
        """
        self._bump_metric("total_requests")

        classification = classify_request(path, method, user_agent)
        key = cache_key(path, method, user_agent)

        cached = self.cache.get(key)
        if cached:
            self._bump_metric("cache_hits")
            self._log_metrics_if_due()
            return cached, "cache", "none", True, False

        if should_skip_llm(path, classification):
            fast_response = fallback_html(path, classification)
            self.cache.set(key, fast_response)
            self._bump_metric("deterministic_fast")
            self._log_metrics_if_due()
            return fast_response, "deterministic_fast", "none", False, False

        for model_name in [GROQ_MODEL_PRIMARY, GROQ_MODEL_SECONDARY]:
            if not model_name:
                continue

            try:
                async with self.semaphore:
                    response_text = await asyncio.wait_for(
                        asyncio.to_thread(
                            self._query_ai,
                            path,
                            method,
                            user_agent,
                            model_name,
                            classification,
                        ),
                        timeout=LLM_TIMEOUT_SECONDS,
                    )

                if response_text:
                    self.cache.set(key, response_text)
                    self._bump_metric("llm_success")
                    self._log_metrics_if_due()
                    return response_text, "llm", model_name, False, False
            except asyncio.TimeoutError:
                self._bump_metric("llm_timeout")
                self.logger.info("LLM timeout on model %s for %s %s", model_name, method, path)
                continue
            except Exception as exc:
                self._bump_metric("llm_error")
                self.logger.warning("LLM call failed on model %s for %s %s: %s", model_name, method, path, exc)
                continue

        fallback = fallback_html(path, classification)
        self.cache.set(key, fallback)
        self._bump_metric("fallback")
        self._log_metrics_if_due()
        return fallback, "fallback", "none", False, True
