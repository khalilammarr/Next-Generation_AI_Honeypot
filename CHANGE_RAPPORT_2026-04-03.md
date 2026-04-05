# Change Rapport - 2026-04-03

## Scope

This rapport summarizes the HTTP honeypot refactor and latency/security hardening applied in this project.

## Executive Summary

The project moved from a monolithic HTTP honeypot implementation to a modular architecture with explicit routing, policy, caching, and LLM orchestration layers. The runtime was tuned for lower and more stable latency by adding deterministic fast responses, fallback behavior, bounded cache, and concurrency controls.

## What Changed

### 1) HTTP Service Refactor (Structure)

The original large `agent.py` was split into focused modules:

- `honeypot/http/agent.py`: Thin launcher entrypoint.
- `honeypot/http/app_main.py`: FastAPI app + route handler + event metadata assembly.
- `honeypot/http/llm_orchestrator.py`: LLM model routing, timeout handling, semaphore-based concurrency, fallback chain.
- `honeypot/http/response_policy.py`: Request classification, cache key generation, fallback templates, token budgets, output sanitization.
- `honeypot/http/cache_store.py`: TTL cache abstraction.
- `honeypot/http/event_logger.py`: JSON log writer.
- `honeypot/http/settings.py`: Environment-driven configuration.
- `honeypot/http/__init__.py`: Package marker.

### 2) Latency and Throughput Enhancements

Implemented in HTTP stack:

- Deterministic fast-path for scanner/sensitive traffic and common endpoints.
- Dual-model fallback routing (`primary` -> `secondary` -> deterministic fallback).
- Strict timeout control for LLM calls.
- Bounded in-memory TTL cache to absorb repetitive scanning bursts.
- Semaphore-limited LLM concurrency to avoid overload collapse.
- Adaptive token budget by request class.
- Output truncation/sanitization to prevent oversized payload delays.

### 3) Security and Secrets Hardening

- Removed hardcoded API usage from HTTP runtime and switched to environment variables.
- Updated Cowrie LLM block to remove embedded key and use placeholder for secret injection.
- Added `.env.example` as canonical runtime configuration template.

### 4) Deployment Configuration Updates

`docker-compose.yml` now exposes tuning knobs for HTTP and SSH behavior:

- API and model env vars.
- Timeout and token caps.
- Cache and concurrency controls.
- Scanner-mode optimization switch.

### 5) Build/Dependency Updates

- `honeypot/http/requirements.txt` switched to `openai` SDK usage.
- `honeypot/http/Dockerfile` now installs from requirements and copies the full HTTP module directory.

## Operational Impact

### Expected Improvements

- Lower p95 response latency under scanner-heavy traffic.
- Better resilience during model slowness/outages via deterministic fallback.
- Better maintainability and extensibility due to modular code ownership.
- Better observability through enriched event fields (`route_strategy`, `model_name`, `cache_hit`, `timeout_fallback`, `response_time_ms`).

### Runtime Controls You Can Tune Quickly

Use `.env` values (from `.env.example`) to tune behavior without code edits:

- `NVIDIA_MODEL_PRIMARY`
- `NVIDIA_MODEL_SECONDARY`
- `LLM_TIMEOUT_SECONDS`
- `LLM_MAX_TOKENS`
- `LLM_CONCURRENCY`
- `RESPONSE_CACHE_TTL_SECONDS`
- `MAX_CACHE_ITEMS`
- `MAX_RESPONSE_CHARS`
- `FAST_SCANNER_MODE`

## Validation Performed

- Python compile validation for all HTTP modules succeeded.
- Editor diagnostics reported no errors on changed/refactored files.

## Notes / Follow-Up

1. Rotate any previously exposed NVIDIA API keys.
2. Add unit tests for `response_policy.py` and `cache_store.py`.
3. Add a simple benchmark script to measure p50/p95 latency before and after model changes.
4. Consider extending the same modular pattern to SSH-side custom logic.
