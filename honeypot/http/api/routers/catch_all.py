"""
Catch-All Dynamic Router.
Every path not handled by static routes is intercepted here.
The LLMOrchestrator generates a realistic deception response.
"""

import datetime
import random

from fastapi import APIRouter, Request, BackgroundTasks
from fastapi.responses import HTMLResponse

from core.config import FAKE_HEADERS
from core.logger import log_event
from services.llm_orchestrator import LLMOrchestrator
from policies.mime_router import resolve_mime
from policies.sanitizer import sanitize_path, sanitize_user_agent

router = APIRouter()
orchestrator = LLMOrchestrator()


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str, background_tasks: BackgroundTasks):
    raw_path = f"/{path}"
    safe_path = sanitize_path(raw_path)
    safe_ua = sanitize_user_agent(request.headers.get("user-agent", "unknown"))

    # Log event for Wazuh SIEM
    try:
        body = await request.body()
        body_text = body.decode("utf-8", errors="replace")[:2048]
    except Exception:
        body_text = ""

    event = {
        "eventid": "http.honeypot.hit",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": safe_path,
        "user_agent": safe_ua,
        "payload": body_text,
    }
    background_tasks.add_task(log_event, event)

    # Get AI-generated or cached response
    response_text, source, model_used, was_cached, was_fallback = await orchestrator.get_response(
        safe_path, request.method, safe_ua
    )

    # Log the AI decision for SOC analysis
    ai_event = {
        "eventid": "http.honeypot.ai_decision",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": event["src_ip"],
        "path": safe_path,
        "source": source,
        "model": model_used,
        "cached": was_cached,
        "fallback": was_fallback,
    }
    background_tasks.add_task(log_event, ai_event)

    # Response jitter: simulate real server processing time (50-300ms)
    jitter = random.uniform(0.05, 0.3)
    import asyncio
    await asyncio.sleep(jitter)

    mime_type = resolve_mime(safe_path)

    return HTMLResponse(
        content=response_text,
        status_code=200,
        media_type=mime_type,
        headers=FAKE_HEADERS,
    )
