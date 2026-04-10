import os
import json
import asyncio
import logging
import contextlib
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import sys
import io

# Import our analysis logic
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))
from llm_analysis import analyze_session_with_llm, explain_command_with_llm
from report_generator import generate_pdf_report

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "honeypot", "analysis"))
from session_db import SessionDB

app = FastAPI(title="GhostNet Control Center")
logger = logging.getLogger("dashboard.ingestor")

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "analysis.db")
db = SessionDB(DB_PATH)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COWRIE_LOG = os.getenv("COWRIE_LOG", "/var/log/cowrie/cowrie.json")
HTTP_LOG = os.getenv("HTTP_LOG", "/var/log/cowrie/http_honeypot.json")

# Fallback for local testing if system paths don't exist
local_cowrie = os.path.join(ROOT_DIR, "logs", "cowrie.json")
local_http = os.path.join(ROOT_DIR, "logs", "http_honeypot.json")

if not os.path.exists(COWRIE_LOG) and os.path.exists(local_cowrie):
    COWRIE_LOG = local_cowrie
if not os.path.exists(HTTP_LOG) and os.path.exists(local_http):
    HTTP_LOG = local_http

logger.info(f"Ingestor active. Reading records from: {HTTP_LOG}")

INGEST_INTERVAL_SECONDS = 3.0


# ─────────────────────── Log Ingestor ───────────────────────────

class LogIngestor:
    def __init__(self, session_db: SessionDB) -> None:
        self.db = session_db
        self._positions: Dict[str, int] = {}
        self._inodes: Dict[str, int] = {}

    def _open_from_last_position(self, path: str):
        if not os.path.exists(path):
            return None

        stat = os.stat(path)
        previous_inode = self._inodes.get(path)
        if previous_inode != stat.st_ino:
            self._positions[path] = 0
            self._inodes[path] = stat.st_ino

        file_handle = open(path, "r", encoding="utf-8", errors="replace")
        file_handle.seek(self._positions.get(path, 0))
        return file_handle

    def _read_new_lines(self, path: str):
        file_handle = self._open_from_last_position(path)
        if file_handle is None:
            return []

        with file_handle:
            lines = file_handle.readlines()
            self._positions[path] = file_handle.tell()
            return lines

    async def _auto_analyze(self, session_id: str):
        try:
            await asyncio.to_thread(analyze_session_with_llm, session_id)
        except Exception as e:
            logger.error(f"Auto analysis failed: {e}")

    def _ingest_cowrie_event(self, event: Dict[str, Any]) -> None:
        session_id = event.get("session")
        timestamp = event.get("timestamp")
        event_id = event.get("eventid")
        src_ip = event.get("src_ip") or "unknown"

        if not session_id or not timestamp:
            return

        if event_id == "cowrie.session.connect":
            self.db.upsert_session(session_id, src_ip, "SSH", timestamp)
            return

        if event_id == "cowrie.command.input":
            cmd = event.get("input") or ""
            self.db.upsert_session(session_id, src_ip, "SSH", timestamp)
            self.db.add_event(session_id, timestamp, "COMMAND", cmd)
            asyncio.create_task(self._auto_analyze(session_id))
            return

        if event_id == "cowrie.login.success":
            username = event.get("username") or "unknown"
            self.db.upsert_session(session_id, src_ip, "SSH", timestamp)
            self.db.add_event(session_id, timestamp, "LOGIN", f"login success: {username}")

    def _ingest_http_event(self, event: Dict[str, Any]) -> None:
        timestamp = event.get("timestamp")
        src_ip = event.get("src_ip") or event.get("ip") or "unknown"
        if not timestamp:
            return

        import uuid
        session_id = event.get("request_id") or f"http-{uuid.uuid4().hex[:12]}"
        method = event.get("method") or "GET"
        path = event.get("path") or "/"
        user_agent = event.get("user_agent")

        payload = event.get("payload")
        req_line = f"{method} {path}"
        if payload:
            req_line += f"\nPayload: {payload}"

        self.db.upsert_session(session_id, src_ip, "HTTP", timestamp, user_agent=user_agent)
        self.db.add_event(session_id, timestamp, "REQUEST", req_line)
        asyncio.create_task(self._auto_analyze(session_id))

    def ingest_once(self) -> None:
        # Re-evaluate paths if they don't exist yet (useful for new log files)
        global COWRIE_LOG, HTTP_LOG
        if not os.path.exists(COWRIE_LOG) and os.path.exists(local_cowrie):
            COWRIE_LOG = local_cowrie
            logger.info(f"Ingestor switched to local Cowrie log: {COWRIE_LOG}")
        if not os.path.exists(HTTP_LOG) and os.path.exists(local_http):
            HTTP_LOG = local_http
            logger.info(f"Ingestor switched to local HTTP log: {HTTP_LOG}")

        for line in self._read_new_lines(COWRIE_LOG):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                self._ingest_cowrie_event(event)
            except Exception as exc:
                logger.debug("Skipping malformed cowrie log line: %s", exc)

        for line in self._read_new_lines(HTTP_LOG):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                self._ingest_http_event(event)
            except Exception as exc:
                logger.debug("Skipping malformed http log line: %s", exc)


ingestor = LogIngestor(db)
ingest_task: Optional[asyncio.Task] = None


async def _ingest_loop() -> None:
    while True:
        try:
            ingestor.ingest_once()
        except Exception as exc:
            logger.exception("Background ingestion failure: %s", exc)
        await asyncio.sleep(INGEST_INTERVAL_SECONDS)


@app.on_event("startup")
async def startup_event() -> None:
    global ingest_task
    ingestor.ingest_once()
    ingest_task = asyncio.create_task(_ingest_loop())


@app.on_event("shutdown")
async def shutdown_event() -> None:
    global ingest_task
    if ingest_task:
        ingest_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ingest_task
        ingest_task = None


# ─────────────────────── Pydantic Models ────────────────────────

class SessionEntry(BaseModel):
    session_id: str
    ip_address: str
    protocol: str
    start_time: str
    risk_level: str
    summary: Optional[str] = None

class CommandRequest(BaseModel):
    command: str


# ─────────────────────── API Endpoints ──────────────────────────

@app.get("/api/stats")
async def get_stats():
    """Aggregate statistics for the dashboard overview cards and charts."""
    try:
        return db.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to load stats.") from exc


@app.get("/api/sessions", response_model=List[SessionEntry])
async def get_sessions():
    try:
        return db.get_sessions()
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to load sessions.") from exc


@app.get("/api/sessions/{session_id}/events")
async def get_session_events(session_id: str):
    try:
        if not db.session_exists(session_id):
            raise HTTPException(status_code=404, detail="Session not found.")
        return db.get_session_timeline(session_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to load session events.") from exc


@app.get("/api/sessions/{session_id}/analysis")
async def get_analysis(session_id: str):
    try:
        if not db.session_exists(session_id):
            raise HTTPException(status_code=404, detail="Session not found.")

        # 1. Try cached result
        analysis = db.get_analysis(session_id)

        # 2. If not cached → run LLM
        if not analysis:
            analysis = await run_in_threadpool(analyze_session_with_llm, session_id)
            if not analysis:
                raise HTTPException(status_code=404, detail="No events found for this session.")

        return analysis
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Analysis engine failed.") from exc


@app.post("/api/sessions/{session_id}/analyze")
async def trigger_analysis(session_id: str):
    """Force a fresh LLM analysis, bypassing cache."""
    try:
        if not db.session_exists(session_id):
            raise HTTPException(status_code=404, detail="Session not found.")

        analysis = await run_in_threadpool(analyze_session_with_llm, session_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="No events found for this session.")
        return analysis
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Analysis engine failed.") from exc


@app.post("/api/explain_command")
async def explain_command(req: CommandRequest):
    """Generate a short description for a single command."""
    try:
        explanation = await run_in_threadpool(explain_command_with_llm, req.command)
        return {"explanation": explanation}
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Explanation engine failed.") from exc


@app.get("/api/sessions/{session_id}/report")
async def download_report(session_id: str):
    """Generate and stream a PDF threat intelligence report."""
    try:
        if not db.session_exists(session_id):
            raise HTTPException(status_code=404, detail="Session not found.")

        pdf_bytes = await run_in_threadpool(generate_pdf_report, session_id)
        if not pdf_bytes:
            raise HTTPException(status_code=404, detail="Session not found or no data available.")

        filename = f"ghostnet_report_{session_id[:12]}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Report generation failed.") from exc


# ─────────────────────── Frontend ───────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r", encoding="utf-8") as f:
        return f.read()


# For running locally:
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
