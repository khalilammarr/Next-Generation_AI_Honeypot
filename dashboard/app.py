import os
import json
import asyncio
import logging
import contextlib
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sys

# Import our analysis logic
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))
from llm_analysis import analyze_session_with_llm

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "honeypot", "analysis"))
from session_db import SessionDB

app = FastAPI(title="GhostNet Control Center")
logger = logging.getLogger("dashboard.ingestor")

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "analysis.db")
db = SessionDB(DB_PATH)
COWRIE_LOG = "/var/log/cowrie/cowrie.json"
HTTP_LOG = "/var/log/cowrie/http_honeypot.json"
INGEST_INTERVAL_SECONDS = 3.0


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
            return

        if event_id == "cowrie.login.success":
            username = event.get("username") or "unknown"
            self.db.upsert_session(session_id, src_ip, "SSH", timestamp)
            self.db.add_event(session_id, timestamp, "LOGIN", f"login success: {username}")

    def _ingest_http_event(self, event: Dict[str, Any]) -> None:
        timestamp = event.get("timestamp")
        src_ip = event.get("ip") or "unknown"
        if not timestamp:
            return

        session_id = event.get("request_id") or f"http-{src_ip}"
        method = event.get("method") or "GET"
        path = event.get("path") or "/"
        user_agent = event.get("user_agent")

        self.db.upsert_session(session_id, src_ip, "HTTP", timestamp, user_agent=user_agent)
        self.db.add_event(session_id, timestamp, "REQUEST", f"{method} {path}")

    def ingest_once(self) -> None:
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
    # Prime database with any existing log data on startup.
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

class SessionEntry(BaseModel):
    session_id: str
    ip_address: str
    protocol: str
    start_time: str
    risk_level: str
    summary: Optional[str] = None

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

@app.post("/api/sessions/{session_id}/analyze")
async def trigger_analysis(session_id: str):
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

# Serve the static files (Frontend)
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r", encoding="utf-8") as f:
        return f.read()

# For running locally:
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
