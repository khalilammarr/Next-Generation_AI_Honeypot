import os
import json
import asyncio
import logging
import contextlib
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import sys
import io
import urllib.request

# Import our analysis logic
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))
from llm_analysis import analyze_session_with_llm, explain_command_with_llm
from report_generator import generate_pdf_report, generate_batch_pdf_report

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

_ip_cache = {}

def get_country_for_ip(ip: str) -> str:
    if ip in _ip_cache:
        return _ip_cache[ip]
    if ip == "unknown" or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return "Local"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            country = data.get("country", "Unknown")
            _ip_cache[ip] = country
            return country
    except Exception as e:
        logger.error(f"GeoIP error for {ip}: {e}")
        return "Unknown"

# ─────────────────────── Log Ingestor ───────────────────────────

class LogIngestor:
    def __init__(self, session_db: SessionDB) -> None:
        self.db = session_db
        self._positions: Dict[str, int] = {}
        self._inodes: Dict[str, int] = {}
        # ip -> (session_id, last_timestamp_obj)
        self._active_http_sessions: Dict[str, Any] = {}
        from datetime import datetime
        self._dt_parse = datetime.fromisoformat

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

    async def _auto_analyze(self, session_id: str, src_ip: str):
        try:
            country = await asyncio.to_thread(get_country_for_ip, src_ip)
            if country and country != "Unknown":
                self.db.set_session_country(session_id, country)
        except Exception as e:
            logger.error(f"Country resolution failed: {e}")

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
            asyncio.create_task(self._auto_analyze(session_id, src_ip))
            return

        if event_id == "cowrie.login.success":
            username = event.get("username") or "unknown"
            self.db.upsert_session(session_id, src_ip, "SSH", timestamp)
            self.db.add_event(session_id, timestamp, "LOGIN", f"login success: {username}")

    def _ingest_http_event(self, event: Dict[str, Any]) -> None:
        timestamp_str = event.get("timestamp")
        src_ip = event.get("src_ip") or event.get("ip") or "unknown"
        if not timestamp_str:
            return

        try:
            # Handle ISO timestamp with Z or +00:00
            clean_ts = timestamp_str.replace("Z", "+00:00")
            ts_obj = self._dt_parse(clean_ts)
        except Exception:
            from datetime import datetime
            ts_obj = datetime.utcnow()

        # Sessionization logic: group events from same IP within 15 minutes
        session_id = None
        if src_ip in self._active_http_sessions:
            last_sid, last_ts = self._active_http_sessions[src_ip]
            try:
                if (ts_obj - last_ts).total_seconds() < 900:
                    session_id = last_sid
            except Exception:
                pass
        else:
            # Try to recover from DB (persistent sessionization)
            last_record = self.db.get_last_session_id(src_ip, "HTTP")
            if last_record:
                last_sid, last_ts_str = last_record
                try:
                    # Parse DB timestamp (handles spaces and T)
                    clean_db_ts = last_ts_str.replace(" ", "T").replace("Z", "+00:00")
                    db_ts_obj = self._dt_parse(clean_db_ts)
                    if (ts_obj - db_ts_obj).total_seconds() < 900:
                        session_id = last_sid
                except Exception:
                    pass

        if not session_id:
            import uuid
            session_id = f"http-{uuid.uuid4().hex[:12]}"

        self._active_http_sessions[src_ip] = (session_id, ts_obj)

        method = event.get("method") or "GET"
        path = event.get("path") or "/"
        user_agent = event.get("user_agent")

        payload = event.get("payload")
        req_line = f"{method} {path}"
        if payload:
            req_line += f"\nPayload: {payload}"

        self.db.upsert_session(session_id, src_ip, "HTTP", timestamp_str, user_agent=user_agent)
        self.db.add_event(session_id, timestamp_str, "REQUEST", req_line)
        asyncio.create_task(self._auto_analyze(session_id, src_ip))

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

class PaginatedSessions(BaseModel):
    total: int
    page: int
    limit: int
    sessions: List[SessionEntry]

class CommandRequest(BaseModel):
    command: str


# ─────────────────────── API Endpoints ──────────────────────────

@app.get("/api/stats")
async def get_stats(time_range: str = Query("all")):
    """Aggregate statistics for the dashboard overview cards and charts."""
    try:
        return db.get_stats(time_range=time_range)
    except Exception as exc:
        logger.error(f"Failed to fetch stats for {time_range}: {exc}")
        raise HTTPException(status_code=500, detail="Failed to load stats.") from exc


@app.post("/api/sessions/analyze_all")
async def analyze_all_sessions():
    """Trigger background analysis for all unanalyzed sessions."""
    try:
        # 1. Prioritize critical/high risk sessions that are missing analysis
        unanalyzed = db.get_unanalyzed_sessions(limit=100)
        
        if not unanalyzed:
            return {"status": "ok", "message": "All active sessions are already analyzed.", "count": 0}
            
        # 2. Trigger background analysis task for each
        count = 0
        for s in unanalyzed:
            asyncio.create_task(ingestor._auto_analyze(s["session_id"], s.get("ip_address", "")))
            count += 1
            
        return {"status": "ok", "message": f"Enqueued {count} sessions for background analysis.", "count": count}
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")


@app.get("/api/sessions/insights/critical")
async def get_critical_insights():
    """Retrieve top critical incidents for strategic overview."""
    try:
        return db.get_critical_insights(limit=10)
    except Exception as exc:
        logger.error(f"Failed to fetch insights: {exc}")
        raise HTTPException(status_code=500, detail="Failed to load critical insights.")


@app.get("/api/sessions", response_model=PaginatedSessions)
async def get_sessions(
    page: int = Query(1, ge=1),
    limit: int = Query(15, ge=1, le=100),
    time_range: str = Query("all")
):
    try:
        sessions_data = db.get_sessions(page=page, limit=limit, time_range=time_range)
        total_count = db.get_sessions_count(time_range=time_range)
        return {"total": total_count, "page": page, "limit": limit, "sessions": sessions_data}
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


@app.get("/api/reports/batch")
async def get_batch_report(time_range: str = Query("30d")):
    try:
        # Run report generation in threadpool since reportlab is CPU blocking
        pdf_bytes = await run_in_threadpool(generate_batch_pdf_report, time_range)
        if not pdf_bytes:
            raise HTTPException(status_code=404, detail="No sessions found in this period to report on.")
            
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=ghostnet_intelligence_{time_range}.pdf"
            }
        )
    except Exception as e:
        logger.error(f"Failed to generate batch PDF report: {e}")
        raise HTTPException(status_code=500, detail="Report generation failed.")

@app.get("/api/reports/{session_id}")
async def get_report(session_id: str):
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


# For running locally. The dashboard has no authentication, so it binds to
# loopback by default; set DASHBOARD_HOST/DASHBOARD_PORT to change that.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.getenv("DASHBOARD_PORT", "8080")),
    )
