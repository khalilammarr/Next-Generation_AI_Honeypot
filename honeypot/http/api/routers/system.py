"""
Static Deception Routes.
Hardcoded traps for high-value endpoints (/login, /admin, /health).
These respond instantly without querying the LLM (zero cost, zero latency).
Credential harvesting: captures every username/password attempt.
"""

import datetime

from fastapi import APIRouter, Request, BackgroundTasks
from fastapi.responses import HTMLResponse

from core.config import FAKE_HEADERS
from core.logger import log_event

router = APIRouter()


@router.get("/login")
@router.get("/admin")
@router.get("/wp-login.php")
@router.get("/administrator")
async def login_page(request: Request, background_tasks: BackgroundTasks):
    # Get the real public IP if behind a proxy
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        src_ip = forwarded.split(",")[0].strip()
    else:
        src_ip = request.client.host if request.client else "unknown"

    event = {
        "eventid": "http.honeypot.login_view",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "method": "GET",
        "path": request.url.path,
    }
    background_tasks.add_task(log_event, event)

    html = """
    <html><head><title>Sign In - Internal Portal</title></head>
    <body style="background:#121212; color:#eee; font-family:monospace; display:flex; align-items:center; justify-content:center; height:100vh;">
        <div style="border:1px solid #333; padding:40px; border-radius:4px; background:#1e1e1e; width:320px;">
            <h2 style="color:#ffcc00; text-align:center; margin-bottom:20px;">Restricted Access</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Employee ID" style="width:100%; padding:10px; margin-bottom:10px; background:#000; border:1px solid #444; color:#fff; box-sizing:border-box;"/>
                <input type="password" name="password" placeholder="Master Key" style="width:100%; padding:10px; margin-bottom:15px; background:#000; border:1px solid #444; color:#fff; box-sizing:border-box;"/>
                <button type="submit" style="width:100%; padding:10px; background:#ffcc00; border:none; cursor:pointer; color:#000; font-weight:bold;">Sign In</button>
            </form>
        </div>
    </body></html>
    """
    return HTMLResponse(content=html, headers=FAKE_HEADERS)


@router.post("/login")
@router.post("/admin")
@router.post("/wp-login.php")
@router.post("/administrator")
async def login_attempt(request: Request, background_tasks: BackgroundTasks):
    """Credential Harvesting: Captures every username/password pair."""
    try:
        form = await request.form()
        username = str(form.get("username", form.get("u", form.get("user", ""))))
        password = str(form.get("password", form.get("p", form.get("pass", ""))))
    except Exception:
        username = ""
        password = ""

    # Get the real public IP if behind a proxy
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        src_ip = forwarded.split(",")[0].strip()
    else:
        src_ip = request.client.host if request.client else "unknown"

    event = {
        "eventid": "http.honeypot.credential_harvest",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "method": "POST",
        "path": request.url.path,
        "username": username,
        "password": password,
    }
    background_tasks.add_task(log_event, event)

    html = """
    <html><head><title>Sign In - Internal Portal</title></head>
    <body style="background:#121212; color:#eee; font-family:monospace; display:flex; align-items:center; justify-content:center; height:100vh;">
        <div style="border:1px solid #333; padding:40px; border-radius:4px; background:#1e1e1e; width:320px;">
            <h2 style="color:#ffcc00; text-align:center; margin-bottom:10px;">Restricted Access</h2>
            <p style="color:#ff4444; text-align:center;">Authentication Failure. This attempt has been logged.</p>
            <form method="POST">
                <input type="text" name="username" placeholder="Employee ID" style="width:100%; padding:10px; margin-bottom:10px; background:#000; border:1px solid #444; color:#fff; box-sizing:border-box;"/>
                <input type="password" name="password" placeholder="Master Key" style="width:100%; padding:10px; margin-bottom:15px; background:#000; border:1px solid #444; color:#fff; box-sizing:border-box;"/>
                <button type="submit" style="width:100%; padding:10px; background:#ffcc00; border:none; cursor:pointer; color:#000; font-weight:bold;">Sign In</button>
            </form>
        </div>
    </body></html>
    """
    return HTMLResponse(content=html, status_code=200, headers=FAKE_HEADERS)


@router.get("/health")
@router.get("/status")
async def health_check(request: Request):
    """Fake health endpoint — common on real production servers."""
    return HTMLResponse(
        content='{"status":"ok","uptime":"327d 14h 22m","version":"2.1.4"}',
        media_type="application/json",
        headers=FAKE_HEADERS,
    )
