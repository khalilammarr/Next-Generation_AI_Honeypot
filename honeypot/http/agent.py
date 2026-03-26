from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import json
import os
import datetime

# --- Configuration ---
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "http_honeypot.json")

# Hide standard FastAPI footprints (docs/redoc)
app = FastAPI(docs_url=None, redoc_url=None) 

# --- SOC Logging Core (Unbuffered for Real-time alerts) ---
def log_event(event_data: dict):
    """Write the event to our JSON log file for Wazuh to ingest instantly."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event_data) + "\n")
        f.flush()            # Force Python to write to the OS buffer
        os.fsync(f.fileno()) # Force the OS to write to the physical disk

async def analyze_and_log(request: Request, path: str, background_tasks: BackgroundTasks):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    method = request.method
    
    # Payload Scavenging (T1110 - Brute Force or T1595 - Vulnerability Scan)
    try:
        body = await request.body()
        body_text = body.decode("utf-8")[:500]
    except:
        body_text = ""

    event = {
        "eventid": "http.honeypot.hit",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": client_ip,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "payload": body_text,
        "headers": dict(request.headers)
    }
    background_tasks.add_task(log_event, event)

# --- Deceptive UI Templates ---
COMMON_CSS = """
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1c1e; color: #e1e2e1; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #2d2f31; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); width: 350px; border: 1px solid #3e4042; }
    h2 { color: #4dabf7; margin-bottom: 24px; text-align: center; font-weight: 400; font-size: 24px; }
    input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #3e4042; border-radius: 4px; background: #1a1c1e; color: #fff; box-sizing: border-box; }
    button { width: 100%; padding: 12px; border: none; border-radius: 4px; background: #1c7ed6; color: white; cursor: pointer; font-size: 16px; transition: background 0.2s; }
    button:hover { background: #1864ab; }
    .warning { color: #fa5252; font-size: 13px; text-align: center; margin-top: 15px; }
    .footer { font-size: 11px; color: #868e96; text-align: center; margin-top: 25px; }
</style>
"""

# --- Routes (Bait Endpoints) ---

@app.get("/login", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
@app.post("/login", response_class=HTMLResponse)
@app.post("/admin", response_class=HTMLResponse)
async def login_portal(request: Request, background_tasks: BackgroundTasks):
    await analyze_and_log(request, request.url.path, background_tasks)
    
    # Simulate a fake authentication failure (Brute Force Trap)
    error_msg = ""
    if request.method == "POST":
        error_msg = '<p class="warning">❌ Error: Invalid authentication key or user profile.</p>'

    html = f"""
    <html><head><title>Secure Access Gateway</title>{COMMON_CSS}</head>
    <body>
        <div class="card">
            <h2>Sentinel<span style="font-weight:700">OS</span> v2.4</h2>
            <p style="font-size: 14px; text-align: center; color: #adb5bd; margin-bottom: 30px;">Authorized Access Only (Node: PRD-CLUSTER-07)</p>
            {error_msg}
            <form method="POST">
                <input type="text" name="username" placeholder="Employee ID / Mail" required/>
                <input type="password" name="password" placeholder="Access Password" required/>
                <button type="submit">Unlock Partition</button>
            </form>
            <div class="footer">Security Policy 12-4B | Global Threat Intelligence Group</div>
        </div>
    </body></html>
    """
    return HTMLResponse(content=html, status_code=200)

@app.get("/.env", response_class=JSONResponse)
async def env_trap(request: Request, background_tasks: BackgroundTasks):
    await analyze_and_log(request, "/.env", background_tasks)
    return JSONResponse(status_code=403, content={"error": "Access Denied", "reason": "Environment isolated"})

@app.get("/{path:path}", response_class=HTMLResponse)
async def default_trap(request: Request, path: str, background_tasks: BackgroundTasks):
    await analyze_and_log(request, f"/{path}", background_tasks)
    
    # Generic "Directory Protected" response to pique curiosity
    html = f"""
    <html><head><title>Directory: /{path}</title>{COMMON_CSS}</head>
    <body>
        <div class="card" style="width: 500px;">
            <h2 style="text-align: left;">HTTP 403: Forbidden</h2>
            <hr style="border: 0; border-top: 1px solid #3e4042; margin-bottom: 20px;">
            <p>Access to the requested resource <code>/{path}</code> is restricted. Credentials must be established via the <a href="/login" style="color: #4dabf7;">Authentication Proxy</a>.</p>
            <p style="font-size: 13px; color: #868e96;">Error Trace ID: 0x{os.urandom(4).hex()}</p>
        </div>
    </body></html>
    """
    return HTMLResponse(content=html, status_code=403)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
