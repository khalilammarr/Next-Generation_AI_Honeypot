from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import json
import os
import datetime
import requests
import asyncio

# --- Configuration ---
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "http_honeypot.json")

# The URL to the Ollama Container (defined in docker-compose.yml)
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama-server:11434/api/generate")
PERSONALITY_FILE = "/app/personality.txt"

app = FastAPI(docs_url=None, redoc_url=None) 

# --- SOC Logging Core ---
def log_event(event_data: dict):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event_data) + "\n")
        f.flush()            
        os.fsync(f.fileno()) 

async def analyze_and_log(request: Request, path: str, background_tasks: BackgroundTasks):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    method = request.method
    
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

# --- The AI Brain (Ollama Integration) ---
def query_ai_morph(path: str, method: str, user_agent: str) -> str:
    """Synchronous function to query Ollama for a custom deception page."""
    # 1. Provide the "Soul"
    try:
        with open(PERSONALITY_FILE, "r") as f:
            system_prompt = f.read()
    except Exception:
        system_prompt = "You are a vulnerable legacy web server returning realistic HTML."

    # 2. Tell the AI what the attacker is doing
    prompt = f"The attacker (User-Agent: {user_agent}) requested: {method} {path}. Generate a highly realistic file or HTML response that keeps them hooked but provides no real access. DO NOT USE MARKDOWN. Return ONLY raw HTML/Text code for the fake page."

    payload = {
        "model": "llama3",
        "system": system_prompt,
        "prompt": prompt,
        "stream": False
    }

    try:
        # 3. Request the trap from the AI Brain
        res = requests.post(OLLAMA_URL, json=payload, timeout=20)   
        # Return the AI's generated code!
        return res.json().get("response", "<h1>500 Internal Error - Deception Failed</h1>")
    except Exception as e:
        return f"<h1>Service Unavailable - AI Brain Offline ({str(e)})</h1>"


# --- Routes (Bait Endpoints) ---

# We only keep the Login specific as a fixed trap because it catches credentials perfectly.
@app.get("/login", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
@app.post("/login", response_class=HTMLResponse)
@app.post("/admin", response_class=HTMLResponse)
async def login_portal(request: Request, background_tasks: BackgroundTasks):
    await analyze_and_log(request, request.url.path, background_tasks)
    
    error_msg = ""
    if request.method == "POST":
        error_msg = '<p style="color:red; text-align:center;">❌ Error: Invalid authentication.</p>'

    html = f"""
    <html><head><title>Admin Portal</title></head>
    <body style="background: #1a1c1e; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh;">
        <div style="background: #2d2f31; padding: 40px; border-radius: 8px;">
            <h2 style="text-align: center; color: #4dabf7;">Sentinel Gateway</h2>
            {error_msg}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" style="width:100%; padding:10px; margin-bottom:15px;" required/>
                <input type="password" name="password" placeholder="Password" style="width:100%; padding:10px; margin-bottom:15px;" required/>
                <button type="submit" style="width:100%; padding:10px; cursor:pointer;">Login</button>
            </form>
        </div>
    </body></html>
    """
    return HTMLResponse(content=html, status_code=200)

# The AI "Morphing" Endpoint
@app.get("/{path:path}", response_class=HTMLResponse)
async def dynamic_ai_trap(request: Request, path: str, background_tasks: BackgroundTasks):
    """If they hit ANYTHING else, hand the request to the AI Brain!"""
    full_path = f"/{path}"
    await analyze_and_log(request, full_path, background_tasks)
    
    # Send the AI task to a separate thread so we don't block other web traffic!
    user_agent = request.headers.get("user-agent", "unknown")
    ai_html = await asyncio.to_thread(query_ai_morph, full_path, request.method, user_agent)
    
    return HTMLResponse(content=ai_html, status_code=200)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
