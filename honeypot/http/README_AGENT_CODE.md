# 🕵️‍♂️ Understanding the AI Honeypot Code (`agent.py`)
*A Beginner-Friendly Guide to How Our Deception Engine Works*

This file explains every piece of the `agent.py` script. If you are new to Python or building honeypots, this is your roadmap to understanding exactly how our server tricks attackers and catches their malware!

---

### 1. The Setup (Imports & Configuration)
At the very top, we import the tools we need:
- `FastAPI`: The lightning-fast web framework that acts as our actual "fake server."
- `json` and `os`: For formatting logs and reading files.
- `requests`: This is what lets our Python code "talk" to the Ollama AI brain over the network.
- `asyncio`: A tool that lets our server do multiple things at the same time without freezing.

**Important Lines:**
```python
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama-server:11434/api/generate")
PERSONALITY_FILE = "/app/personality.txt"
```
These lines tell our script where the AI lives (`OLLAMA_URL`) and where the AI's "soul" or instructions are stored (`PERSONALITY_FILE`). If you change your personality file, the script automatically reads it next time it needs to think!

---

### 2. The SIEM Connection (`log_event` and `analyze_and_log`)
This is the most critical part for a SOC Engineer. A honeypot is useless if it doesn't record the attack.

**The Logging Function:**
```python
def log_event(event_data: dict):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event_data) + "\n")
        f.flush()            # <--- THE MAGIC FIX
        os.fsync(f.fileno()) 
```
Normally, Python is lazy. It waits to write logs until it has a large "batch" to save disk power. But in a SOC, we need alerts *instantly*. `f.flush()` and `os.fsync()` scream at the operating system: *"Write this to the hard drive Right Now!"* This ensures Wazuh sees the alert the millisecond an attacker clicks our link.

**The Analyzer (`analyze_and_log`):**
This function grabs the attacker's `IP Address`, `User-Agent` (the tool they are using, like Nmap or Firefox), and the `payload` (like the password they typed). It packages all this into a neat JSON box and hands it to the `log_event` function.

---

### 3. The Brain Link (`query_ai_morph`)
This is where the magic happens. When an attacker asks for a page that doesn't exist, we run this function.

```python
def query_ai_morph(path: str, method: str, user_agent: str) -> str:
```
**How it thinks:**
1.  It reads your `personality.txt` to remember who it is pretending to be.
2.  It creates a "Prompt" for Llama3: *"The attacker asked for /backup.zip using Nmap. Generate something fake to keep them hooked."*
3.  It sends this prompt to Ollama using `requests.post(OLLAMA_URL, ...)`.
4.  Ollama thinks for 1-2 seconds, writes the fake HTML code, and hands it back to our Python script!

---

### 4. The Traps (FastAPI Routes)

In FastAPI, routes are created using decorators like `@app.get(...)`. This tells the server: "If someone asks for this URL, run this specific function."

#### Trap A: The Static Login Portal
```python
@app.get("/login", response_class=HTMLResponse)
```
We intentionally *do not* use AI for `/login` or `/admin`. Why? Because we want this page to be incredibly fast and 100% reliable for catching passwords. If an attacker tries to brute force 1000 passwords a second, we don't want the AI to crash. So this trap always returns fixed, hardcoded HTML.

#### Trap B: The "Morphing" Catch-All
```python
@app.get("/{path:path}", response_class=HTMLResponse)
```
This is the ultimate deception mechanism. The `{path:path}` rule catches *literally any other URL* the attacker tries to visit. 

If they go to `http://honeypot.com/wp-config.php`, this route catches it. 
**Important Lines:**
```python
ai_html = await asyncio.to_thread(query_ai_morph, full_path, request.method, user_agent)
```
- `asyncio.to_thread` is a crucial performance trick. Because asking the AI to think takes 1 or 2 seconds, we send that "thinking" task to a different CPU thread. This means while the AI is busy generating code for Attacker A, Attacker B can still load the login page instantly without waiting!

---

### 5. Starting the Server
```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```
Finally, we use `uvicorn` (a high-performance, asynchronous web server built for Python) to start the application on port 8000. It stays awake forever, listening for the next attack!
