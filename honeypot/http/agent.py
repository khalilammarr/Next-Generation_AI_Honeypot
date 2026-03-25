from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import requests
import os
# Template w kahaw ma aandou hata maana taw
app = FastAPI()

# Point to our AI Backend script logic or call Ollama directly
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama-server:11434/api/generate")

@app.get("/{path:path}", response_class=HTMLResponse)
async def dynamic_morph(request: Request, path: str):
    """
    The 'Morphing' Web Engine.
    Generates HTML on-the-fly based on the requested path and attacker headers.
    """
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Simple prompt to generate a realistic looking trap
    prompt = (
        f"Generate a simple but realistic HTML page for a server path: /{path}. "
        f"The server is a 'vulnerable' internal admin portal. "
        f"User-Agent scavenging for info: {user_agent}. "
        "Include a fake login form or directory listing as appropriate. "
        "Make it look professional but slightly outdated."
    )

    payload = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False
    }
    
    try:
        # In a real scenario, we would use LangChain to keep state, 
        # but for Phase 1, we do direct calls.
        response = requests.post(OLLAMA_URL, json=payload)
        html_content = response.json().get("response", "<h1>404 Not Found</h1>")
        return html_content
    except:
        return "<h1>Internal Server Error</h1>"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
