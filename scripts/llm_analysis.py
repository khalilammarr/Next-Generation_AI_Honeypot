import sys
import os
import json
import re
from typing import Any, Dict, List, Optional
from openai import OpenAI

# Add paths to find session_db
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'honeypot', 'analysis')))
from session_db import SessionDB

# Load API Key from .env
from dotenv import load_dotenv
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "moonshotai/kimi-k2-instruct")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "analysis.db"))
db = SessionDB(DB_PATH)

def _extract_json_object(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _normalize_risk_level(value: Optional[str]) -> str:
    normalized = (value or "unknown").strip().lower()
    allowed = {"low", "medium", "high", "critical", "unknown"}
    return normalized if normalized in allowed else "unknown"


def _normalize_mitre_mapping(value: Any) -> List[str]:
    if isinstance(value, list):
        candidates = value
    elif isinstance(value, str):
        candidates = re.split(r"[,\n]", value)
    else:
        candidates = []

    cleaned = []
    for item in candidates:
        token = str(item).strip()
        if token:
            cleaned.append(token.upper())
    return cleaned[:15]


def analyze_session_with_llm(session_id):
    if not (GROQ_API_KEY or "").strip():
        raise RuntimeError("GROQ_API_KEY is missing for analysis service.")

    events = db.get_session_events(session_id)
    if not events:
        return None

    # Prepare timeline for LLM
    timeline = []
    for etype, data, output in events:
        event_data = (data or "").strip()
        event_output = (output or "").strip()
        if event_output:
            timeline.append(f"[{etype}] {event_data} -> {event_output[:500]}")
        else:
            timeline.append(f"[{etype}] {event_data}")
    
    timeline_str = "\n".join(timeline[:300])

    system_prompt = (
        "You are a Senior Cyber Threat Intelligence Analyst.\n"
        "Analyze attacker behavior from honeypot telemetry and return strict JSON only.\n"
        "Required keys: intent, risk_level, mitre_mapping, summary.\n"
        "risk_level must be one of: low, medium, high, critical.\n"
        "mitre_mapping must be a list of ATT&CK IDs where possible.\n"
        "summary must be concise (2-4 sentences)."
    )

    client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Session ID: {session_id}\nSession Timeline:\n{timeline_str}"}
        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )

    content = response.choices[0].message.content or "{}"
    parsed = _extract_json_object(content)

    analysis = {
        "intent": str(parsed.get("intent", "Unknown intent")).strip(),
        "risk_level": _normalize_risk_level(parsed.get("risk_level")),
        "mitre_mapping": _normalize_mitre_mapping(parsed.get("mitre_mapping")),
        "summary": str(parsed.get("summary", "No summary generated.")).strip(),
    }

    db.save_analysis(
        session_id=session_id,
        risk_level=analysis["risk_level"],
        summary=analysis["summary"],
        mitre_mapping=analysis["mitre_mapping"],
    )
    return analysis

if __name__ == "__main__":
    # Example usage:
    # analyze_session_with_llm("SESSION_ID_HERE")
    pass
