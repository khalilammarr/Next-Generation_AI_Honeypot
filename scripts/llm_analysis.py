import sys
import os
import json
import re
from typing import Any, Dict, List, Optional
from openai import OpenAI

# Add paths to find session_db
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'honeypot', 'analysis')))
from honeypot.analysis.session_db import SessionDB

# Load API Key from .env
from dotenv import load_dotenv
load_dotenv()

GROQ_API_KEY = os.getenv("AI_API_KEY", os.getenv("GROQ_API_KEY"))
GROQ_MODEL = os.getenv("LLM_MODEL", os.getenv("GROQ_MODEL", "moonshotai/kimi-k2-instruct"))
GROQ_BASE_URL = os.getenv("AI_BASE_URL", os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"))

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "analysis.db"))
db = SessionDB(DB_PATH)


# ──────────────────── Parsers / Normalizers ────────────────────

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


def _normalize_str_list(value: Any, max_items: int = 10) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()][:max_items]
    if isinstance(value, str) and value.strip():
        return [value.strip()][:max_items]
    return []


def _normalize_confidence(value: Any) -> float:
    try:
        f = float(value)
        return round(max(0.0, min(1.0, f)), 2)
    except (TypeError, ValueError):
        return 0.0


def _normalize_kill_chain(value: Optional[str]) -> str:
    valid_phases = {
        "reconnaissance", "weaponization", "delivery",
        "exploitation", "installation", "command & control",
        "command and control", "actions on objectives", "unknown",
    }
    v = (value or "unknown").strip().lower()
    return v if v in valid_phases else "unknown"


# ──────────────────── Core Analysis Function ────────────────────

SYSTEM_PROMPT = """\
You are a Senior Cyber Threat Intelligence Analyst with deep expertise in Linux internals, \
network exploitation, and the MITRE ATT&CK framework. \
You will receive raw honeypot telemetry (SSH commands and HTTP requests captured from real attackers).

Your task: produce a thorough, structured threat intelligence report as strict JSON only.

Required JSON keys:
- intent (string): One concise sentence describing the attacker's primary objective.
- risk_level (string): One of [low, medium, high, critical].
- kill_chain_phase (string): The Lockheed Martin Cyber Kill Chain phase that best describes the primary activity. \
  One of [Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives].
- confidence (float): Your confidence in this analysis, from 0.0 (very uncertain) to 1.0 (certain).
- mitre_mapping (array of strings): MITRE ATT&CK technique IDs (e.g. ["T1059.004", "T1071.001"]). \
  Include sub-techniques where applicable. Maximum 15 entries.
- iocs (array of strings): Indicators of Compromise extracted from the session — IPs, domains, \
  suspicious file paths, URLs, hashes, malware names. Maximum 10 entries.
- behavioral_tags (array of strings): Short keyword tags describing the attack pattern \
  (e.g. ["brute-force", "crypto-miner", "data-exfiltration", "lateral-movement"]). Maximum 8 entries.
- summary (string): Executive summary in 3-5 sentences covering what the attacker did, \
  the risk, and the likely objective.
- recommendations (array of strings): 3 concrete, actionable defensive recommendations. \

Return ONLY valid JSON. No markdown, no code fences, no explanations outside the JSON.\
"""


def analyze_session_with_llm(session_id: str) -> Optional[Dict[str, Any]]:
    if not (GROQ_API_KEY or "").strip():
        raise RuntimeError("GROQ_API_KEY is missing for analysis service.")

    events = db.get_session_events(session_id)
    if not events:
        return None

    # Build timeline string
    timeline = []
    for etype, data, output in events:
        event_data = (data or "").strip()
        event_output = (output or "").strip()
        if event_output:
            timeline.append(f"[{etype}] {event_data} -> {event_output[:500]}")
        else:
            timeline.append(f"[{etype}] {event_data}")

    timeline_str = "\n".join(timeline[:300])

    client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)
    
    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Session ID: {session_id}\nSession Timeline:\n{timeline_str}"},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
            timeout=15.0,
        )
        content = response.choices[0].message.content or "{}"
    except Exception as e:
        # Fallback: Try without JSON object format or with a more standard model
        print(f"Primary analysis failed, trying fallback: {e}")
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-specdec",  # A very fast, standard Groq model
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT + "\nIMPORTANT: Return ONLY raw JSON."},
                    {"role": "user", "content": f"Session ID: {session_id}\nSession Timeline:\n{timeline_str}"},
                ],
                temperature=0.1,
                timeout=20.0,
            )
            content = response.choices[0].message.content or "{}"
        except Exception as e2:
            print(f"All analysis attempts failed: {e2}")
            return None
    parsed = _extract_json_object(content)

    analysis = {
        "intent": str(parsed.get("intent", "Unknown intent")).strip(),
        "risk_level": _normalize_risk_level(parsed.get("risk_level")),
        "kill_chain_phase": _normalize_kill_chain(parsed.get("kill_chain_phase")),
        "confidence": _normalize_confidence(parsed.get("confidence")),
        "mitre_mapping": _normalize_mitre_mapping(parsed.get("mitre_mapping")),
        "iocs": _normalize_str_list(parsed.get("iocs"), max_items=10),
        "behavioral_tags": _normalize_str_list(parsed.get("behavioral_tags"), max_items=8),
        "summary": str(parsed.get("summary", "No summary generated.")).strip(),
        "recommendations": _normalize_str_list(parsed.get("recommendations"), max_items=3),
    }

    db.save_analysis(
        session_id=session_id,
        risk_level=analysis["risk_level"],
        summary=analysis["summary"],
        mitre_mapping=analysis["mitre_mapping"],
        iocs=analysis["iocs"],
        kill_chain_phase=analysis["kill_chain_phase"],
        confidence=analysis["confidence"],
        behavioral_tags=analysis["behavioral_tags"],
        recommendations=analysis["recommendations"],
    )
    return analysis


def explain_command_with_llm(command: str) -> str:
    if not (GROQ_API_KEY or "").strip():
        raise RuntimeError("GROQ_API_KEY is missing for analysis service.")
    
    prompt = f"Explain what the following attacker command does in 1-2 short sentences. Be concise and technical:\n\n{command}"
    client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )
    return response.choices[0].message.content or "No explanation generated."


if __name__ == "__main__":
    pass
