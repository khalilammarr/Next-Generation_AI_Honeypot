import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "honeypot", "analysis")))
from session_db import SessionDB

# Path to logs (Relative to the project root or Docker volumes)
COWRIE_LOG = "/var/log/cowrie/cowrie.json"
HTTP_LOG = "/var/log/cowrie/http_honeypot.json"

db = SessionDB("analysis.db")

def parse_cowrie_logs():
    if not os.path.exists(COWRIE_LOG):
        print(f"Cowrie log not found at {COWRIE_LOG}")
        return

    print(f"Parsing Cowrie logs from {COWRIE_LOG}...")
    with open(COWRIE_LOG, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
                session_id = event.get("session")
                timestamp = event.get("timestamp")
                eventid = event.get("eventid")
                src_ip = event.get("src_ip")

                if eventid == "cowrie.session.connect":
                    db.upsert_session(session_id, src_ip, "SSH", timestamp)
                
                elif eventid == "cowrie.command.input":
                    cmd = event.get("input")
                    db.add_event(session_id, timestamp, "COMMAND", cmd)
                
                elif eventid == "cowrie.command.success":
                    # Optionally capture command output if logged
                    pass

            except Exception as e:
                continue

def parse_http_logs():
    if not os.path.exists(HTTP_LOG):
        print(f"HTTP log not found at {HTTP_LOG}")
        return

    print(f"Parsing HTTP logs from {HTTP_LOG}...")
    with open(HTTP_LOG, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
                # HTTP logs might not have a formal 'session' ID yet, 
                # we group by IP + Time Window manually if needed, 
                # but let's assume a unique ID per request sequence for now.
                import uuid
                session_id = event.get("request_id") or f"http-{uuid.uuid4().hex[:12]}"
                timestamp = event.get("timestamp")
                src_ip = event.get("src_ip") or event.get("ip") or "unknown"
                method = event.get("method")
                path = event.get("path")
                ua = event.get("user_agent")

                payload = event.get("payload")
                req_line = f"{method} {path}"
                if payload:
                    req_line += f"\nPayload: {payload}"

                db.upsert_session(session_id, src_ip, "HTTP", timestamp, user_agent=ua)
                db.add_event(session_id, timestamp, "REQUEST", req_line)

            except Exception as e:
                continue

if __name__ == "__main__":
    parse_cowrie_logs()
    parse_http_logs()
    print("Ingestion complete. Database 'analysis.db' updated.")
