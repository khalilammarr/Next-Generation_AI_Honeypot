import os
import sys
import argparse
from datetime import datetime
from session_db import SessionDB
from llm_analysis import analyze_session_with_llm

db = SessionDB("analysis.db")

def generate_report(session_id):
    # Ensure it's analyzed first
    analysis = analyze_session_with_llm(session_id)
    if not analysis:
        return

    # Fetch session details
    with sqlite3.connect(db.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
        session = cursor.fetchone()

    if not session:
        return

    # Fetch events
    events = db.get_session_events(session_id)

    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    report_path = os.path.join(report_dir, f"report_{session_id}.md")
    
    with open(report_path, "w") as f:
        f.write(f"# GhostNet Attack Report: {session_id}\n\n")
        f.write(f"## Attacker Profile\n")
        f.write(f"- **IP Address**: {session['ip_address']}\n")
        f.write(f"- **Protocol**: {session['protocol']}\n")
        f.write(f"- **Start Time**: {session['start_time']}\n")
        f.write(f"- **Risk Level**: **{session['risk_level'].upper()}**\n\n")
        
        f.write(f"## Executive Summary\n")
        f.write(f"{session['analysis_summary']}\n\n")

        f.write(f"## MITRE ATT&CK Mapping\n")
        mitre = json.loads(session['mitre_mapping'])
        if mitre:
            for tech in mitre:
                f.write(f"- {tech}\n")
        else:
            f.write(f"- No specific techniques identified.\n")
        f.write("\n")

        f.write(f"## Activity Timeline\n")
        f.write("| Timestamp | Type | Input/Command | Output/Response |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for etype, data, output in events:
            f.write(f"| {etype} | {data} | {'Generated AI Response' if output else 'N/A'} |\n")

    print(f"Report generated successfully: {report_path}")

def list_sessions():
    with sqlite3.connect(db.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT session_id, ip_address, protocol, risk_level FROM sessions')
        sessions = cursor.fetchall()
        
        print(f"{'Session ID':<15} | {'IP Address':<15} | {'Protocol':<8} | {'Risk'}")
        print("-" * 50)
        for s in sessions:
            print(f"{s['session_id']:<15} | {s['ip_address']:<15} | {s['protocol']:<8} | {s['risk_level']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostNet Session Analyzer & Reporter")
    parser.add_argument("--list", action="store_true", help="List all captured sessions")
    parser.add_argument("--report", type=str, help="Generate report for a specific session ID")
    parser.add_argument("--ingest", action="store_true", help="Ingest latest logs into the DB")
    
    args = parser.parse_args()

    if args.ingest:
        # Import and run the ingest logic from analyze_sessions.py
        import subprocess
        subprocess.run(["python3", "scripts/analyze_sessions.py"])
    
    if args.list:
        list_sessions()
    
    if args.report:
        import sqlite3
        import json
        generate_report(args.report)
