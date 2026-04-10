import json
import os
import time
from datetime import datetime

# Configuration
LOG_DIR = "logs"
HTTP_LOG = os.path.join(LOG_DIR, "http_honeypot.json")

def simulate_http_requests(ip_address, count=3):
    """
    Simulates multiple HTTP requests from the same IP address.
    Each should generate a unique session ID based on our new logic in app.py.
    """
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        print(f"Created directory: {LOG_DIR}")

    print(f"Generating {count} HTTP requests from IP: {ip_address}...")
    
    with open(HTTP_LOG, "a") as f:
        for i in range(count):
            event = {
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "ip": ip_address,
                "method": "GET",
                "path": f"/test-endpoint-{i}",
                "user_agent": "GhostNet-Tester/1.0"
            }
            f.write(json.dumps(event) + "\n")
            print(f"  [+] Logged request to {event['path']}")
            time.sleep(0.5) # Wait to ensure different timestamps and allow dashboard to ingest

    print("-" * 40)
    print("SUCCESS: Log entries added to 'logs/http_honeypot.json'.")
    print("Since the dashboard server uses --reload, it should pick up the new log paths.")
    print("Refresh your browser at http://localhost:8080")
    print("You should see 3 NEW distinct rows in the Live Feed for IP: " + ip_address)
    print("-" * 40)

if __name__ == "__main__":
    simulate_http_requests("192.168.1.50", count=3)
