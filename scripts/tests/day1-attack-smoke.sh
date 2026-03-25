#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-192.168.56.10}"

echo "[1/4] Nmap service scan"
nmap -sV -p 2222,8000 "$TARGET_IP"

echo "[2/4] HTTP probe /admin"
curl -i "http://$TARGET_IP:8000/admin" || true

echo "[3/4] HTTP probe /login"
curl -i "http://$TARGET_IP:8000/login" || true

echo "[4/4] SSH handshake test"
ssh -o StrictHostKeyChecking=no -p 2222 root@"$TARGET_IP" exit || true

echo "Smoke attack script complete. Check SIEM for events."
