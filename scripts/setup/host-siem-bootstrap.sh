#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] Updating host packages..."
sudo apt update && sudo apt upgrade -y

echo "[2/4] Installing host SIEM prerequisites..."
sudo apt install -y curl ca-certificates gnupg jq git net-tools htop ufw

echo "[3/4] Applying host firewall baseline..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
# Wazuh dashboard (default)
sudo ufw allow 443/tcp
# Wazuh manager API (default local/admin usage)
sudo ufw allow 55000/tcp
sudo ufw --force enable

echo "[4/4] Next: install Wazuh on this host using infra/wazuh/install-notes.md and official docs."
echo "Post-install check: curl -k https://127.0.0.1:55000"
