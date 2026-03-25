#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "[1/6] Updating Ubuntu packages..."
sudo apt update && sudo apt upgrade -y

echo "[2/6] Installing base utilities..."
sudo apt install -y ufw curl ca-certificates gnupg jq git net-tools htop

echo "[3/6] Installing Docker..."
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"

echo "[4/6] Applying baseline firewall rules for honeypot VM..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 1883/tcp
sudo ufw allow 9001/tcp
sudo ufw allow 11434/tcp
sudo ufw allow 3000/tcp
sudo ufw --force enable

echo "[5/6] Validating Docker + Compose availability..."
docker --version
docker compose version

echo "[6/6] Starting project stack from ${REPO_ROOT}..."
cd "${REPO_ROOT}"
if ! docker compose up -d; then
	echo "WARN: stack startup failed; inspect with: docker compose ps && docker compose logs --tail=100"
fi

echo "Done. Re-login (or run 'newgrp docker') for docker group changes if needed."
