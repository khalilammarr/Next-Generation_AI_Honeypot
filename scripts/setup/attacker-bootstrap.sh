#!/usr/bin/env bash
set -euo pipefail

echo "[1/3] Updating attacker VM packages..."
sudo apt update && sudo apt upgrade -y

echo "[2/3] Installing attacker tooling..."
sudo apt install -y nmap curl openssh-client net-tools jq htop

echo "[3/3] Tool versions..."
nmap --version | head -n 1
ssh -V 2>&1 | head -n 1
curl --version | head -n 1

echo "Done. Attacker VM is ready for controlled smoke tests."
