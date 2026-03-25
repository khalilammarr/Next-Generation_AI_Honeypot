# Architecture and Roles Guide

This document explains the full lab architecture, each machine role, what to install on each machine, which commands to run, and how traffic and logs move between systems.

## 1. Target Lab Topology

- Host machine (SIEM): Wazuh manager, indexer, and dashboard
- Ubuntu VM (Honeypot): Cowrie SSH honeypot, HTTP deception service, Ollama LLM, MQTT, Grafana
- Kali VM (Attacker simulation): recon and controlled attack tooling

Reference network:
- Subnet: `192.168.56.0/24`
- Ubuntu honeypot VM: `192.168.56.10`
- Kali attacker VM: `192.168.56.20`
- Host SIEM machine: `<HOST_SIEM_IP>`

## 2. Architecture Components and Data Flow

### 2.1 Running services on Ubuntu honeypot VM

From `docker-compose.yml`:
- `cowrie-ssh` on port `2222`
- `honey-mqtt` on ports `1883` and `9001`
- `ollama-server` on port `11434`
- `honey-dashboard` (Grafana) on port `3000`

### 2.2 Functional flow

1. Kali sends traffic (nmap, curl, ssh, gobuster) to Ubuntu VM
2. Ubuntu services respond (Cowrie SSH, HTTP deception app)
3. LLM content generation is handled by local Ollama on Ubuntu VM
4. Ubuntu logs and alerts are forwarded to Wazuh on Host
5. Wazuh dashboard on Host is used for analysis and evidence collection

### 2.3 Role of MQTT (`honey-mqtt`)

MQTT is the lightweight message bus used for internal event exchange between services.

What MQTT does in this lab:
- transports threat-intel style messages between services
- enables decoupled communication (publisher does not need direct connection to each consumer)
- can carry real-time notifications for analytics/dashboard integrations

Why it is useful here:
- simple protocol for near-real-time event fanout
- easy to integrate with Python services and agents
- good fit for lightweight lab-scale intelligence sharing

Current deployment details:
- service: `honey-mqtt`
- image: Eclipse Mosquitto
- ports: `1883` (MQTT), `9001` (WebSocket MQTT)

### 2.4 Role of Grafana (`honey-dashboard`)

Grafana is the operational visualization layer for quick dashboards and service observability.

What Grafana does in this lab:
- provides real-time panels for service and event metrics
- helps monitor stack health during attack simulations
- supports operator-friendly views during demos and tuning sessions

Why it is useful here:
- faster operational visibility than raw logs
- easy to build custom panels for traffic, errors, and event rates
- complements Wazuh (Wazuh for SIEM/security workflows, Grafana for ops/telemetry dashboards)

Current deployment details:
- service: `honey-dashboard`
- port: `3000`
- default admin password currently set in compose for lab usage

## 3. Machine Roles and Responsibilities

## 3.1 Host machine role (SIEM)

Purpose:
- Central security brain for the lab
- Receives telemetry from Ubuntu VM
- Visualizes alerts and events in Wazuh dashboard

Main responsibilities:
- Install and run Wazuh stack
- Accept and manage Ubuntu agent enrollment
- Validate event ingestion from honeypot activity
- Keep SIEM services healthy and reachable

## 3.2 Ubuntu VM role (Honeypot platform)

Purpose:
- Expose controlled attack surface
- Collect attacker behavior
- Generate realistic decoy responses

Main responsibilities:
- Host Cowrie SSH service (`2222`)
- Host HTTP deception app (`8000` when app is running)
- Host Ollama LLM (`11434`)
- Host MQTT and Grafana support services
- Run Wazuh agent and forward events to Host SIEM

## 3.3 Kali VM role (Attacker simulation)

Purpose:
- Generate controlled attack behavior
- Test realism and detection coverage

Main responsibilities:
- Recon scanning
- Directory brute force
- HTTP probing
- SSH login attempts and command interaction
- Provide repeatable test traces for reporting

## 4. Setup Guide by Machine

## 4.1 Host machine setup (Wazuh SIEM)

### Step A: baseline packages and firewall

```bash
cd <repo-root>
bash scripts/setup/host-siem-bootstrap.sh
```

What this script does:
- updates packages
- installs tools (`curl`, `jq`, `git`, `ufw`)
- applies firewall baseline
- opens key SIEM ports (`443`, `55000`)

### Step B: install Wazuh

Follow:
- `infra/wazuh/install-notes.md`
- `infra/wazuh/docker-single-node-setup.md`

Quick health check after install:

```bash
curl -k https://127.0.0.1:55000
```

Expected:
- successful API response (or auth challenge), not connection failure

## 4.2 Ubuntu VM setup (Honeypot stack)

### Step A: baseline and stack bootstrap

```bash
cd <repo-root>
bash scripts/setup/day1-bootstrap.sh
```

What this script does:
- installs Docker
- applies firewall rules for honeypot ports
- starts compose stack

### Step B: verify containers

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Expected containers:
- `cowrie-ssh`
- `honey-mqtt`
- `ollama-server`
- `honey-dashboard`

### Step C: check service logs

```bash
docker logs cowrie-ssh --tail 50
docker logs honey-mqtt --tail 50
docker logs ollama-server --tail 50
docker logs honey-dashboard --tail 50
```

### Step D: verify firewall allows required ports

```bash
sudo ufw status verbose
```

Required open ports on Ubuntu VM:
- `22/tcp`
- `2222/tcp`
- `8000/tcp`
- `1883/tcp`
- `9001/tcp`
- `11434/tcp`
- `3000/tcp`

## 4.3 Kali VM setup (attacker tooling)

### Step A: bootstrap attacker tools

```bash
cd <repo-root>
bash scripts/setup/attacker-bootstrap.sh
```

### Step B: install additional recon tools used in this lab

```bash
sudo apt update
sudo apt install -y gobuster hydra
```

Optional verification:

```bash
gobuster version
hydra -h | head -n 1
```

## 5. Attack Simulation Guide (Kali -> Ubuntu)

Run these in controlled windows only.

### 5.1 Recon scan

```bash
nmap -sV -p 2222,8000 192.168.56.10
```

Purpose:
- validate exposed services and collect banner behavior

### 5.2 HTTP probe

```bash
curl -i http://192.168.56.10:8000/admin
curl -i http://192.168.56.10:8000/login
```

Purpose:
- generate web telemetry and test deception responses

### 5.3 Directory brute force

```bash
gobuster dir -u http://192.168.56.10:8000 -w /usr/share/wordlists/dirb/common.txt
```

Purpose:
- emulate attacker path enumeration behavior

### 5.4 SSH interaction

```bash
ssh -p 2222 root@192.168.56.10
```

Purpose:
- enter Cowrie shell session and trigger command telemetry

## 6. LLM Integration Plan and Location

## 6.1 Where Ollama runs

Ollama runs on Ubuntu honeypot VM as `ollama-server` container on port `11434`.

Reason:
- keeps deception logic near honeypot services
- avoids external cloud dependency for lab baseline
- improves lab isolation

## 6.2 How LLM is currently integrated

Current files:
- `honeypot/http/agent.py`: HTTP app calls Ollama directly (`/api/generate`)
- `scripts/llm-backend/main.py`: backend skeleton for LLM + MQTT integration

Current mode is close to direct-generation for HTTP.

## 6.3 Target integration model (recommended)

Use policy-gated orchestration:

1. request/command arrives
2. orchestrator sends candidate prompt to Ollama
3. validator checks output policy
4. allowed output returns to attacker
5. rejected output falls back to deterministic safe template
6. decision metadata is logged

## 7. Host <-> Ubuntu Communication (Wazuh path)

## 7.1 Logical communication

- Ubuntu VM runs Wazuh agent
- Agent sends telemetry to Host Wazuh manager
- Host dashboard visualizes events from Ubuntu

## 7.2 Ubuntu Wazuh agent setup (generic)

On Ubuntu VM, install agent from official Wazuh packages and point it to Host manager.

Example sequence:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="<HOST_SIEM_IP>" apt install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

Validate agent on Ubuntu:

```bash
sudo systemctl status wazuh-agent --no-pager
```

Validate on Host dashboard:
- agent appears as `Active`
- recent keepalive timestamps are updating

## 7.3 Typical connectivity checks

From Ubuntu VM:

```bash
ping -c 3 <HOST_SIEM_IP>
```

From Host machine:

```bash
ping -c 3 192.168.56.10
```

If enrollment fails:
- verify IP routing
- verify host firewall allows Wazuh manager ports
- verify Ubuntu can reach Host manager address

## 8. Command Quick Reference by Machine

## 8.1 Host (SIEM)

```bash
cd <repo-root>
bash scripts/setup/host-siem-bootstrap.sh
curl -k https://127.0.0.1:55000
```

## 8.2 Ubuntu (Honeypot)

```bash
cd <repo-root>
bash scripts/setup/day1-bootstrap.sh
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
docker logs cowrie-ssh --tail 50
```

## 8.3 Kali (Attacker)

```bash
cd <repo-root>
bash scripts/setup/attacker-bootstrap.sh
nmap -sV -p 2222,8000 192.168.56.10
gobuster dir -u http://192.168.56.10:8000 -w /usr/share/wordlists/dirb/common.txt
ssh -p 2222 root@192.168.56.10
```

## 9. Operational Notes

- Keep this lab isolated from production networks.
- Use controlled attack windows and document each run.
- Save evidence in day reports after each simulation cycle.
- Prefer Docker-based operation for reproducibility across teammates.
