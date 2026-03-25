# Honeypot Setup Guide (Ubuntu VM)

This document is the main operational guide for setting up and running the honeypot lab now that the Ubuntu VM is installed.

## 1. Objective

Build and run a safe lab where:
- Ubuntu VM hosts honeypot services (Cowrie, MQTT, Ollama, Grafana)
- Wazuh collects and analyzes events
- Attacker VM runs controlled simulations
- Evidence is collected for daily reporting and tuning

## 2. Current Architecture

- Honeypot VM (Ubuntu): target host, Docker stack runtime
- SIEM host: Wazuh manager/indexer/dashboard (prefer host machine)
- Attacker VM (Kali or Ubuntu): controlled scans and probes

Reference IP targets used in this project:
- Honeypot VM: `192.168.56.10`
- Attacker VM: `192.168.56.20`
- Host-only subnet: `192.168.56.0/24`

## 2.1 LLM Response Model Decision (Important)

There are two valid operating modes:

### Mode 1: Direct LLM to attacker (Cowrie built-in style)

Flow:
1. Attacker sends command
2. Cowrie sends prompt to LLM
3. LLM response is returned directly to attacker

Pros:
- Simple and fast to enable
- No extra middleware required
- Good for quick experiments

Cons:
- No strong response filtering before attacker sees output
- Higher risk of prompt-injection artifacts
- Harder to enforce consistent persona and policy across channels
- Limited governance and analyst control

### Mode 2: Policy-gated LLM (recommended for this project)

Flow:
1. Attacker sends command/request
2. Event goes to orchestrator/policy layer
3. LLM generates candidate response
4. Validator filters/scores response
5. If accepted: send to attacker
6. If rejected: fallback deterministic safe response

Pros:
- Better control and safety
- Better consistency across SSH and HTTP deception
- Easier auditing and SOC explainability
- Supports red-team-resistant behavior tuning

Cons:
- More components to build and maintain
- Slight extra latency
- Requires clear response contracts and test cases

### Practical manager approval note

Manual human approval for every attacker command is usually not practical in live interactive SSH sessions because latency breaks realism.

Recommended approach:
- Automatic policy approval by default (real-time)
- Human-in-the-loop only for high-risk flags, tuning mode, or offline replay review

This is the model aligned with project plans: policy-gated automation first, not per-command manual approval.

## 3. Files You Will Use Most

- `scripts/setup/day1-bootstrap.sh`: one-command setup for Ubuntu honeypot VM
- `scripts/setup/host-siem-bootstrap.sh`: host SIEM prerequisites
- `scripts/setup/attacker-bootstrap.sh`: attacker VM bootstrap
- `docker-compose.yml`: honeypot services
- `docs/day-01/runbook.md`: concise Day-01 execution flow
- `docs/day-01/results.md`: results and observations
- `docs/day-01/issues.md`: blockers and incidents

## 4. Step-by-Step Setup on Ubuntu Honeypot VM

### 4.1 Pre-flight checks

Run on Ubuntu VM:

```bash
ip a
ip route
ping -c 3 192.168.56.20
ping -c 3 <HOST_SIEM_IP>
```

Expected:
- VM has host-only IP in `192.168.56.0/24`
- Route is correct
- Connectivity to attacker VM and SIEM host works

### 4.2 Clone repository and move into it

```bash
git clone <YOUR_REPO_URL>
cd LLM_Honeypot-main
```

If repo is already copied to the VM, just `cd` into it.

### 4.3 Bootstrap Ubuntu VM (recommended)

```bash
bash scripts/setup/day1-bootstrap.sh
```

This script performs:
1. System update/upgrade
2. Utility package installation
3. Docker install
4. UFW baseline rules
5. Docker/Compose checks
6. Stack startup

### 4.4 Manual fallback (if script fails)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw curl ca-certificates gnupg jq git net-tools htop

curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
newgrp docker

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
sudo ufw status verbose

docker --version
docker compose version
docker run --rm hello-world
```

### 4.5 Start and validate services

```bash
docker compose up -d
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Inspect logs:

```bash
docker logs cowrie-ssh --tail 50
docker logs honey-mqtt --tail 50
docker logs ollama-server --tail 50
docker logs honey-dashboard --tail 50
```

Expected containers from `docker-compose.yml`:
- `cowrie-ssh` on `2222`
- `honey-mqtt` on `1883`, `9001`
- `ollama-server` on `11434`
- `honey-dashboard` on `3000`

## 5. SIEM Integration (Wazuh)

Install Wazuh on host SIEM machine using project notes:
- `infra/wazuh/install-notes.md`
- `infra/wazuh/docker-single-node-setup.md`

Then onboard Ubuntu honeypot VM as a Wazuh agent.

Validation targets:
- Agent status: Active in dashboard
- Keepalive updates visible
- Security events arriving from Ubuntu VM

## 6. Controlled Attack Simulation (After Setup)

Run from attacker VM:

```bash
nmap -sV -p 2222,8000 192.168.56.10
curl -i http://192.168.56.10:8000/admin
curl -i http://192.168.56.10:8000/login
ssh -p 2222 root@192.168.56.10
```

Expected outcomes:
- Honeypot services stay up
- Attempts appear in honeypot logs
- Alerts/events are visible in Wazuh

## 7. Evidence and Reporting Workflow

At the end of each run/day:

1. Save screenshots of:
- Wazuh agents page (Ubuntu active)
- Wazuh event timeline with attack traces
- Docker service status

2. Update project docs:
- `docs/day-01/results.md`
- `docs/day-01/issues.md`

3. Snapshot VM after stable state:
- Example: `day1-stable`, `post-wazuh-agent`, `post-tuning`

## 8. From Now On: Practical Roadmap

### Phase A: Stabilize Day-01 baseline (now)
- Ensure reproducible bootstrap on Ubuntu VM
- Confirm all containers restart cleanly after reboot
- Confirm Wazuh agent remains connected after reboot

### Phase B: Improve detection quality
- Add/adjust Wazuh rules for:
- SSH brute-force patterns on port 2222
- Web probe patterns for `/admin`, `/login`, path enumeration
- MQTT misuse patterns on 1883/9001

- Map events to MITRE ATT&CK techniques for reporting clarity

### Phase C: Expand honeypot realism
- Add HTTP deception endpoints and realistic response behavior
- Add richer Cowrie fake filesystem/users profile
- Add synthetic background traffic to reduce "empty lab" signatures

### Phase C.1: Implement LLM filtering pipeline (priority)
- Add orchestrator service between honeypot agents and LLM runtime
- Add policy checks: prompt-injection, secret leakage, style/length constraints
- Add confidence scoring and fallback templates for rejected responses
- Log decision metadata: accepted/rejected reason, rule id, latency
- Keep optional analyst override for flagged responses only

### Phase D: Operational hardening
- Restrict management interfaces to trusted subnet only
- Enforce stronger host firewall defaults and verify exposed ports regularly
- Centralize logs and define retention/rotation policy

### Phase E: Automation and repeatability
- One-command validation script for health checks
- Scheduled attack simulation script for regression testing
- Daily report template for detection drift and service uptime

## 9. Daily Operations Checklist

Run on honeypot VM:

```bash
docker ps
sudo ufw status verbose
free -h
df -h
```

Run on SIEM host:
- Check Wazuh cluster/services health
- Confirm honeypot agent is active
- Review new high-severity alerts

Run on attacker VM (controlled and approved windows only):
- Trigger minimal test probes
- Verify expected detections

## 10. Troubleshooting Notes

If `docker compose` fails:
- Re-run with logs: `docker compose up -d && docker compose logs --tail=100`
- Check disk and memory (`df -h`, `free -h`)

If agent disconnects from Wazuh:
- Verify manager IP and firewall path
- Restart agent service
- Check time sync between nodes

If no detections appear:
- Confirm attacks actually reached honeypot IP
- Confirm log pipeline from honeypot to Wazuh
- Check Wazuh rules and indexer/dashboard health

## 11. Safety Notes

- Run this only in isolated lab networking.
- Do not expose honeypot directly to production network.
- Use controlled attacker simulations and document every run window.
- Rotate credentials and avoid default passwords when moving beyond local testing.

---

For fast execution order, use `docs/day-01/runbook.md` together with this file.
