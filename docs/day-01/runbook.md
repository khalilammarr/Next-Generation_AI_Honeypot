# Day 01 Runbook (Copy/Paste Ready)

## 0) Pre-flight
- Host-only subnet target: `192.168.56.0/24`
- Host machine role: `SIEM host` (Wazuh deployment target)
- Ubuntu honeypot VM IP target: `192.168.56.10`
- Attacker VM (Kali preferred, Ubuntu acceptable) IP target: `192.168.56.20`

Run role-specific bootstrap scripts:
- Host SIEM node: `scripts/setup/host-siem-bootstrap.sh`
- Honeypot VM: `scripts/setup/day1-bootstrap.sh`
- Attacker VM: `scripts/setup/attacker-bootstrap.sh`

---

## 1) Network validation

### On Honeypot Ubuntu VM
```bash
ip a
ip route
ping -c 3 192.168.56.20
ping -c 3 <HOST_SIEM_IP>
```

### On Attacker VM
```bash
ip a
ip route
ping -c 3 192.168.56.10
```

### On Host SIEM machine
```bash
ip a
ip route
ping -c 3 192.168.56.10
```

Expected:
- ping success across required node pairs
- host and both VMs on expected host-only subnet

---

## 2) Bootstrap each node

### On Host SIEM machine
```bash
cd <repo-root>
bash scripts/setup/host-siem-bootstrap.sh
```

### On Honeypot Ubuntu VM
```bash
cd <repo-root>
bash scripts/setup/day1-bootstrap.sh
```

### On Attacker VM
```bash
cd <repo-root>
bash scripts/setup/attacker-bootstrap.sh
```

Expected:
- base packages installed on each node
- firewall baseline applied where relevant
- docker installed and stack started on honeypot VM

---

## 3) Install Docker + Compose on Ubuntu (manual fallback)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw curl ca-certificates gnupg jq git net-tools htop
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 1883/tcp
sudo ufw allow 9001/tcp
sudo ufw allow 11434/tcp
sudo ufw allow 3000/tcp
sudo ufw enable
sudo ufw status verbose
```

Expected:
- UFW enabled
- only required ports allowed

---

Then install Docker + Compose:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

docker --version
docker compose version
docker run --rm hello-world
```

Expected:
- Docker works without sudo after group refresh

---

## 4) Start current project stack (honeypot VM)

```bash
cd <repo-root>
docker compose up -d
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Check logs:
```bash
docker logs cowrie-ssh --tail 50
docker logs honey-mqtt --tail 50
docker logs ollama-server --tail 50
docker logs honey-dashboard --tail 50
```

Expected:
- services remain `Up`

---

## 5) Wazuh installation (host SIEM machine)

On the host machine, follow `infra/wazuh/install-notes.md` and official Wazuh quick-start/all-in-one installer.

Post-install checks (on Wazuh host):
```bash
curl -k https://127.0.0.1:55000
# or service checks according to install method
```

Expected:
- Wazuh manager/indexer/dashboard healthy

---

## 6) Add honeypot Ubuntu VM as Wazuh agent

On Ubuntu honeypot VM (commands may vary by Wazuh version):
```bash
# install agent package from official docs for your version
# configure manager address
# start agent service
```

Validation in Wazuh dashboard:
- Agent appears as `Active`
- Last keepalive updates

---

## 7) Controlled attacker simulation from attacker VM

```bash
nmap -sV -p 2222,8000 192.168.56.10
curl -i http://192.168.56.10:8000/admin
curl -i http://192.168.56.10:8000/login
ssh -p 2222 root@192.168.56.10
```

Expected:
- scans and probes visible in logs/SIEM
- no crash of services

---

## 8) Evidence collection

Collect screenshots of:
1. Wazuh agents page (Ubuntu active)
2. Wazuh events/alerts related to nmap/curl/ssh
3. Docker services status

Store under:
- `docs/evidence/`
- update `docs/day-01/results.md`

---

## 9) End of day checkpoint

- Save issues in `docs/day-01/issues.md`
- Save outcomes in `docs/day-01/results.md`
- Create VM snapshot `day1-stable`
