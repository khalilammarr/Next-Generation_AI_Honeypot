<div align="center">

# 🕸️ Project GhostNet
### *Intelligent Multi-Agent LLM Honeypot*

[![Team Size](https://img.shields.io/badge/Team-4_Members-2ea44f?style=for-the-badge)](#)
[![Timeline](https://img.shields.io/badge/Timeline-12_Weeks-0366d6?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Implementation_Ready-purple?style=for-the-badge)](#)

*A Next-Generation Deception-as-a-Service Platform*

---

</div>

<details open>
<summary><b>📖 Table of Contents</b></summary>
<br>

1. [Executive Summary & Mission](#-1-executive-summary--mission)
2. [Locked Architecture & Tech Stack](#-2-locked-architecture--tech-stack)
3. [Machine Roles & Lab Setup](#-3-machine-roles--lab-setup)
4. [Team Organization (The 4 Roles)](#-4-team-organization-the-4-roles)
5. [Execution Plan: Step-by-Step](#-5-execution-plan-step-by-step)
6. [Extra Ideas & Enhancements](#-6-extra-ideas--enhancements-when-mvp-is-stable)

</details>

<br>

## 🚀 1. Executive Summary & Mission

> **Our Vision:** Classical honeypots are static mousetraps; attackers scan them, identify the trap, and leave. Our system is an adaptive **"haunted house."** 

We use a **Policy-Gated AI Engine (Local LLM)** to generate dynamic, realistic, and context-aware responses to attacker interactions across SSH and HTTP services. This dramatically increases attacker dwell time, helping us gather high-fidelity threat intelligence, TTPs (Tactics, Techniques, and Procedures), and IOCs (Indicators of Compromise).

### 🏛️ The Four Project Pillars
| Pillar | Objective |
|:---|:---|
| **🎭 Believability** | Attackers must genuinely believe they are on a real system. |
| **🛡️ Containment** | Attackers must **never escape** the sandbox or harm the real host. |
| **🔎 Observability** | Every action is sent to a SIEM for rules, alerting, and dashboarding. |
| **📡 Coordination** | Multiple honeypot agents share real-time threat intelligence. |

---

## 🏗️ 2. Locked Architecture & Tech Stack

Our stack is strictly frozen for the **MVP (Minimum Viable Product)** to ensure stability, reproducibility, and safety.

<div align="center">

| Layer | Tool / Technology | Role in Architecture |
|:---:|:---:|:---|
| **SSH Honeypot** | <kbd>Cowrie</kbd> | Fake SSH shell. Hooks built-in commands & routes complex ones to AI. |
| **HTTP Honeypot** | <kbd>FastAPI</kbd> | Dynamic web decoy generating fake logins, admin panels, and API endpoints. |
| **LLM Engine** | <kbd>Qwen2.5 7B</kbd> | Runs **locally via Ollama**. Ensures zero data leakage and constant availability. |
| **Orchestrator** | <kbd>LangChain</kbd> | The "Brain". Validates prompts, manages context, and enforces guardrails. |
| **Event Bus** | <kbd>Mosquitto MQTT</kbd> | Handles inter-agent messaging and threat intelligence fan-out. |
| **State Cache** | <kbd>Redis 7</kbd> | Tracks ephemeral session state (fake filesystem modifications). |
| **SIEM & SOC** | <kbd>Wazuh + OpenSearch</kbd>| Analytics platform for log indexing, real-time alerting, and dashboards. |
| **Deployment** | <kbd>Docker Compose</kbd> | Ensures the entire node ships as isolated, reproducible containers. |

</div>

---

## 💻 3. Machine Roles & Lab Setup

🛑 **CRITICAL SAFETY NOTICE:** *NEVER expose this setup to the public internet during the development phase.* 🛑

1. 🟢 **Honeypot VM (`192.168.56.10`)**  
   * Ubuntu Server 24.04.
   * Runs the Docker Compose stack (Cowrie, FastAPI, Ollama, MQTT, Redis).
   * **Network:** Two interfaces: `NAT` (turned off during attack simulations) and `Host-Only`.
2. 🔴 **Attacker VM (`192.168.56.20`)**  
   * Kali Linux. Subnet isolated.
   * Runs Nmap, Hydra, Gobuster, and manual attack payloads.
3. 🔵 **SIEM Host (`<HOST_IP>`)**  
   * Wazuh manager and OpenSearch dashboard.
   * Ingests, normalizes, and visualizes all telemetry from the Honeypot VM.

---

## 👥 4. Team Organization (The 4 Roles)

Each member controls a distinct component, ensuring parallel progress. Everyone contributes to the final testing and reporting.

| Member | Focus Area | Core Responsibilities |
|:---:|:---|:---|
| 👤 **A** | **DevOps & Infra Lead** | VM Lab setup, Docker network containment, Cowrie config, UFW/Iptables. |
| 👤 **B** | **AI & Orchestration** | LLM wrapper, LangChain prompt engineering, Redis session context store, guardrails. |
| 👤 **C** | **Security & Deception** | FastAPI HTTP fake apps, honeytokens generation, SIEM integration, Wazuh rule engine. |
| 👤 **D** | **Frontend & Integrations**| MQTT architecture, cross-agent intel sharing, Grafana/Kibana live dashboards. |

---

## 📅 5. Execution Plan: Step-by-Step

This structured roadmap ensures we build safely and effectively. Do not advance until the previous phase passes validation.

### Phase 1: Foundations & Lab Isolation
- [ ] **Task 01: VM & Network Baseline**. Set up Ubuntu and Kali VMs (Host-Only). Verify isolation. *(Owner: Member A)*
- [ ] **Task 02: Core Environment**. Install Docker, Compose, UFW. *(Owner: A)*
- [ ] **Task 03: Stack Health-Check**. Run `docker-compose.yml` (Cowrie, MQTT, Ollama); verify clean boot. *(Owner: A & B)*

### Phase 2: Static Deception Layer
- [ ] **Task 04: HTTP Honeypot Foundations**. Build FastAPI endpoints (`/admin`, `/login`). *(Owner: C)*
- [ ] **Task 05: SSH Realism Tuning**. Customize Cowrie's fake filesystem, hostname, and banners. *(Owner: A & C)*
- [ ] **Task 06: Event Unification**. Define `event-contract.json` (timestamp, session_id, src_ip, action). *(Owner: C & D)*

### Phase 3: The AI Brain (Orchestrator)
- [ ] **Task 07: Policy Engine & Guardrails**. Build Python middleware to block prompt-injection. *(Owner: B)*
- [ ] **Task 08: AI-to-SSH/HTTP Integration**. Route complex commands to Ollama. Validate latency (< 2s). *(Owner: B)*
- [ ] **Task 09: Session Context**. Track attacker state in Redis (e.g., remember "fake files" created earlier). *(Owner: B)*

### Phase 4: SIEM, Detection & Dashboards
- [ ] **Task 10: Rule Engine & Alerting**. Map actions to MITRE ATT&CK in Wazuh. Trigger alerts on brute-force. *(Owner: C)*
- [ ] **Task 11: Multi-Agent Intelligence Sharing**. Configure MQTT to broadcast aggressive IPs to other agents. *(Owner: B & D)*
- [ ] **Task 12: Operations Dashboards**. Build real-time analytics panels for the final demo. *(Owner: D)*

### Phase 5: Warfare & Validation
- [ ] **Task 13: Live Attack Campaigns**. Red team (Kali) launches full attacks. Measure KPIs. *(Owner: ALL)*
- [ ] **Task 14: Final Runbook & Demo Prep**. Finalize reports, refine `docker compose up` deployment. *(Owner: ALL)*

---

## 🌟 6. Extra Ideas & Enhancements (When MVP is Stable)

Take your project to the next level with these advanced offensive/defensive concepts:

> **1. Auto-Network Blackhole (Active Response)**  
> If an agent identifies an attacker scanning aggressively, use Wazuh Active Response to dynamically ban the attacker's IP on *all other agents* instantly via the MQTT bus.

> **2. Honeytoken Beacons**  
> Generate fake AWS Access Keys or `.pdf` files scattered in the fake SSH filesystem. If an attacker downloads and uses them, a silent HTTP request triggers a critical internal alert.

> **3. Simulated "Human Noise" (Ghost Activity)**  
> Inject a cronjob that slowly randomly updates `auth.log` or writes bash history to simulate a "real admin" actively working on the server. The LLM can generate this fake history contextually.

> **4. Adaptive Persona Shifting**  
> If the HTTP Agent detects an aggressive automated scanner (like `Nikto`), have the LLM immediately morph the site's error pages into "WAF (Web Application Firewall) blocked" pages to trick the scanner into thinking the site is hyper-secure instead of just fake.

> **5. Teardown & Replay Architecture**  
> Create a "Time Machine" script. Dump a specific session’s raw logs from Redis, wipe the system clean, and stream the logs back through the pipeline internally to perfectly recreate a demo scenario on demand.
