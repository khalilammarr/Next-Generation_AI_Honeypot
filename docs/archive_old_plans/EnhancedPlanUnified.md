# Enhanced Master Plan — Intelligent Multi-Agent LLM Honeypot (Planning Only)

## 1) Project Clarification (What this project is and is not)

### Mission
Design and deliver a **safe, believable, and measurable deception platform** that combines:
- medium-interaction honeypots (SSH + HTTP),
- policy-constrained LLM response generation,
- behavioral analytics and ATT&CK-mapped detections,
- multi-agent threat-intelligence sharing,
- SOC/SIEM-ready outputs.

### Explicit Non-Goals (to prevent scope creep)
- No full high-interaction VM honeypot in the core scope.
- No autonomous offensive actions (no active counter-attack behavior).
- No production internet exposure without lab hardening and approval.
- No “AI novelty for its own sake” features without measurable value.

### Success Definition
The project succeeds if it proves, with metrics:
1. Attackers remain engaged longer than with static honeypot responses.
2. Detection output is explainable and ATT&CK-aligned.
3. Multi-agent sharing improves correlation quality and/or detection speed.
4. System remains contained and reproducible in lab conditions.

---

## 2) Global Technical Overview (Simple End-to-End View)

This section gives the **big picture in order**, before detailed architecture and phase-by-phase execution.

### 2.1 What we are technically building (from start to finish)
1. Create a controlled lab where attackers can interact with fake services safely.
2. Deploy an SSH honeypot and an HTTP honeypot that look realistic.
3. Collect all attacker actions in a unified event format.
4. Add an AI layer to generate dynamic but controlled responses.
5. Analyze sessions (rules + scoring) to detect techniques and intent.
6. Share threat intelligence between honeypot agents.
7. Send enriched alerts to SIEM dashboards for SOC visibility.

### 2.2 Main technical areas (and why each one matters)
- **Deception Services (SSH/HTTP):** keep attackers engaged and produce useful behavior traces.
- **AI Response Layer:** improve realism without giving unsafe or inconsistent answers.
- **Telemetry & Normalization:** make data consistent so detection and dashboards work reliably.
- **Detection & Correlation:** turn raw logs into actionable alerts and campaign-level insights.
- **Multi-Agent Intelligence Sharing:** improve global visibility across multiple honeypot nodes.
- **SOC Visualization:** make attack timelines and alerts usable by analysts and evaluators.

### 2.3 Infrastructure we will need
- **Honeypot host environment:**
   - Preferred: one dedicated **Linux VM** (or bare-metal lab machine) to run Docker services safely.
   - Why: easier isolation, reproducibility, and rollback compared to running directly on personal OS.
- **Attacker simulation environment:**
   - One separate **attacker VM** (for Nmap/Hydra/manual tests) to validate realism and detection quality.
- **Core runtime services:**
   - Cowrie (SSH), FastAPI (HTTP), Redis (state + bus), ELK (SIEM), Ollama (local LLM runtime).

### 2.3.1 SSH Service Model Clarification (Important)
- The SSH endpoint will be **real at protocol/network level** (port, handshake, login flow), so scanners and clients see it as SSH.
- Behind that endpoint, we run a **controlled honeypot simulation** (e.g., Cowrie), not a real production shell on a real server.
- This means attackers can interact in realistic ways, but commands are emulated/policy-controlled to keep containment and safety.
- Design rule: **real SSH surface, simulated backend behavior, zero sensitive assets exposed**.

### 2.4 AI model strategy (training vs using existing models)
- **We do not need to train a model from scratch.**
- Baseline approach:
   - Use pre-trained local models via Ollama.
   - Use prompt engineering + policy validation + fallback templates.
- Optional advanced step (only if time allows):
   - lightweight tuning (e.g., LoRA-style adaptation) for specific deception style.
   - This is an enhancement, not a dependency for MVP success.

### 2.5 Build order (recommended execution sequence)
1. Lab isolation + safety rules
2. SSH/HTTP believable interaction baseline
3. Unified event schema and ingestion
4. AI orchestration with guardrails
5. Detection rules and ATT&CK mapping
6. Multi-agent sharing and correlation
7. Dashboard, validation campaign, and KPI evaluation

### 2.5.1 Fast Execution Block (Detailed Step-by-Step)
**Step 1 — Lab isolation + safety rules**
- Set network segmentation (honeypot VLAN/subnet), egress restrictions, and logging at host + container level.
- Define containment policy (no outbound payload execution, no real credentials, no access to internal assets).
- **Output:** reproducible lab baseline (network map + security policy doc + compose baseline).
- **Verify:** attacker VM reaches honeypot ports; honeypot cannot reach sensitive internal targets.
- **After this step, we have:** one controlled honeypot environment (typically a Linux VM) running isolated containers, ready to host SSH and HTTP deception services safely.

**Step 2 — SSH/HTTP believable interaction baseline**
- Deploy Cowrie (SSH) and FastAPI deception endpoints with realistic banners, prompts, and response timing.
- Add basic service fingerprints (version style, login flows, common endpoint behavior) to reduce obvious fakery.
- Define HTTP decoy content set (static first):
   - fake login page,
   - admin panel decoy,
   - simple API/status endpoints,
   - believable headers/errors and response codes.
- Define SSH decoy behavior set (static first):
   - banner + login prompts,
   - controlled fake filesystem view,
   - safe emulated command responses for common attacker commands.
- **Output:** two interactive deception surfaces with session IDs and initial realism profile.
- **Verify:** manual attacker script can complete multi-step interaction on both channels without immediate break.
- **After this step, we have:** a live SSH honeypot service and a live HTTP deception server that attackers can interact with in a believable way.

**Step 3 — Unified event schema and ingestion**
- Normalize SSH + HTTP events into one schema (timestamp, session_id, source_ip, action, outcome, artifact).
- Pipe events to Redis stream/bus, then index to ELK with service tags and severity placeholders.
- **Output:** single searchable event model across channels.
- **Verify:** one attacker session appears as a coherent timeline in ELK with no missing critical fields.
- **After this step, we have:** one central event pipeline where both SSH and HTTP activity is searchable as a single timeline.

**Step 4 — AI orchestration with guardrails**
- **AI intervention starts here** (not in Step 2).
- Add response routing: template-first fallback + LLM generation path (Ollama) with policy checks.
- Enforce prompt/output constraints (no real commands, no sensitive data, bounded response style/length).
- AI scope at this stage:
   - generate dynamic text responses for HTTP decoy flows,
   - generate contextual SSH emulated output text,
   - keep static fallback when confidence/policy checks fail.
- **Output:** dynamic response engine with safe fallback behavior.
- **Verify:** prompt-injection test cases are blocked or downgraded to safe template responses.
- **After this step, we have:** controlled dynamic responses that improve realism without breaking safety or containment policy.

**Step 5 — Detection rules + ATT&CK mapping**
- Implement first detector pack (recon, brute-force, suspicious command patterns, staged persistence behavior).
- Attach ATT&CK technique IDs, confidence score, and evidence snippets per alert.
- **Output:** explainable alerts instead of raw logs.
- **Verify:** replayed attacks generate mapped alerts with correct evidence chain.
- **After this step, we have:** actionable alerts tied to ATT&CK techniques, not just raw events.

**Step 6 — Multi-agent sharing + correlation**
- Share IOC/reputation messages (IP, user-agent, command pattern, timing profile) between honeypot agents.
- Add TTL + dedup to avoid noisy propagation and stale intelligence.
- **Output:** cross-node campaign view and improved confidence scoring.
- **Verify:** activity detected on one node influences scoring/context on another node within defined latency.
- **After this step, we have:** multiple honeypot nodes that collaborate and enrich each other’s detections in near real time.

**Step 7 — Dashboard + validation campaign + KPI evaluation**
- Build analyst views (live timeline, top techniques, high-risk sessions, model latency/guardrail events).
- Run fixed validation campaign (automated + manual) and compare KPI baseline vs current sprint.
- **Output:** final operational dashboard + measurable performance report.
- **Verify:** KPI report includes dwell-time delta, detection precision/recall snapshot, and containment status.
- **After this step, we have:** an end-to-end demonstrable platform with dashboards, validated KPIs, and evidence-ready reporting.

**Execution rhythm (kept fast)**
- Day 1: scope + attack scenarios + acceptance checks.
- Days 2–3: build step targets.
- Day 4: integrate and harden.
- Day 5: replay attacks, measure KPIs, publish sprint evidence.

**Decision speed rule**
- If blocked > 24h, use safe fallback and keep progress (templates > LLM, local rules > advanced correlation).

**Weekly evidence rule**
- Always ship: KPI delta, top detected techniques, one end-to-end trace/screenshot, and next bottleneck list.

### 2.5.2 LLM Visibility and Intervention Model (Practical)
- **Will attackers know an LLM is responding?**
   - Target behavior: usually **no obvious indication**.
   - They may suspect AI if responses are too verbose, too polite, inconsistent, or not protocol-realistic.
   - Design rule: short service-like outputs, realistic delays, consistent session memory, strict fallback templates.

- **When does AI intervene?**
   - **Step 2:** static deception only (no LLM required).
   - **Step 4 onward:** LLM augments responses under guardrails; static templates remain fallback.

- **SSH intervention examples (Step 4+)**
   - Attacker command: `ls /var/www` → LLM returns plausible decoy directory listing consistent with prior session state.
   - Attacker command: `cat /etc/os-release` → LLM returns coherent fake distro details aligned with banner/fingerprint.
   - Unknown command sequence → LLM returns realistic shell-like error/output, never real host data.

- **HTTP intervention examples (Step 4+, primary channel)**
   - `POST /login` with SQLi payload → LLM generates believable app-style validation/denial message (not generic chatbot text).
   - `GET /api/v1/users` → LLM returns structured decoy JSON with realistic fields/timestamps and consistent schema.
   - `GET /admin` probing → LLM selects plausible `401/403/404` behavior with coherent headers/body style.

- **Safety boundary (always)**
   - No real command execution, no sensitive data exposure, no outbound attacker-controlled action.
   - If policy/confidence checks fail, route immediately to deterministic static response.

### 2.6 What “done” looks like at a global level
- Attackers can interact naturally with the system.
- Dynamic responses remain coherent and policy-safe.
- Alerts include context, confidence, and mapped techniques.
- Multiple agents improve detection context through shared intel.
- Full system is reproducible in lab conditions with documented runbook.

---

## 3) Consolidated Architecture Baseline (Decision-Ready)

### Core Layers
1. **Deception Ingress Layer**
   - SSH honeypot agent (Cowrie-based)
   - HTTP honeypot agent (FastAPI-based)
2. **Session Orchestration & Policy Layer**
   - session state manager
   - guardrail/policy validator
   - response routing (template vs LLM)
3. **AI Interaction Layer**
   - local LLM adapter (Ollama)
   - prompt builder + context window manager
   - output plausibility/safety checks
4. **Telemetry & Enrichment Layer**
   - normalized event schema
   - IOC extraction + ATT&CK mapping
5. **Detection & Correlation Layer**
   - rule engine + session risk scoring
   - cross-agent intelligence bus (Redis streams/pubsub)
6. **SOC & Operations Layer**
   - ELK ingestion/indexing/dashboards
   - admin/supervision UI

### Contract-First Principle
Every layer must exchange structured contracts before implementation:
- Event contract
- LLM response contract
- Alert contract
- Inter-agent threat message contract

---

## 4) Enhanced Delivery Plan (12 Weeks, Quality-Gated)

## Phase P0 — Alignment, Threat Model, and Contracts (Week 1)
**Objective**: freeze architecture assumptions and measurable criteria.

**Outputs**
- Threat model (attacker profiles + attack narratives)
- Versioned contracts (event/alert/agent-intel)
- NFR baseline (latency, precision, containment, availability)
- Legal/ethical lab operation policy

**Exit Gate**
- Contracts reviewed and accepted by all team members.
- NFR targets documented with test method per metric.

---

## Phase P1 — Deception Surface Foundation (Weeks 2–3)
**Objective**: build believable SSH/HTTP interaction capture and replayable telemetry.

**Outputs**
- Realistic SSH and HTTP emulation baseline
- Session identifiers unified across both channels
- End-to-end log flow into SIEM index

**Exit Gate**
- External scanning and manual interaction do not instantly expose static fakery.
- Event completeness > 90% for required schema fields.

---

## Phase P2 — LLM-Orchestrated Dynamic Responses (Weeks 4–5)
**Objective**: add dynamic response generation under strict policy control.

**Outputs**
- Orchestrator with deterministic policy checks
- Context-aware prompts by service type
- Response validator with fallback templates

**Exit Gate**
- Session coherence sustained for multi-step attacker flows.
- P95 response latency within agreed threshold.
- Prompt-injection safety tests pass baseline policy checks.

---

## Phase P3 — Behavioral Analytics & Detection Quality (Weeks 6–7)
**Objective**: deliver explainable and measurable detection.

**Outputs**
- Rule pack v1 (brute-force, recon, suspicious transfer, persistence attempts)
- Session risk scoring model (weighted explainable formula)
- ATT&CK technique mapping and evidence trail

**Exit Gate**
- Precision/recall measured on labeled scenarios.
- Every critical alert includes actionable context and evidence references.

---

## Phase P4 — Multi-Agent Intelligence Correlation (Week 8)
**Objective**: prove that agents improve one another’s situational awareness.

**Outputs**
- Inter-agent message channels + TTL strategy
- Shared IP/behavior reputation propagation
- Correlated campaign view across multiple agents

**Exit Gate**
- Demonstrated reduction in detection delay or increase in confidence via shared intel.

---

## Phase P5 — Admin/SOC Experience (Week 9)
**Objective**: make output operationally useful for analysts and demo audiences.

**Outputs**
- Live attack timeline
- Session replay and behavior summary
- Health and model-latency observability panels

**Exit Gate**
- Analysts can triage top threats without raw log access.

---

## Phase P6 — Integrated Validation and Hardening (Week 10)
**Objective**: run full system tests under adversarial and load conditions.

**Outputs**
- Integrated test campaign report
- Performance + resilience benchmark results
- Hardening checklist status

**Exit Gate**
- No containment-critical failures.
- Stability and KPI thresholds met for demo conditions.

---

## Phase P7 — Finalization, Reporting, and Defense Prep (Weeks 11–12)
**Objective**: convert engineering output into academic and SOC-quality deliverables.

**Outputs**
- Final technical report
- Architecture diagrams and KPI dashboard snapshots
- Reproducible runbook and demo narrative

**Exit Gate**
- Full project can be reproduced from clean environment using documented steps.

---

## 5) Parallel Workstreams (Team Coordination Model)

### Workstream A — Deception & Infrastructure
- Honeypot realism (SSH/HTTP)
- network isolation and service hardening
- SIEM plumbing and dashboard observability

### Workstream B — AI Orchestration & Analytics
- LLM pipeline + guardrails
- session context and response quality
- detection scoring and ATT&CK mapping

### Shared Integration Cadence
- twice-weekly integration checkpoints
- one decision log update per checkpoint
- one measurable KPI update per week

---

## 6) KPI Scorecard (Project Evaluation Backbone)

### Realism KPIs
- Median attacker session length
- Multi-step command continuity score
- Honeypot fingerprint detection rate (lower is better)

### Detection KPIs
- Precision / recall on controlled scenarios
- Mean time to detection (MTTD)
- ATT&CK mapping coverage (% of high-priority scenarios)

### Security/Safety KPIs
- Containment violations (target: zero)
- Policy-blocked unsafe LLM outputs (tracked count + ratio)
- Unauthorized outbound connection attempts (target: zero)

### Operations KPIs
- P95 end-to-end response latency
- Service uptime during test windows
- Event ingestion loss rate

---

## 7) Risk Register (Enhanced)

1. **LLM realism drift**
   - Mitigation: bounded persona templates + response validator + fallback profiles.
2. **Prompt injection / policy bypass**
   - Mitigation: strict role separation, denylist/allowlist policy gates, adversarial prompt tests.
3. **Honeypot fingerprinting by advanced attackers**
   - Mitigation: timing jitter realism, coherent host identity, artifact consistency checks.
4. **Event noise / false positives**
   - Mitigation: staged threshold tuning using labeled attack traces.
5. **Resource bottlenecks (LLM latency spikes)**
   - Mitigation: queueing, context truncation policy, model tiering strategy.
6. **Integration instability**
   - Mitigation: contract tests at each phase gate and controlled integration cadence.

---

## 8) Documentation and Governance Plan

## Required Artifacts
- Architecture Decision Log (ADL)
- Threat Model document
- Contracts specification
- KPI Tracking sheet
- Test Evidence report (scenario-by-scenario)
- Final report and defense deck

## Decision Log Template
- Context
- Options considered
- Decision
- Security impact
- Operational impact
- Validation method
- Revisit trigger/date

---

## 9) Planning Delta vs Existing Plans (What was enhanced)

This enhanced plan improves clarity by:
1. separating **mission, non-goals, and measurable success**,
2. adding **contract-first gates** before build work,
3. defining **quality exit gates per phase**,
4. introducing a **KPI scorecard** tied to evaluation,
5. formalizing **parallel workstreams + integration cadence**,
6. strengthening **risk-to-mitigation mapping**,
7. tightening **documentation governance** for academic defensibility.

---

## 10) Immediate Planning Next Steps (Still Planning, No Implementation)

1. Confirm phase gates and KPI thresholds with all stakeholders.
2. Freeze the four canonical contracts (event, response, alert, intel-message).
3. Approve the risk register and legal/ethical lab boundaries.
4. Lock timeline feasibility (12-week baseline vs 14-week fallback).
5. Approve final deliverables checklist for defense readiness.

## Clarification: Why Dynamic Honeypots (and not just IP collection)

### What we are building
We will deploy a controlled decoy environment exposing SSH and HTTP services.  
Attackers can discover and interact with these services, while we capture telemetry safely.

### Core confusion resolved
It is true that we can collect attacker IP addresses, but IP-only intelligence is insufficient:
- IPs are often disposable (VPN/proxy/Tor/botnets)
- IPs alone do not reveal attacker methodology
- Blocking IPs gives short-lived value

### Why dynamic behavior is important
If SSH/HTTP responses are static, attackers quickly identify honeypots and disengage.  
Dynamic, policy-bounded behavior (session-aware responses, realistic command output, realistic web content variants) increases interaction depth and realism.

This helps us capture:
- TTPs (tools, commands, persistence techniques)
- Exploit chains and post-exploitation behavior
- Indicators of compromise (domains, hashes, paths, payloads)
- Adversary sophistication and intent

### Why realism matters (filesystem + web pages)
Realistic decoy artifacts increase attacker trust and dwell time.  
Longer, believable interaction produces higher-fidelity data for:
- better detection engineering (SIEM/EDR rules)
- stronger incident response playbooks
- threat hunting hypotheses
- security awareness and red-team simulation quality

### Practical objective
The system is not only to “know who touched us,” but to understand:
1. how they got in,
2. what they tried next,
3. what indicators they left,
4. and how to detect/stop this faster in real production systems.

---

## 12) Stack Lock (Final Technology Choices)

> This section is **normative** for implementation. Any change must be documented with rationale.

### 12.1 Core stack decision matrix

| Layer | Options compared | Selected | Why selected |
|---|---|---|---|
| SSH Honeypot | Cowrie / OpenCanary / custom Paramiko | **Cowrie** | Most realistic attacker interaction + rich telemetry |
| HTTP Honeypot | OpenCanary HTTP / custom app | **FastAPI fake service** | Full control for LLM-driven deception flows |
| LLM Orchestration | Direct SDK / LangChain / LlamaIndex | **LangChain (light use)** | Structured prompt chains, guardrails, tool routing |
| LLM Model (local) | Qwen2.5 7B / Llama 3.1 8B / Mistral 7B | **Qwen2.5 7B Instruct** | Best quality/performance balance on student hardware |
| Event Bus | MQTT / Redis PubSub / NATS | **MQTT (Mosquitto)** | Simple multi-agent pub/sub with topic isolation |
| SIEM | Wazuh / ELK-only / Graylog / Security Onion | **Wazuh + OpenSearch** | Strong open-source SOC workflow and alerting |
| IDS | Suricata / Zeek / both | **Suricata (MVP)** | Faster operational deployment and signature alerts |
| DB | PostgreSQL / MongoDB | **PostgreSQL** | Structured analytics and strong query/reporting |
| Shared state | Redis / none | **Redis** | Session, counters, throttling, transient intelligence |
| API backend | FastAPI / Flask | **FastAPI** | Validation, async support, OpenAPI docs |
| Deployment | Docker Compose / Kubernetes | **Docker Compose** | Fast and reproducible for university scope |
| Reverse proxy | Nginx / Traefik | **Nginx** | Stable, familiar, easy TLS + routing |

### 12.2 Protocol decisions

| Protocol | Usage | Decision | Controls |
|---|---|---|---|
| SSH | Deception service | **Enabled** | Cowrie only, rate-limit, full session logging |
| HTTP/HTTPS | Fake admin/login/services | **Enabled** | Isolated app, strict input validation |
| MQTT | Inter-honeypot intelligence sharing | **Enabled (internal only)** | ACL + auth + private subnet |
| REST | Internal APIs (adapter/analysis/dashboard) | **Enabled** | Token auth, schema validation |
| Syslog/JSON | SIEM forwarding | **Enabled** | Normalized schema + signed transport where possible |

### 12.3 LLM policy (operational)

- **Primary:** local model (`Qwen2.5 7B Instruct`) via Ollama/vLLM.
- **Fallback:** cloud LLM optional, disabled by default.
- **Guardrails:** allowlist response templates, denylist keywords, max token limits, timeout fallback.
- **No autonomous actions:** LLM can generate interaction text only; no shell/system execution.

### 12.4 Open-source SIEM comparison summary

| SIEM | Advantages | Limitations | Final status |
|---|---|---|---|
| **Wazuh + OpenSearch** | SOC-ready workflows, rich detection ecosystem | Heavier resources | **Selected** |
| ELK-only | Flexible ingestion/search | More custom detection engineering | Rejected (MVP) |
| Graylog | Easy operations | Less security-native depth | Rejected |
| Security Onion | Very powerful NSM | Too heavy for current timeline | Rejected |

### 12.5 Version-lock (initial)

- Docker Engine + Compose plugin (latest stable)
- Cowrie (latest stable)
- FastAPI + Uvicorn (latest stable)
- Mosquitto (2.x stable)
- PostgreSQL (16.x)
- Redis (7.x)
- Suricata (7.x)
- Wazuh stack (latest compatible release)

> Exact pinned versions go in `.env` + `docker-compose.yml` image tags during implementation.
