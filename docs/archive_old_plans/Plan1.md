<response>
# Intelligent Honeypot using AI (LLMs) — Complete Engineering Work Plan

## 0) @brainstorming Phase (Architecture & Strategy Thinking First)

### 0.1 Problem framing
You are not building a “chatbot around a honeypot”. You are building a **deception system** where realism, operational safety, and measurable detection value matter more than model novelty.

Core design tension:
- If responses are too static: attacker fingerprints the trap quickly.
- If responses are too dynamic/uncontrolled: system leaks unsafe behavior, breaks plausibility, or becomes unstable.
- If telemetry is weak: no SOC value, no academic evaluation quality.

So the architecture must optimize for:
1. **Believability** (service realism and consistent state)
2. **Containment** (strong isolation and no pivot risk)
3. **Observability** (high-quality event capture and enrichment)
4. **Determinism under policy** (LLM constrained by guardrails)
5. **Scalability** (multi-agent intelligence sharing)

---

### 0.2 Threat and adversary model (for realistic scope)
Assume 3 attacker profiles:
- **Opportunistic bot/scanner**: mass scan, default creds, scripted commands.
- **Interactive intruder**: manual SSH session, reconnaissance, privilege attempts.
- **Smarter red-teamer**: fingerprinting honeypot artifacts, timing analysis, consistency checks.

What they do:
- Port scanning / banner grab (`nmap`, `masscan`)
- Credential stuffing / brute force
- Command execution (`uname`, `id`, `cat /etc/passwd`, `wget`, `curl`)
- HTTP probing (`/admin`, `/wp-login.php`, `/phpmyadmin`, upload endpoints)
- Persistence attempts and privilege checks

What your system must prove:
- It captures and classifies these actions.
- It remains believable during multi-step sessions.
- It emits SIEM-usable alerts with context.
- It shares attacker intelligence across honeypot agents.

---

### 0.3 Key architectural decisions (the ones that make or break the project)

#### Decision A: High-interaction vs medium-interaction
- **Recommended**: Medium interaction for SSH (Cowrie), controlled HTTP emulation (FastAPI).
- Why: safer and feasible for university timeline while still realistic enough.

#### Decision B: Where LLM sits in the control path
- **Recommended**: LLM behind a **Policy/Orchestration Layer**, never directly exposed.
- LLM only generates candidate responses; policy engine validates before output.

#### Decision C: Local LLM vs cloud API
- **Recommended for this project**: local model via Ollama for privacy, repeatability, and offline testing.
- Add optional abstraction for cloud fallback.

#### Decision D: Shared intelligence protocol
- **Recommended**: Redis pub/sub + Redis streams for event fanout and replay.
- Pub/Sub for near real-time, Streams for durability/reprocessing.

#### Decision E: Behavior analytics approach
- **Recommended**: hybrid
  - Rule-based detections (high precision baseline)
  - Statistical/session scoring
  - Optional LLM summarization for analyst-readable context (not primary detector)

#### Decision F: Safety constraints
- Strict egress controls, no outbound attack capability.
- No real shell execution on host.
- Sanitized payload handling and malware sample quarantine.

---

### 0.4 High-risk areas and mitigations
1. **LLM hallucination breaks realism**
   - Mitigation: template grounding + finite-state session context + response validator.
2. **Prompt injection by attacker**
   - Mitigation: structured prompts, role separation, strip unsafe instructions, allowlist tool usage.
3. **Honeypot fingerprinting**
   - Mitigation: realistic filesystem artifacts, timing jitter, service-specific error realism, consistent host identity.
4. **Resource exhaustion (DoS by scans)**
   - Mitigation: async queues, rate limiting per source IP, bounded context windows.
5. **False positives/low-quality detections**
   - Mitigation: ATT&CK-aligned event schema + calibration datasets + confusion matrix tracking.
6. **Containment failure**
   - Mitigation: container isolation, non-root, seccomp/AppArmor, read-only volumes where possible.

---

## 1) System Architecture (modules, data flow, technologies)

### 1.1 Reference architecture (logical modules)

1. **Ingress Deception Layer**
   - SSH Honeypot Agent: Cowrie-based, custom hooks.
   - HTTP Honeypot Agent: FastAPI service emulating admin/router/NAS interfaces.

2. **Session Orchestrator Layer**
   - Session manager (per attacker IP/session_id)
   - State store (short-term context: commands, path, fake filesystem state)
   - Policy engine (guardrails and response constraints)

3. **AI Interaction Layer**
   - LLM adapter (Ollama API)
   - Prompt builder (service-specific personas)
   - Response post-processor (format and plausibility checks)

4. **Telemetry & Enrichment Layer**
   - Event normalizer (JSON schema)
   - MITRE ATT&CK mapper
   - IOC extractor (IP, domain, URL, hashes, command patterns)

5. **Detection & Correlation Layer**
   - Rule engine (Sigma-like patterns or custom Python rules)
   - Behavioral profiler (session risk score, attacker intent)
   - Multi-agent correlation (shared reputation over Redis)

6. **SOC/SIEM Integration Layer**
   - Logstash/Elastic ingestion
   - Alerting pipeline (email/webhook/Slack optional)
   - Kibana dashboards

7. **Admin & Operations Layer**
   - Dashboard (attack timeline, sessions, source map, TTP stats)
   - Agent health view (uptime, model latency, queue depth)
   - Deployment controls (enable/disable persona profiles)

---

### 1.2 Data flow (end-to-end)
1. Attacker connects via SSH or HTTP.
2. Agent captures raw interaction event.
3. Event enters orchestrator with session context.
4. Policy checks whether dynamic response is needed.
5. If yes: prompt builder + LLM inference + validator.
6. Response returned to attacker (with realistic delay profile).
7. Full event (raw + enriched + decision metadata) is sent to Redis stream and ELK pipeline.
8. Detection engine scores session and emits alert if thresholds/rules match.
9. Reputation/IP/TTP info broadcast to other agents.
10. Dashboard visualizes attack and analyst summary.

---

### 1.3 Recommended technology stack

- **Language**: Python 3.11+
- **SSH honeypot**: Cowrie (custom output plugin + event hook)
- **HTTP honeypot**: FastAPI + Uvicorn
- **LLM runtime**: Ollama (`llama3`, `mistral`, or smaller tuned model for latency)
- **Orchestration patterns**: LangChain/LangGraph (optional but useful for stateful flows)
- **Message bus / shared memory**: Redis (Pub/Sub + Streams)
- **SIEM/log stack**: ELK (Elasticsearch + Logstash + Kibana)
- **Data persistence**: PostgreSQL (sessions, analytics snapshots), optional MinIO for artifacts
- **Containerization**: Docker + Docker Compose
- **Testing tools**: Hydra, Nmap, Metasploit modules (controlled lab), Locust for load
- **Security hardening**: Falco (optional), AppArmor/seccomp profiles

---

## 2) Development Phases (timeline with milestones)

Recommended timeline: **10 weeks** (can compress to 8 if needed)

### Milestone 0 (Week 1): Foundations and safety baseline
- Define architecture and event schema (`event_id`, `session_id`, `src_ip`, `service`, `action`, `ttp`, `severity`).
- Prepare Docker network segmentation.
- Establish legal/ethical lab rules and traffic boundaries.

**Exit criteria**:
- Compose stack boots cleanly.
- Network isolation validated.
- Baseline logging visible in Kibana.

### Milestone 1 (Weeks 2–3): Realistic service emulation
- Integrate Cowrie SSH with custom config/persona.
- Build HTTP deception endpoints (`/admin`, `/login`, fake panels).
- Implement static believable responses and fake asset corpus.

**Exit criteria**:
- External scan sees realistic SSH/HTTP surfaces.
- Session logs capture commands, headers, paths, auth attempts.

### Milestone 2 (Weeks 4–5): LLM dynamic interaction pipeline
- Implement orchestrator and policy guardrails.
- Build prompt templates by service type (SSH shell vs HTTP app).
- Add context memory (bounded to last N actions and synthetic host state).

**Exit criteria**:
- Multi-step attacker interactions remain coherent.
- LLM response latency target met (P50 and P95 tracked).

### Milestone 3 (Weeks 6–7): Detection and behavioral analytics
- Rule-based detectors (brute force, recon, tool transfer, privilege attempts).
- Session scoring model (weighted behavior vectors).
- MITRE ATT&CK mapping and SIEM alert formatting.

**Exit criteria**:
- Alerts fire on known attack playbooks.
- Detection quality measured (precision/recall on test scenarios).

### Milestone 4 (Week 8): Multi-agent intelligence sharing
- Redis channels for threat intel sharing (`bad_ip`, `ttp_observed`, `campaign_id`).
- Cross-node reputation scoring and event correlation.
- Dashboard panel for multi-agent event graph.

**Exit criteria**:
- Attack observed on Agent A is reflected on Agent B within target SLA.

### Milestone 5 (Weeks 9–10): Hardening, evaluation, and report
- Performance tuning and resilience tests.
- Full demonstration scenario and metrics collection.
- Final report and reproducible deployment package.

**Exit criteria**:
- End-to-end demo reproducible.
- Final metrics and architecture rationale documented.

---

## 3) Team of 2 — task distribution

### Student A: Security/Infrastructure Lead
Primary ownership:
- Docker/Compose architecture and network segmentation
- Cowrie and HTTP service realism
- ELK pipeline, alerting wiring, dashboard ops metrics
- Security hardening (container/user perms, egress controls)

Deliverables:
- Stable infrastructure stack
- Hardened and believable deception surface
- SIEM-ready telemetry path

### Student B: AI/Backend/Analytics Lead
Primary ownership:
- LLM orchestration and policy engine
- Session context memory + prompt templates
- Behavioral analytics and threat scoring
- Multi-agent correlation logic (Redis + correlation service)

Deliverables:
- Safe, coherent dynamic interaction engine
- Detection/intelligence modules
- Analyst-friendly summaries

### Shared responsibilities
- Attack simulation campaign design
- Acceptance test execution
- Documentation and final report narrative

---

## 4) Implementation details (how to build each part)

### 4.1 SSH module (Cowrie + AI augmentation)
- Start with Cowrie native interaction.
- Hook command events using output plugin/webhook.
- Route selected commands to orchestrator:
  - benign/common commands → deterministic templates
  - complex contextual responses → LLM candidate generation
- Maintain fake filesystem/session state:
  - current directory
  - fake files created/deleted
  - user privilege context

**Critical rule**: never execute attacker commands on real host.

### 4.2 HTTP module (FastAPI deception app)
- Build realistic fake endpoints and auth forms.
- Add dynamic pages whose content is LLM-assisted but schema-controlled.
- Capture:
  - request headers, body, query params
  - auth attempts
  - user-agent fingerprints
  - payload signatures (basic)

### 4.3 Orchestrator + guardrails
Implement a “response contract”:
- Input: event + session context + service policy
- Output: `response_text`, `delay_ms`, `confidence`, `policy_flags`
- Validator checks:
  - no policy-violating content
  - service-consistent format
  - no leakage of honeypot internals
  - max length and token budget

### 4.4 Event schema and pipeline
Normalize all events to one schema:
- Identity: `timestamp`, `agent_id`, `session_id`, `src_ip`, `dst_port`
- Interaction: `service`, `action_type`, `raw_input`, `response_type`
- Enrichment: `mitre_tactic`, `mitre_technique`, `ioc_list`, `risk_score`
- AI metadata: `model`, `latency_ms`, `guardrail_decision`

Send to:
- Redis stream (near real-time processing)
- Logstash/Elasticsearch (indexing, dashboards, alerting)

### 4.5 Detection engine
Start simple and measurable:
- Rule set v1:
  - brute force threshold
  - recon command clusters
  - suspicious file retrieval commands
  - known scanner fingerprints
- Session score formula (example):

$$
Risk = 0.30\cdot AuthAbuse + 0.25\cdot Recon + 0.20\cdot ExploitPattern + 0.15\cdot Persistence + 0.10\cdot IOCSeverity
$$

- Trigger alert if rule hit OR `Risk > threshold`.

### 4.6 Multi-agent protocol
Define compact message contracts:
- `threat.observed`
- `ip.reputation.update`
- `campaign.suspected`
- `ttp.new`

Each message includes:
- `source_agent`, `timestamp`, `entity`, `confidence`, `ttl`, `evidence_ref`

Use TTL to avoid stale intelligence poisoning.

---

## 5) Testing strategy (real attack simulation + validation)

### 5.1 Test categories
1. **Functional tests**
   - SSH/HTTP service behavior correctness
   - Event ingestion and schema validation
2. **Adversarial realism tests**
   - Manual attacker session to test consistency over time
   - Fingerprinting attempts (timing, banners, artifacts)
3. **Detection quality tests**
   - Replay known attack scripts and verify alert labels
   - Evaluate precision/recall and false positive rate
4. **Performance tests**
   - Concurrent sessions, queue pressure, LLM latency
5. **Resilience/safety tests**
   - Container restart recovery
   - malformed payload handling
   - no outbound abuse path

### 5.2 Attack simulation playbook
- **Scenario A**: brute-force SSH + simple recon
- **Scenario B**: authenticated session + privilege escalation attempts
- **Scenario C**: HTTP admin probing + malicious payload submission
- **Scenario D**: coordinated scans against multiple agents

For each scenario collect:
- detection time
- alert quality
- interaction coherence score
- mean and P95 response latency

### 5.3 Suggested success KPIs
- > 90% structured event completeness
- > 80% precision on labeled attack scenarios
- < 1.2s P95 dynamic response latency (local LLM target, tune by model)
- multi-agent propagation delay < 3s in lab conditions

---

## 6) Deployment strategy

### 6.1 Environments
- **Dev**: local Docker Compose on student machines
- **Integration**: one shared lab server with complete stack
- **Demo/Final**: clean reproducible compose profile with seeded data

### 6.2 Deployment model
- Use versioned `docker-compose.yml` profiles:
  - `core` (SSH/HTTP + Redis)
  - `ai` (Ollama + orchestrator)
  - `soc` (ELK + dashboard)

- Add healthchecks and startup dependencies.
- Persist volumes for logs and model cache.

### 6.3 Operational hardening checklist
- Non-root containers where possible
- Restricted Docker network and iptables egress policy
- Secrets in env files or secret manager (never hardcoded)
- Resource quotas (CPU/RAM) to prevent model starvation
- Rotating logs and index lifecycle policy in Elasticsearch

---

## 7) Practical backlog (step-by-step execution checklist)

1. Freeze event schema and folder structure.
2. Bring up base Compose (`cowrie + redis + elk`).
3. Validate log ingestion from Cowrie to Elasticsearch.
4. Implement minimal HTTP honeypot and log forwarding.
5. Build orchestrator API (`/respond`, `/enrich`, `/score`).
6. Integrate Ollama adapter and first prompt templates.
7. Add response validator and guardrail policy set.
8. Add session memory store and fake host-state manager.
9. Implement detection rule pack v1.
10. Add ATT&CK mapping and SIEM alert formatter.
11. Implement Redis multi-agent threat message channels.
12. Build monitoring dashboard views (sessions, risk, TTPs, agent health).
13. Run controlled attack simulations and capture metrics.
14. Tune latency, thresholds, and realism artifacts.
15. Produce final report with architecture diagrams and KPI outcomes.

---

## 8) Risks, trade-offs, and decision log template

Track these weekly:
- **Model choice vs latency**: quality improves with larger model, but response delay increases.
- **Realism vs safety**: do not emulate dangerous capability if it risks abuse.
- **Detection sensitivity vs false positives**: adjust thresholds with empirical evidence.
- **Storage cost vs observability depth**: tune retention and indexing strategy.

Decision log format:
- Context
- Options considered
- Decision
- Security impact
- Performance impact
- Revisit date

---

## 9) Advanced ideas (if core scope is completed early)

1. **RAG-based deception memory**
   - Retrieve service-specific historical patterns to improve consistency.
2. **Campaign clustering**
   - Group sessions by command sequence similarity and infrastructure overlap.
3. **Adaptive persona switching**
   - Auto-switch host profile (router, NAS, Linux server) based on attacker behavior.
4. **Canary-token integration**
   - Plant fake credentials/documents and alert on exfil attempts.
5. **Graph analytics**
   - Build attacker infrastructure graph (IP-domain-hash relation) for SOC context.

---

## 10) Final implementation recommendation (practical and realistic)

If you want the highest chance of delivering a strong university project on time:
- Build a **robust medium-interaction honeypot** first.
- Add **LLM only where it creates measurable realism value**.
- Keep **detectors simple, explainable, and ATT&CK-aligned**.
- Show **multi-agent benefit with clear before/after metrics**.
- Prioritize **stability, reproducibility, and safety** over feature count.

This gives you a project that is both academically defensible and technically credible in front of cybersecurity professionals.
</response>
