# ExectuionTaskBreakdown — Guide d’exécution détaillé (Équipe de 4)

## Objectif
Transformer `EnhancedPlanUnified.md` en exécution concrète, avec tasks ordonnées, étapes techniques précises, responsables (4 personnes), critères de validation, et artefacts attendus.

## Équipe (répartition logique)
- **P1 — Infra & Sécurité Lab**: VM, réseau, isolation, durcissement Docker.
- **P2 — Honeypots & Deception**: Cowrie SSH + service HTTP leurre.
- **P3 — IA & Orchestrateur**: Ollama, policy layer, prompts, fallback.
- **P4 — SIEM, Détection & Dashboard**: pipeline ELK/Grafana, règles ATT&CK, KPI.

> Note: certaines tasks sont transverses; tous les membres peuvent contribuer selon charge. L’important est le respect des étapes et validations.

---

## Vue d’exécution (ordre obligatoire)
1. Task 01–03: environnement lab prêt et sécurisé.
2. Task 04–06: deception SSH/HTTP stable.
3. Task 07–08: normalisation événements + bus inter-agents.
4. Task 09–10: IA dynamique sous garde-fous.
5. Task 11–13: détection, dashboard, validation KPI.
6. Task 14: packaging final et runbook de démonstration.

---

## Task 01 — Préparer les VMs (Honeypot + Attacker)
**Owner principal:** P1  
**Support:** P2

### Étapes
1. Installer VirtualBox/VMware (ou Proxmox si dispo labo).
2. Créer **VM-HONEYPOT**:
   - Ubuntu Server 24.04 LTS
   - 4 vCPU, 8 GB RAM, 80 GB SSD
   - 2 interfaces réseau:
     - `eth0` NAT (updates)
     - `eth1` Host-Only/Lab (trafic attaque)
3. Créer **VM-ATTACKER**:
   - Kali Linux ou Ubuntu + outils
   - 2 vCPU, 4 GB RAM, 40 GB SSD
   - Même réseau lab (`eth1`)
4. Configurer IPs statiques (exemple):
   - VM-HONEYPOT: `192.168.56.10/24`
   - VM-ATTACKER: `192.168.56.20/24`
5. Sur VM-HONEYPOT:
   - `sudo apt update && sudo apt upgrade -y`
   - `sudo timedatectl set-timezone Africa/Tunis` (ou timezone équipe)

### Validation
- Depuis VM-ATTACKER: `ping 192.168.56.10` OK.
- Depuis VM-HONEYPOT: `ping 192.168.56.20` OK.
- Snapshot des deux VMs créé: `baseline-clean`.

### Artefacts
- Capture écran IP + interfaces.
- Fichier `docs/lab-network.md` (à créer).

---

## Task 02 — Installer runtime Docker et outils système
**Owner principal:** P1  
**Support:** P3

### Étapes
1. Installer Docker + Compose plugin:
   - `sudo apt install -y ca-certificates curl gnupg`
   - `curl -fsSL https://get.docker.com | sh`
   - `sudo usermod -aG docker $USER`
   - Re-login session
2. Vérifier:
   - `docker --version`
   - `docker compose version`
3. Installer utilitaires:
   - `sudo apt install -y jq git make htop net-tools ufw`
4. Cloner/ouvrir le projet:
   - `cd /home/khalil/Projects/PPP`

### Validation
- `docker run --rm hello-world` fonctionne.
- `docker ps` sans sudo fonctionne.

### Artefacts
- Log d’installation dans `docs/install-log.md`.

---

## Task 03 — Isoler et durcir le lab (règles minimales)
**Owner principal:** P1  
**Support:** P4

### Étapes
1. Activer UFW sur VM-HONEYPOT:
   - `sudo ufw default deny incoming`
   - `sudo ufw default allow outgoing`
2. Ouvrir uniquement ports nécessaires lab:
   - `sudo ufw allow 2222/tcp` (SSH honeypot)
   - `sudo ufw allow 8000/tcp` (HTTP honeypot)
   - `sudo ufw allow 3000/tcp` (Grafana)
   - `sudo ufw allow 1883/tcp` (MQTT)
   - `sudo ufw allow 11434/tcp` (Ollama interne)
3. `sudo ufw enable`
4. Ajouter politique: pas d’exposition internet publique du lab.
5. Créer doc politique sécurité: `docs/lab-security-policy.md`.

### Validation
- `sudo ufw status numbered` montre seulement ports attendus.
- Scan depuis VM-ATTACKER montre ports ouverts conformes.

### Artefacts
- `docs/lab-security-policy.md`
- Export `ufw status`.

---

## Task 04 — Démarrer la stack existante et corriger les bases
**Owner principal:** P2  
**Support:** P1

### Étapes
1. Depuis racine projet: `docker compose up -d`
2. Vérifier services:
   - `docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"`
3. Vérifier logs initiaux:
   - `docker logs cowrie-ssh --tail 50`
   - `docker logs honey-mqtt --tail 50`
   - `docker logs ollama-server --tail 50`
   - `docker logs honey-dashboard --tail 50`
4. Si un service crash, corriger config immédiatement avant suite.

### Validation
- Les 4 conteneurs restent `Up` > 2 min.
- Port 2222, 1883, 3000, 11434 répondent.

### Artefacts
- Capture `docker ps`.

---

## Task 05 — Implémenter et brancher le honeypot HTTP
**Owner principal:** P2  
**Support:** P3

### Étapes
1. Vérifier contenu existant `honeypot/http/agent.py` + `Dockerfile`.
2. Ajouter service `http-honeypot` dans `docker-compose.yml`:
   - build `./honeypot/http`
   - port `8000:8000`
   - env `OLLAMA_URL=http://ollama-server:11434/api/generate`
   - restart `always`
3. Démarrer service:
   - `docker compose up -d --build http-honeypot`
4. Tester endpoint:
   - `curl -i http://192.168.56.10:8000/admin`
   - `curl -i http://192.168.56.10:8000/login`
5. Si nécessaire, limiter réponses LLM (taille/réponse HTML sûre).

### Validation
- `http-honeypot` est `Up`.
- Réponse HTML renvoyée sur chemins testés.

### Artefacts
- Mise à jour `docker-compose.yml`.
- Logs `http-honeypot` (tail 50).

---

## Task 06 — Stabiliser le SSH honeypot (Cowrie) et collecte commandes
**Owner principal:** P2  
**Support:** P4

### Étapes
1. Vérifier `honeypot/ssh/cowrie.cfg`:
   - écoute sur `0.0.0.0:2222`
   - hostname plausible.
2. Depuis VM-ATTACKER:
   - `ssh -p 2222 root@192.168.56.10`
   - Exécuter commandes test: `uname -a`, `id`, `ls /`
3. Vérifier logs Cowrie:
   - `docker exec -it cowrie-ssh ls /home/cowrie/cowrie-git/var/log/cowrie`
   - `docker logs cowrie-ssh --tail 100`
4. Créer checklist réalisme SSH: bannière, prompts, erreurs, latence.

### Validation
- Session SSH simulée complète sans crash.
- Commandes de test apparaissent dans logs.

### Artefacts
- `docs/ssh-realism-checklist.md`.

---

## Task 07 — Définir le schéma unifié d’événements (contract-first)
**Owner principal:** P4  
**Support:** P2, P3

### Étapes
1. Créer `docs/contracts/event-contract.json` avec champs obligatoires:
   - `timestamp`, `session_id`, `src_ip`, `service`, `action`, `raw_input`, `severity`, `ttp`.
2. Créer exemples JSON:
   - `docs/contracts/examples/ssh-event.json`
   - `docs/contracts/examples/http-event.json`
3. Définir niveaux sévérité (`low`, `medium`, `high`, `critical`).
4. Définir dictionnaire actions (`auth_attempt`, `command_exec`, `http_probe`, etc.).

### Validation
- Tous les événements tests SSH/HTTP peuvent être mappés sans champ manquant.

### Artefacts
- `docs/contracts/event-contract.json`
- `docs/contracts/examples/*.json`

---

## Task 08 — Bus inter-agents (MQTT) + publication d’intel
**Owner principal:** P3  
**Support:** P4

### Étapes
1. Vérifier `scripts/llm-backend/main.py` et topic actuel.
2. Standardiser topics:
   - `honey/events/raw`
   - `honey/intel/reputation`
   - `honey/alerts`
3. Implémenter publication test depuis terminal:
   - `docker exec -it honey-mqtt sh`
   - utiliser `mosquitto_pub`/`mosquitto_sub` (installer si besoin)
4. Ajouter message contract intel:
   - `ip`, `confidence`, `source_agent`, `ttl`, `evidence`.
5. Documenter mapping topic->payload.

### Validation
- Un message publié sur `honey/intel/reputation` est reçu par subscriber.

### Artefacts
- `docs/contracts/intel-message-contract.json`
- `docs/mqtt-topics.md`

---

## Task 09 — Orchestrateur IA (réponse dynamique sous politiques)
**Owner principal:** P3  
**Support:** P2

### Étapes
1. Créer module policy (nouveau fichier):
   - `scripts/llm-backend/policy.py`
2. Règles minimales:
   - bloquer commandes “réelles” dangereuses (pas d’exécution réelle)
   - limiter longueur sortie
   - fallback template si erreur LLM
3. Créer routeur (nouveau fichier):
   - `scripts/llm-backend/router.py`
   - mode: `template_first` puis `llm_if_needed`
4. Mettre à jour `main.py` pour intégrer policy + router.
5. Ajouter timeout requête Ollama (ex: 5s).

### Validation
- En cas d’échec Ollama: réponse fallback propre.
- Cas prompt injection testés -> neutralisés/loggés.

### Artefacts
- `scripts/llm-backend/policy.py`
- `scripts/llm-backend/router.py`
- MAJ `main.py`

---

## Task 10 — Templates deception (HTTP + SSH) cohérents
**Owner principal:** P2  
**Support:** P3

### Étapes
1. Créer templates HTTP dans `honeypot/http/templates/`:
   - `login.html`, `admin.html`, `error_403.html`, `error_404.html`
2. Ajouter réponses SSH templates (JSON/YAML) dans:
   - `honeypot/ssh/templates/commands.json`
3. Relier routeur IA pour utiliser templates en priorité.
4. Ajouter légère latence réaliste (jitter contrôlé).

### Validation
- 10 interactions consécutives cohérentes avec le même “host persona”.

### Artefacts
- `honeypot/http/templates/*`
- `honeypot/ssh/templates/commands.json`

---

## Task 11 — Détection v1 + mapping MITRE ATT&CK
**Owner principal:** P4  
**Support:** P3

### Étapes
1. Créer moteur simple (nouveau fichier):
   - `scripts/detection/rules_engine.py`
2. Ajouter règles initiales:
   - brute force SSH
   - recon commands
   - HTTP probing sensible
3. Mapper techniques ATT&CK (exemple):
   - T1110 (Brute Force)
   - T1059 (Command and Scripting Interpreter)
   - T1595 (Active Scanning)
4. Produire alert contract:
   - `docs/contracts/alert-contract.json`

### Validation
- Scénarios de test déclenchent alertes attendues avec TTP correct.

### Artefacts
- `scripts/detection/rules_engine.py`
- `docs/contracts/alert-contract.json`

---

## Task 12 — Dashboard opérationnel (Grafana + métriques)
**Owner principal:** P4  
**Support:** P1

### Étapes
1. Configurer datasource (ELK ou source intermédiaire).
2. Créer dashboard panels minimum:
   - attaques par service (SSH/HTTP)
   - top source IP
   - top ATT&CK techniques
   - latence LLM p95
   - taux fallback policy
3. Sauvegarder dashboard JSON dans `configs/grafana/dashboards/`.
4. Documenter accès dashboard:
   - URL, user/pass, procédure import.

### Validation
- Dashboard charge sans erreurs.
- Au moins 1 panel mis à jour en temps réel pendant attaque test.

### Artefacts
- `configs/grafana/dashboards/honeypot-overview.json`
- `docs/dashboard-access.md`

---

## Task 13 — Campagne de test (attaques simulées + KPI)
**Owner principal:** P1  
**Support:** P2, P3, P4

### Étapes
1. Depuis VM-ATTACKER, lancer scénarios:
   - `nmap -sV -p 2222,8000 192.168.56.10`
   - `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.10 -s 2222 -t 4`
   - probes HTTP (curl scripts)
2. Enregistrer résultats:
   - temps détection
   - qualité alertes
   - cohérence des réponses
3. Calculer KPI minimum:
   - taux complétude événements
   - précision baseline des règles
   - latence p95 IA
4. Créer rapport test.

### Validation
- Rapport contient traces, métriques, captures dashboard.

### Artefacts
- `docs/testing/campaign-01.md`
- `docs/testing/kpi-baseline.md`

---

## Task 14 — Packaging final + runbook demo
**Owner principal:** P1  
**Support:** Tous

### Étapes
1. Nettoyer `docker-compose.yml` final (services utilisés seulement).
2. Créer `README.md` d’exécution:
   - prérequis
   - `docker compose up -d --build`
   - tests smoke
   - troubleshooting
3. Créer script smoke test:
   - `scripts/smoke_test.sh`
   - vérifie ports, services, endpoints.
4. Préparer runbook soutenance:
   - scénario démo 10 min (attaque -> détection -> dashboard).

### Validation
- Environnement reproductible depuis VM neuve avec docs.

### Artefacts
- `README.md`
- `scripts/smoke_test.sh`
- `docs/demo-runbook.md`

---

## Cadence hebdomadaire recommandée (4 personnes)
- **Lundi**: plan sprint + risques + assignation tasks.
- **Mercredi**: checkpoint intégration (30 min).
- **Vendredi**: review KPI + preuve de progression (logs, screenshots, démos).

## Règles d’exécution
1. Pas de nouvelle feature sans validation de la task courante.
2. Si bloqué > 24h: fallback simple + avancer.
3. Chaque task doit produire un artefact concret (fichier/doc/trace).
4. Aucun test en production internet; uniquement lab contrôlé.

## Définition de “Done” globale
- Stack démarre proprement.
- SSH + HTTP interactifs et crédibles.
- Événements unifiés visibles dans dashboard.
- IA sous politiques (fallback fonctionnel).
- Alertes ATT&CK générées sur scénarios de test.
- Runbook permet une démo complète en 10 minutes.

---

## Appendix A — Stack Lock (Must-follow during execution)

This appendix is mandatory for all tasks. If a task proposes another tool, create a change request first.

### A.1 Final selected stack

| Category | Tooling locked |
|---|---|
| SSH honeypot | **Cowrie** |
| HTTP honeypot | **FastAPI deceptive web service** |
| LLM runtime | **Qwen2.5 7B Instruct (local)** via Ollama/vLLM |
| LLM orchestration | **LangChain (minimal)** |
| Multi-agent messaging | **MQTT (Mosquitto)** |
| SIEM/SOC | **Wazuh + OpenSearch** |
| IDS | **Suricata (MVP)** |
| Datastore | **PostgreSQL** |
| Cache/state | **Redis** |
| Deployment | **Docker Compose** |
| Reverse proxy | **Nginx** |

### A.2 Protocol baseline

| Protocol | Scope | Required controls |
|---|---|---|
| SSH | attacker ↔ honeypot | rate-limit, logging, isolated VM network |
| HTTP/HTTPS | attacker ↔ fake services | input validation, no real secrets/data |
| MQTT | honeypot ↔ honeypot | ACL, credentials, internal subnet only |
| REST | internal modules | token auth + schema validation |
| JSON/Syslog | SIEM ingestion | normalized schema, UTC timestamps |

### A.3 SIEM choice rationale (for reporting)

- **Selected:** Wazuh + OpenSearch
- **Reason:** best open-source SOC-like visibility for alerts, rule-based detections, dashboards.
- **Rejected for MVP:** ELK-only (too much custom rule engineering), Graylog (less security depth), Security Onion (too heavy).

### A.4 Execution rules linked to this stack

1. Do not introduce Grafana in MVP unless Wazuh dashboards are insufficient.
2. Do not replace MQTT with NATS/Redis PubSub in MVP.
3. Keep cloud LLM fallback disabled by default.
4. Any stack change must update:
   - architecture section,
   - task dependencies,
   - risk register,
   - test plan.
