# Day 01 Plan — Lab Bootstrap

## Goals
1. Validate isolated lab networking between Ubuntu (honeypot) and Kali (attacker).
2. Install Docker runtime on Ubuntu honeypot VM.
3. Install and verify Wazuh (preferably on physical host, else dedicated VM).
4. Connect Ubuntu honeypot VM as Wazuh agent.
5. Run first controlled attack simulation from Kali and confirm SIEM visibility.

## Success Criteria
- Ubuntu and Kali communicate on Host-Only network.
- Docker and Compose work on Ubuntu.
- Wazuh dashboard accessible and healthy.
- Ubuntu agent shows **active** in Wazuh.
- At least one scan/probe event visible in Wazuh timeline.

## Team Split (4 persons)
- P1: Infrastructure + network + hardening.
- P2: Honeypot services + service checks.
- P3: Agent onboarding + integration support.
- P4: Wazuh dashboard + evidence collection.
