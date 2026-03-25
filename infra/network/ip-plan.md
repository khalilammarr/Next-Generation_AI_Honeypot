# IP Plan (Lab)

| Node | OS | IP | Network Mode |
|---|---|---|---|
| Honeypot VM | Ubuntu Server 24.04 | 192.168.56.10/24 | Host-Only + NAT (maintenance) |
| Attacker VM | Kali Linux (preferred) / Ubuntu | 192.168.56.20/24 | Host-Only |
| SIEM Host (physical host machine) | Linux host OS | 192.168.56.30/24 (or host-only adapter IP) | Host-Only |

Notes:
- NAT is for updates only.
- No public exposure of lab services.
- Architecture lock: SIEM runs on host machine; honeypot and attacker run in separate VMs.
