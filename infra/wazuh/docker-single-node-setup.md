# Wazuh Docker Single-Node Setup (Host SIEM)

This runbook follows the official Wazuh Docker single-node deployment flow for `v4.14.4`, adapted to this project where the physical host is the SIEM node.

## Architecture
- Host machine: Wazuh SIEM (Docker single-node stack)
- Honeypot VM(s): attack telemetry sources
- Attacker VM: controlled test traffic

## Why Docker deployment for this project
We chose Docker deployment instead of native package installation or Kubernetes for practical and security reasons in this lab setup.

1. Reproducible setup across machines
- The same images and compose file produce the same stack on any teammate host.
- This reduces environment drift and shortens troubleshooting time.

2. Faster setup and rollback
- Single-node Wazuh can be deployed in minutes with `docker compose`.
- If a change breaks the stack, containers can be recreated cleanly without deep host cleanup.

3. Safer host isolation
- Services run in containers with explicit port publishing instead of broad host-level service installs.
- This makes network exposure easier to audit and restrict with VPN ACL + host firewall rules.

4. Easier upgrades and version pinning
- We pin Wazuh to a known version (`v4.14.4`) and upgrade intentionally.
- Rolling back to a previous known-good version is straightforward.

5. Better fit for this scope than Kubernetes
- This environment is a single-node SIEM lab, not a multi-node production cluster.
- Kubernetes would add operational complexity without clear benefit for current requirements.

6. Better fit for this scope than native install
- Native installs are valid, but they couple components directly to host package state and init/system services.
- For training/lab workflows, containerized lifecycle management is simpler and more predictable.

Summary:
- Docker gives us repeatability, controlled exposure, and lower operational overhead while still matching the project security model (VPN-only access + allowlisted teammates + least privilege).

## Prerequisites
- Docker Engine running on host
- Docker Compose available (`docker compose`)
- Git installed
- Host resources for single-node stack:
  - CPU: >= 4 cores
  - RAM: >= 8 GB
  - Disk: >= 50 GB

## Required host tuning
Set kernel map count (required for Wazuh indexer):

```bash
sudo sysctl -w vm.max_map_count=262144
```

To persist across reboots, add:

```conf
vm.max_map_count=262144
```

in `/etc/sysctl.d/99-wazuh.conf`, then reload:

```bash
sudo sysctl --system
```

## Deployment steps

### 1) Clone Wazuh Docker repository
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.4
cd wazuh-docker/single-node
```

### 2) Generate certificates
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

Generated certs are placed under:
- `single-node/config/wazuh_indexer_ssl_certs/`

### 3) Start stack
```bash
docker compose up -d
```

### 4) Validate containers
```bash
docker compose ps
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 5) Access dashboard
- URL: `https://<DOCKER_HOST_IP>`
- Default username: `admin`
- Default password: `SecretPassword`

If browser warns about self-signed certificate, this is expected initially.

## Exposed ports (Wazuh central components)
- `1514/tcp` Wazuh events
- `1515/tcp` Wazuh auth
- `514/udp` Syslog
- `55000/tcp` Wazuh API
- `9200/tcp` Indexer API
- `443/tcp` Dashboard HTTPS

## Expected startup behavior
You may see temporary dashboard logs like:
- `Failed to connect to Wazuh indexer port 9200`
- `Wazuh dashboard server is not ready yet`

This is normal while indexer initializes (about 1 minute).

## Post-deployment hardening (mandatory)
1. Change default Wazuh dashboard credentials.
2. Restrict inbound access to trusted VPN/team subnets only.
3. Do not expose dashboard/API directly to the public internet.

## Team access recommendation
- Use VPN (mesh VPN preferred) for teammate access.
- Expose only dashboard/API over VPN.
- Keep honeypot management access admin-only.

## VPN-only access control (teammates only)

Use this section to ensure the Wazuh dashboard/API is reachable only through VPN, not from your home LAN or public internet.

### 1) Identity and teammate allowlist
- Create a fixed teammate list (name + VPN identity + role).
- Grant access only to those teammate identities in your VPN ACL/policy.
- Do not share accounts; create one Wazuh account per teammate.
- Enable MFA in the VPN provider and in Wazuh accounts when available.

Example teammate allowlist (maintain in your private notes):
- `owner`: you (full admin)
- `analyst-1`: read-only
- `analyst-2`: read-only
- `hunter-1`: read-only or limited write

### 2) Enforce VPN-only network path

Preferred model:
- Teammates connect to VPN first.
- Dashboard/API traffic is allowed only from VPN address space.
- Home LAN and WAN traffic to Wazuh ports is blocked.

If using a mesh VPN (recommended):
- Advertise only the host SIEM node.
- Use VPN ACLs so only teammate identities can reach dashboard/API.
- Disable broad subnet exposure unless required.

### 3) Host firewall policy (critical)

Apply a deny-by-default host firewall and only allow Wazuh ports from VPN source addresses.

Ports to control:
- `443/tcp` dashboard
- `55000/tcp` API

Policy goal:
- Allow: VPN subnet or explicit teammate VPN IPs.
- Deny: home LAN subnet and all other sources.

Implementation note:
- Use your host firewall tool (`nftables`, `iptables`, or `ufw`) consistently.
- If your VPN provider offers policy ACLs, keep both VPN ACL and host firewall restrictions in place.

### 4) Optional hardening: remove direct host exposure

For stricter isolation, avoid publishing Wazuh ports broadly:
- Restrict published ports to localhost and expose via VPN tunnel/proxy only.
- Or run a VPN-bound reverse proxy that is the only listener for dashboard access.

### 5) Wazuh account hardening
- Change default `admin` password immediately.
- Create individual teammate users and least-privilege roles.
- Disable unused default users.
- Rotate credentials on teammate offboarding.

### 6) Verify dashboard is VPN-only

Run these checks after firewall + VPN ACL setup:
- From teammate machine on VPN: dashboard opens at `https://<HOST_VPN_IP>`.
- From a device on your home LAN (not on VPN): connection to `443` and `55000` fails.
- From an external network (not VPN): connection fails.
- From host: `ss -tulpen | grep -E ':443|:55000'` shows listeners as expected.

Acceptance criteria:
- Only authenticated teammates on VPN can access dashboard/API.
- Home LAN and public internet cannot access dashboard/API.
- Every teammate action is attributable to an individual account.

## Troubleshooting
- Docker inactive:
```bash
systemctl status docker --no-pager -l
sudo systemctl enable --now docker
```
- Indexer memory mapping errors:
```bash
sysctl vm.max_map_count
```
Ensure value is `262144`.
- Inspect logs:
```bash
docker compose logs --tail=200
```
