# Wazuh Install Notes

## Target Deployment
- Primary: physical host machine (this project setup)
- Alternative fallback: dedicated Ubuntu VM

## Architecture Context
- Host machine runs SIEM (Wazuh manager/indexer/dashboard).
- Honeypot Ubuntu VM forwards telemetry to host SIEM.
- Attacker VM generates controlled test traffic.

## Checklist
- [ ] Manager installed
- [ ] Indexer installed
- [ ] Dashboard installed
- [ ] Credentials stored securely
- [ ] Ubuntu honeypot agent connected

## Health Validation
- Dashboard reachable
- Agent status active
- Alert/event flow visible

## Quick readiness checks (host)
- `curl -k https://127.0.0.1:55000`
- `ss -tulpen | grep -E ':443|:55000'`
- Verify honeypot VM agent heartbeat in dashboard

## Version Notes
- Fill exact Wazuh/OpenSearch versions after install.
