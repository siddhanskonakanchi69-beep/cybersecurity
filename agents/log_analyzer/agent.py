# agents/log_analyzer/agent.py

import json
import os
import re
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from confluent_kafka import Producer
from colorama import Fore, Style, init as colorama_init
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config.mitre_mapping import get_mitre_info

colorama_init(autoreset=True)

# ─── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC     = "log-analyzer-alerts"
AGENT_ID        = os.getenv("AGENT_ID", "log-analyzer-01")
CUSTOM_LOG_PATH = os.getenv("CUSTOM_LOG_PATH", "")

AUTH_LOG    = "/var/log/auth.log"
APACHE_LOG  = "/var/log/apache2/access.log"

# Brute-force thresholds
SSH_FAIL_LIMIT   = 5    # failures
SSH_FAIL_WINDOW  = 60   # seconds
SSH_SUCCESS_WINDOW = 600  # 10 minutes

# SQL injection patterns (compiled once)
SQLI_PATTERNS = [
    re.compile(r"UNION\s+SELECT",           re.IGNORECASE),
    re.compile(r"0x[0-9a-fA-F]+",           re.IGNORECASE),
    re.compile(r"DROP\s+TABLE",             re.IGNORECASE),
    re.compile(r"--\s*$",                   re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bOR\b.+\b1=1\b",         re.IGNORECASE),
]

PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]")

SSH_FAIL_RE    = re.compile(r"Failed password for .+ from (\S+)")
SSH_SUCCESS_RE = re.compile(r"Accepted password for .+ from (\S+)")

_COLOUR = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.YELLOW,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.WHITE,
}


class LogAnalyzerAgent:
    def __init__(self):
        self.producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP})
        self.lock = threading.Lock()

        # SSH failure tracking: src_ip → [timestamps]
        self.ssh_failures: dict[str, list[float]] = defaultdict(list)
        # SSH success dedup: src_ip → last success timestamp
        self.ssh_success_alerted: set[str] = set()

        self._ensure_log_files()

    # ─── Helpers ───────────────────────────────────────────────────────────────

    def _ensure_log_files(self) -> None:
        """Create dummy log files if they don't exist (dev environment)."""
        for path in [AUTH_LOG, APACHE_LOG]:
            p = Path(path)
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.touch()
                    print(f"{Fore.YELLOW}[LogAnalyzer] Created dummy log file: {path}{Style.RESET_ALL}")
            except PermissionError:
                print(f"{Fore.YELLOW}[LogAnalyzer] Cannot create {path} (no permission) — run with sudo or set CUSTOM_LOG_PATH{Style.RESET_ALL}")

    def _publish(self, report: dict) -> None:
        self.producer.produce(KAFKA_TOPIC, value=json.dumps(report).encode())
        self.producer.poll(0)

    def _build_report(self, severity, threat_type, src_ip, dst_ip,
                      description, raw_evidence, recommended_action) -> dict:
        mitre = get_mitre_info(threat_type)
        return {
            "agent_id":             AGENT_ID,
            "timestamp":            int(time.time()),
            "severity":             severity,
            "threat_type":          threat_type,
            "source_ip":            src_ip,
            "destination_ip":       dst_ip,
            "mitre_technique_id":   mitre["technique_id"],
            "mitre_technique_name": mitre["technique_name"],
            "description":          description,
            "raw_evidence":         raw_evidence,
            "recommended_action":   recommended_action,
        }

    def _print_alert(self, report: dict) -> None:
        colour = _COLOUR.get(report["severity"], Fore.WHITE)
        ts = datetime.utcfromtimestamp(report["timestamp"]).strftime("%H:%M:%S")
        print(
            f"{colour}[{ts}] [{report['severity']}] {report['threat_type'].upper()} | "
            f"src={report['source_ip']} | {report['description']}{Style.RESET_ALL}"
        )

    def _emit(self, report: dict) -> None:
        self._print_alert(report)
        self._publish(report)

    # ─── Detection logic ───────────────────────────────────────────────────────

    def _analyze_auth_line(self, line: str) -> None:
        now = time.time()

        # Failed SSH attempt
        m = SSH_FAIL_RE.search(line)
        if m:
            src = m.group(1)
            with self.lock:
                self.ssh_failures[src].append(now)
                # Prune outside window
                cutoff = now - SSH_FAIL_WINDOW
                self.ssh_failures[src] = [t for t in self.ssh_failures[src] if t >= cutoff]
                count = len(self.ssh_failures[src])

            if count > SSH_FAIL_LIMIT:
                report = self._build_report(
                    severity="HIGH",
                    threat_type="brute_force_ssh",
                    src_ip=src,
                    dst_ip="localhost",
                    description=f"SSH brute force from {src}: {count} failures in {SSH_FAIL_WINDOW}s",
                    raw_evidence=f"auth.log: {count} 'Failed password' events from {src} in last {SSH_FAIL_WINDOW}s. Last line: {line.strip()}",
                    recommended_action=f"Block IP: iptables -A INPUT -s {src} -j DROP. Add to /etc/hosts.deny: sshd: {src}. Run: fail2ban-client status sshd",
                )
                self._emit(report)
                with self.lock:
                    self.ssh_failures[src] = []  # reset after alert

        # Successful login — check if preceded by failures
        m2 = SSH_SUCCESS_RE.search(line)
        if m2:
            src = m2.group(1)
            with self.lock:
                prior_failures = len(self.ssh_failures.get(src, []))
                already_alerted = src in self.ssh_success_alerted

            if prior_failures > 3 and not already_alerted:
                with self.lock:
                    self.ssh_success_alerted.add(src)
                report = self._build_report(
                    severity="CRITICAL",
                    threat_type="brute_force_ssh",
                    src_ip=src,
                    dst_ip="localhost",
                    description=f"Successful SSH login after {prior_failures} failures from {src} — possible credential stuffing",
                    raw_evidence=f"auth.log: {prior_failures} prior failures then 'Accepted password' from {src}. Line: {line.strip()}",
                    recommended_action=f"Force-logout session: pkill -u <user> sshd. Reset credentials. Audit /var/log/auth.log for {src}. Consider MFA enforcement.",
                )
                self._emit(report)

    def _analyze_http_line(self, line: str) -> None:
        # SQL injection check
        for pattern in SQLI_PATTERNS:
            if pattern.search(line):
                report = self._build_report(
                    severity="CRITICAL",
                    threat_type="sql_injection",
                    src_ip="unknown",
                    dst_ip="localhost",
                    description=f"SQL injection pattern detected in HTTP request",
                    raw_evidence=f"access.log line: {line.strip()[:500]}",
                    recommended_action="Review WAF rules. Block source IP. Sanitize all DB inputs. Run: grep -n 'UNION SELECT' /var/log/apache2/access.log | tail -50",
                )
                self._emit(report)
                return  # one alert per line max

        # Path traversal check
        if PATH_TRAVERSAL_RE.search(line):
            report = self._build_report(
                severity="HIGH",
                threat_type="path_traversal",
                src_ip="unknown",
                dst_ip="localhost",
                description="Path traversal attempt detected in HTTP request URI",
                raw_evidence=f"access.log line: {line.strip()[:500]}",
                recommended_action="Block request at WAF/nginx. Validate all file path inputs. Check if sensitive files were accessed: grep '200' /var/log/apache2/access.log | grep '\\.\\.'",
            )
            self._emit(report)

    def _analyze_custom_line(self, line: str) -> None:
        """Basic analysis for custom log lines — extend as needed."""
        self._analyze_http_line(line)

    # ─── File tailer ───────────────────────────────────────────────────────────

    def _tail_file(self, path: str, analyzer_fn) -> None:
        """Open a file, seek to end, and yield new lines as they appear."""
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(0, 2)  # seek to EOF
                while True:
                    line = f.readline()
                    if line:
                        analyzer_fn(line)
                    else:
                        time.sleep(0.1)
        except Exception as e:
            print(f"{Fore.RED}[LogAnalyzer] Error tailing {path}: {e}{Style.RESET_ALL}")

    # ─── Watchdog handler (for file rotation awareness) ────────────────────────

    class _RotateHandler(FileSystemEventHandler):
        def __init__(self, path: str, agent, analyzer_fn):
            self.path = path
            self.agent = agent
            self.analyzer_fn = analyzer_fn

        def on_modified(self, event):
            # handled by the tail thread; watchdog is just a safety net
            pass

    # ─── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        print(f"{Fore.GREEN}[LogAnalyzerAgent] Starting → Kafka:{KAFKA_BOOTSTRAP}/{KAFKA_TOPIC}{Style.RESET_ALL}")

        sources = [
            (AUTH_LOG,   self._analyze_auth_line),
            (APACHE_LOG, self._analyze_http_line),
        ]
        if CUSTOM_LOG_PATH:
            sources.append((CUSTOM_LOG_PATH, self._analyze_custom_line))

        threads = []
        for path, fn in sources:
            t = threading.Thread(target=self._tail_file, args=(path, fn), daemon=True)
            t.start()
            threads.append(t)
            print(f"{Fore.CYAN}[LogAnalyzer] Tailing: {path}{Style.RESET_ALL}")

        try:
            while True:
                time.sleep(1)
                self.producer.poll(0)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[LogAnalyzerAgent] Shutting down...{Style.RESET_ALL}")
            self.producer.flush()


if __name__ == "__main__":
    LogAnalyzerAgent().run()
