# agents/network_monitor/agent.py

import json
import os
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime

from scapy.all import AsyncSniffer, IP, TCP, UDP, DNS, DNSQR
from confluent_kafka import Producer
from colorama import Fore, Style, init as colorama_init

# Allow running as `python -m agents.network_monitor.agent` from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config.mitre_mapping import get_mitre_info

colorama_init(autoreset=True)

# ─── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC      = "network-monitor-alerts"
IFACE            = os.getenv("SNIFF_IFACE", "eth0")
AGENT_ID         = os.getenv("AGENT_ID", "network-monitor-01")

# Detection thresholds
PORT_SCAN_WINDOW   = 30    # seconds
PORT_SCAN_LIMIT    = 15    # unique ports
SYN_FLOOD_PPS      = 200   # SYN packets per second
EXFIL_BYTES        = 50 * 1024 * 1024  # 50 MB

# ─── Severity colour map ────────────────────────────────────────────────────────
_COLOUR = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.YELLOW,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.WHITE,
}


class NetworkMonitorAgent:
    def __init__(self):
        self.producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP})
        self.lock = threading.Lock()

        # Port-scan state: src_ip → list of (timestamp, dst_port)
        self.port_events: dict[str, list[tuple[float, int]]] = defaultdict(list)

        # SYN-flood state: src_ip → list of timestamps
        self.syn_events: dict[str, list[float]] = defaultdict(list)

        # Session byte counters: (src_ip, dst_ip, sport, dport) → bytes
        self.session_bytes: dict[tuple, int] = defaultdict(int)

        # Already-alerted sessions / IPs (prevent alert storms)
        self.alerted_exfil: set[tuple]  = set()
        self.alerted_scan:  set[str]    = set()
        self.alerted_syn:   set[str]    = set()

    # ─── Kafka ─────────────────────────────────────────────────────────────────

    def _publish(self, report: dict) -> None:
        payload = json.dumps(report).encode()
        self.producer.produce(KAFKA_TOPIC, value=payload)
        self.producer.poll(0)

    # ─── Alert builder ─────────────────────────────────────────────────────────

    def _build_report(
        self,
        severity:   str,
        threat_type: str,
        src_ip:     str,
        dst_ip:     str,
        description: str,
        raw_evidence: str,
        recommended_action: str,
    ) -> dict:
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

    # ─── Coloured stdout ───────────────────────────────────────────────────────

    def _print_alert(self, report: dict) -> None:
        colour = _COLOUR.get(report["severity"], Fore.WHITE)
        ts = datetime.utcfromtimestamp(report["timestamp"]).strftime("%H:%M:%S")
        print(
            f"{colour}[{ts}] [{report['severity']}] {report['threat_type'].upper()} | "
            f"src={report['source_ip']} dst={report['destination_ip']} | "
            f"{report['description']}{Style.RESET_ALL}"
        )

    # ─── Emit helper ───────────────────────────────────────────────────────────

    def _emit(self, report: dict) -> None:
        self._print_alert(report)
        self._publish(report)

    # ─── Detection handlers ────────────────────────────────────────────────────

    def _handle_port_scan(self, src: str, dst: str, dport: int, now: float) -> None:
        with self.lock:
            events = self.port_events[src]
            events.append((now, dport))
            # Prune old events outside the window
            cutoff = now - PORT_SCAN_WINDOW
            self.port_events[src] = [(t, p) for t, p in events if t >= cutoff]

            unique_ports = {p for _, p in self.port_events[src]}
            elapsed = now - self.port_events[src][0][0] if self.port_events[src] else 0

            if len(unique_ports) > PORT_SCAN_LIMIT and src not in self.alerted_scan:
                self.alerted_scan.add(src)
                report = self._build_report(
                    severity="CRITICAL",
                    threat_type="port_scan",
                    src_ip=src,
                    dst_ip=dst,
                    description=f"Port scan detected: {src} contacted {len(unique_ports)} unique ports in {elapsed:.0f}s",
                    raw_evidence=f"Source IP {src} contacted {len(unique_ports)} unique ports in {elapsed:.0f}s. Ports sample: {sorted(unique_ports)[:20]}",
                    recommended_action=f"Block source IP {src} immediately. Run: nmap -sV {src} to fingerprint attacker. Review firewall egress rules.",
                )
                self._emit(report)
                # Reset after alert so future scans can re-trigger
                self.port_events[src] = []

    def _handle_syn_flood(self, src: str, dst: str, now: float) -> None:
        with self.lock:
            events = self.syn_events[src]
            events.append(now)
            # Keep only last 1-second window
            cutoff = now - 1.0
            self.syn_events[src] = [t for t in events if t >= cutoff]

            pps = len(self.syn_events[src])
            if pps > SYN_FLOOD_PPS and src not in self.alerted_syn:
                self.alerted_syn.add(src)
                report = self._build_report(
                    severity="HIGH",
                    threat_type="syn_flood",
                    src_ip=src,
                    dst_ip=dst,
                    description=f"SYN flood detected: {src} → {pps} SYN/s toward {dst}",
                    raw_evidence=f"Source IP {src} sent {pps} SYN packets in the last second to {dst}",
                    recommended_action=f"Apply rate-limit rule: iptables -A INPUT -s {src} -p tcp --syn -m limit --limit 10/s -j ACCEPT && iptables -A INPUT -s {src} -p tcp --syn -j DROP",
                )
                self._emit(report)
                self.syn_events[src] = []

    def _handle_dns_tunneling(self, src: str, dst: str, pkt) -> None:
        try:
            dns_layer = pkt[DNS]
            raw_len = len(bytes(dns_layer))
            qname = pkt[DNSQR].qname.decode(errors="replace") if pkt.haslayer(DNSQR) else ""
            labels = qname.rstrip(".").split(".")
            max_label_len = max((len(l) for l in labels), default=0)

            if raw_len > 100 or max_label_len > 40:
                report = self._build_report(
                    severity="MEDIUM",
                    threat_type="dns_tunneling",
                    src_ip=src,
                    dst_ip=dst,
                    description=f"Possible DNS tunneling from {src}: payload={raw_len}B, max_label={max_label_len}",
                    raw_evidence=f"DNS query from {src} to {dst}: qname='{qname}', payload={raw_len} bytes, longest label={max_label_len} chars",
                    recommended_action=f"Inspect DNS traffic from {src} with Wireshark. Block if confirmed: iptables -A OUTPUT -s {src} -p udp --dport 53 -j DROP",
                )
                self._emit(report)
        except Exception:
            pass

    def _handle_exfil(self, src: str, dst: str, sport: int, dport: int, payload_len: int) -> None:
        key = (src, dst, sport, dport)
        with self.lock:
            self.session_bytes[key] += payload_len
            total = self.session_bytes[key]

            if total > EXFIL_BYTES and key not in self.alerted_exfil:
                self.alerted_exfil.add(key)
                mb = total / (1024 * 1024)
                report = self._build_report(
                    severity="HIGH",
                    threat_type="data_exfiltration",
                    src_ip=src,
                    dst_ip=dst,
                    description=f"Large outbound transfer: {src}:{sport} → {dst}:{dport} ({mb:.1f} MB)",
                    raw_evidence=f"TCP session {src}:{sport} → {dst}:{dport} transferred {mb:.2f} MB of data (threshold: 50 MB)",
                    recommended_action=f"Immediately terminate connection. Capture full session: tcpdump -w /tmp/exfil_{src}.pcap host {src}. Investigate process on {src} using netstat -tulnp.",
                )
                self._emit(report)

    # ─── Packet callback ───────────────────────────────────────────────────────

    def _process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        now = time.time()

        # TCP analysis
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dport = tcp.dport

            # Port scan: any TCP packet tracks destination ports
            self._handle_port_scan(src, dst, dport, now)

            # SYN flood: flag == 0x02 means pure SYN
            if tcp.flags == 0x02:
                self._handle_syn_flood(src, dst, now)

            # Large outbound transfer
            payload = bytes(tcp.payload)
            if payload:
                self._handle_exfil(src, dst, tcp.sport, tcp.dport, len(payload))

        # DNS tunneling
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            self._handle_dns_tunneling(src, dst, pkt)

    # ─── Lifecycle ─────────────────────────────────────────────────────────────

    def _reset_alerted_loop(self) -> None:
        """Periodically clear alert dedup sets so repeated attacks re-trigger."""
        while True:
            time.sleep(60)
            with self.lock:
                self.alerted_scan.clear()
                self.alerted_syn.clear()
                self.alerted_exfil.clear()

    def run(self) -> None:
        print(f"{Fore.GREEN}[NetworkMonitorAgent] Starting on interface '{IFACE}' -> Kafka:{KAFKA_BOOTSTRAP}/{KAFKA_TOPIC}{Style.RESET_ALL}")

        reset_thread = threading.Thread(target=self._reset_alerted_loop, daemon=True)
        reset_thread.start()

        sniffer = AsyncSniffer(iface=IFACE, prn=self._process_packet, store=False)
        sniffer.start()

        try:
            while True:
                time.sleep(1)
                self.producer.poll(0)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[NetworkMonitorAgent] Shutting down...{Style.RESET_ALL}")
            sniffer.stop()
            self.producer.flush()


if __name__ == "__main__":
    NetworkMonitorAgent().run()
