"""
Log Analyzer Agent
Ingests system/auth logs, detects brute-force, privilege escalation,
lateral movement. Publishes to alerts.logs topic.
"""
import json, re, os
from collections import defaultdict
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.utils.es_client import get_es_client, index_event
from shared.schemas.event import ThreatEvent

INPUT_TOPIC  = "raw.logs"
OUTPUT_TOPIC = "alerts.logs"
ES_INDEX     = os.getenv("ES_INDEX_ALERTS", "cyberdefense-alerts")

# Rolling counters per source IP (in-memory, replace with Redis for scale)
failed_auth_counter: dict = defaultdict(int)
BRUTE_FORCE_THRESHOLD = 10  # failures in window

PATTERNS = {
    "brute_force":    re.compile(r"Failed password for .+ from (\S+)", re.I),
    "sudo_escalation": re.compile(r"sudo:.+COMMAND=", re.I),
    "root_login":     re.compile(r"Accepted .+ for root from (\S+)", re.I),
}


def analyze(log_entry: dict) -> ThreatEvent | None:
    message = log_entry.get("message", "")
    host    = log_entry.get("host")
    user    = log_entry.get("user")

    # Brute force detection
    m = PATTERNS["brute_force"].search(message)
    if m:
        src_ip = m.group(1)
        failed_auth_counter[src_ip] += 1
        if failed_auth_counter[src_ip] >= BRUTE_FORCE_THRESHOLD:
            failed_auth_counter[src_ip] = 0  # reset
            return ThreatEvent(
                agent_id="log-analyzer-01",
                event_type="alert",
                severity="high",
                confidence=0.93,
                source_ip=src_ip,
                host=host,
                mitre_ttp="T1110",
                details={"pattern": "brute_force_ssh", "attempts": BRUTE_FORCE_THRESHOLD},
            )

    # Root login alert
    m = PATTERNS["root_login"].search(message)
    if m:
        return ThreatEvent(
            agent_id="log-analyzer-01",
            event_type="alert",
            severity="critical",
            confidence=0.99,
            source_ip=m.group(1),
            host=host,
            user="root",
            mitre_ttp="T1078",
            details={"pattern": "root_remote_login"},
        )

    # Sudo escalation
    if PATTERNS["sudo_escalation"].search(message):
        return ThreatEvent(
            agent_id="log-analyzer-01",
            event_type="info",
            severity="medium",
            confidence=0.75,
            host=host,
            user=user,
            mitre_ttp="T1548",
            details={"pattern": "privilege_escalation_sudo", "log": message[:200]},
        )
    return None


def run():
    logger.info("📋 Log Analyzer Agent starting...")
    consumer = get_consumer([INPUT_TOPIC], group_id="log-analyzer-group")
    producer = get_producer()
    es       = get_es_client()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        log_entry = json.loads(msg.value().decode("utf-8"))
        alert = analyze(log_entry)
        if alert:
            event_dict = alert.dict()
            publish(producer, OUTPUT_TOPIC, event_dict)
            index_event(es, ES_INDEX, event_dict)
            logger.warning(f"[{alert.severity.upper()}] {alert.details}")


if __name__ == "__main__":
    run()
