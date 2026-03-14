"""
Vulnerability Scanner Agent
Scans hosts for open ports, service versions, CVE matches.
Publishes risk-scored findings to alerts.vuln topic.
"""
import json, os, subprocess
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.utils.es_client import get_es_client, index_event
from shared.schemas.event import ThreatEvent

INPUT_TOPIC  = "raw.vuln.events"
OUTPUT_TOPIC = "alerts.vuln"
ES_INDEX     = os.getenv("ES_INDEX_ALERTS", "cyberdefense-alerts")

# CVSS score threshold for alerting
CRITICAL_CVSS = 9.0
HIGH_CVSS     = 7.0


def severity_from_cvss(score: float) -> str:
    if score >= CRITICAL_CVSS:
        return "critical"
    if score >= HIGH_CVSS:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def analyze(vuln: dict) -> ThreatEvent | None:
    cvss  = vuln.get("cvss_score", 0.0)
    cve   = vuln.get("cve_id", "UNKNOWN")
    host  = vuln.get("host")

    if cvss >= HIGH_CVSS:
        return ThreatEvent(
            agent_id="vuln-scanner-01",
            event_type="alert",
            severity=severity_from_cvss(cvss),
            confidence=0.99,
            host=host,
            details={
                "cve_id": cve,
                "cvss_score": cvss,
                "service": vuln.get("service"),
                "version": vuln.get("version"),
                "patch_available": vuln.get("patch_available", True),
            },
        )
    return None


def run():
    logger.info("🔍 Vulnerability Scanner Agent starting...")
    consumer = get_consumer([INPUT_TOPIC], group_id="vuln-scanner-group")
    producer = get_producer()
    es       = get_es_client()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        vuln = json.loads(msg.value().decode("utf-8"))
        alert = analyze(vuln)
        if alert:
            event_dict = alert.dict()
            publish(producer, OUTPUT_TOPIC, event_dict)
            index_event(es, ES_INDEX, event_dict)
            logger.warning(f"[VULN] {alert.details}")


if __name__ == "__main__":
    run()
