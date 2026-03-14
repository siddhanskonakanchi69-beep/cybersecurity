"""
Network Traffic Monitor Agent
Consumes raw network events from Kafka, detects anomalies,
and publishes alerts to alerts.network topic.
"""
import json
import os
import time
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.utils.es_client import get_es_client, index_event
from shared.schemas.event import ThreatEvent

INPUT_TOPIC  = "raw.network.events"
OUTPUT_TOPIC = "alerts.network"
ES_INDEX     = os.getenv("ES_INDEX_ALERTS", "cyberdefense-alerts")

THRESHOLDS = {
    "syn_flood_pps": 10000,
    "port_scan_ports": 50,
    "conn_rate_per_min": 500,
}


def analyze(raw: dict) -> ThreatEvent | None:
    """Simple rule + threshold based detection. ML layer added in Phase 4."""
    pps      = raw.get("packets_per_second", 0)
    ports    = raw.get("distinct_ports", 0)
    src_ip   = raw.get("src_ip")
    dst_ip   = raw.get("dst_ip")

    if pps > THRESHOLDS["syn_flood_pps"]:
        return ThreatEvent(
            agent_id="network-monitor-01",
            event_type="anomaly",
            severity="critical",
            confidence=0.95,
            source_ip=src_ip,
            dest_ip=dst_ip,
            mitre_ttp="T1498",
            details={"pattern": "SYN_flood", "pps": pps},
        )

    if ports > THRESHOLDS["port_scan_ports"]:
        return ThreatEvent(
            agent_id="network-monitor-01",
            event_type="anomaly",
            severity="high",
            confidence=0.88,
            source_ip=src_ip,
            dest_ip=dst_ip,
            mitre_ttp="T1046",
            details={"pattern": "port_scan", "distinct_ports": ports},
        )
    return None


def run():
    logger.info("🛡️  Network Monitor Agent starting...")
    consumer = get_consumer([INPUT_TOPIC], group_id="network-monitor-group")
    producer = get_producer()
    es       = get_es_client()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        raw = json.loads(msg.value().decode("utf-8"))
        alert = analyze(raw)
        if alert:
            event_dict = alert.dict()
            publish(producer, OUTPUT_TOPIC, event_dict)
            index_event(es, ES_INDEX, event_dict)
            logger.warning(f"[{alert.severity.upper()}] {alert.details}")


if __name__ == "__main__":
    run()
