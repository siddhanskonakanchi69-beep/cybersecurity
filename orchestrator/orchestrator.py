import json
import logging
import os
import time
import threading
from collections import defaultdict, deque
from uuid import uuid4

import requests

from config.config import (
    CORRELATION_WINDOW_SEC,
    ES_INDEX_THREATS,
    TOPIC_ALERT_LOGS,
    TOPIC_ALERT_NETWORK,
    TOPIC_ALERT_UEBA,
    TOPIC_ALERT_VULN,
    TOPIC_THREATS,
)
from orchestrator.kill_chain import analyze_kill_chain_progression
from orchestrator.response_dispatcher import ResponseDispatcher
from shared.schemas.event import ThreatEvent
from shared.utils.es_client import get_es_client, index_event
from shared.utils.kafka_client import get_consumer, get_producer, publish
from shared.utils.redis_client import get_redis


SEVERITY_SCORES = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 10,
}


def _normalize_severity(severity: str) -> str:
    if not severity:
        return "LOW"
    return str(severity).upper()


class OrchestratorAgent:
    """Orchestrator that consumes per-agent alerts, correlates them, and routes responses."""

    def __init__(self):
        self.logger = logging.getLogger("orchestrator")
        self.correlation_window = defaultdict(lambda: deque())
        self.lock = threading.Lock()
        self.running = True

        self.consumer = get_consumer(
            [
                TOPIC_ALERT_NETWORK,
                TOPIC_ALERT_LOGS,
                TOPIC_ALERT_UEBA,
                TOPIC_ALERT_VULN,
            ],
            group_id="orchestrator-group",
        )
        self.producer = get_producer()
        self.es = get_es_client()
        self.redis = get_redis()
        self.dispatcher = ResponseDispatcher()

        self.ml_service_url = os.getenv("ML_SERVICE_URL", "http://ml-service:8001")

    def run(self) -> None:
        self.logger.info(
            "[Orchestrator] Starting (consuming alert topics & publishing to threats.classified)"
        )

        while True:
            msg = self.consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                self.logger.error(f"Kafka error: {msg.error()}")
                continue

            try:
                alert = json.loads(msg.value().decode("utf-8"))
                classified = self.process_alert(alert)

                publish(self.producer, TOPIC_THREATS, classified)
                index_event(self.es, ES_INDEX_THREATS, classified)

            except Exception as exc:
                self.logger.exception(f"[Orchestrator] Failed to process alert: {exc}")

    def process_alert(self, alert: dict) -> dict:
        """Correlate alerts per source IP, score, and decide response."""
        now = int(time.time())
        alert_ts = int(alert.get("timestamp", now))

        source_ip = alert.get("source_ip") or alert.get("src_ip") or "unknown"
        alert["source_ip"] = source_ip
        alert["timestamp"] = alert_ts

        # Add ML enrichment (best-effort)
        try:
            self._enrich_with_ml(alert)
        except Exception:
            pass

        with self.lock:
            bucket = self.correlation_window[source_ip]
            bucket.append(alert)
            cutoff = time.time() - CORRELATION_WINDOW_SEC
            while bucket and bucket[0].get("timestamp", 0) < cutoff:
                bucket.popleft()
            events = list(bucket)

        result = self._correlate_and_score(events)

        threat = ThreatEvent(
            agent_id=alert.get("agent_id", "orchestrator"),
            event_type=alert.get("threat_type", "alert"),
            severity=result["recommended_severity"].lower(),
            confidence=float(alert.get("confidence", 0.0)),
            source_ip=source_ip,
            dest_ip=alert.get("destination_ip") or alert.get("dest_ip"),
            user=alert.get("user"),
            host=alert.get("host"),
            mitre_ttp=alert.get("mitre_technique_id") or alert.get("mitre_ttp"),
            details={
                "raw_alert": alert,
                "compound_score": result["compound_score"],
                "kill_chain": result["kill_chain"],
                "agents_involved": result["agents_involved"],
                "alert_count": result["alert_count"],
                "ml": {
                    "severity": alert.get("ml_severity"),
                    "confidence": alert.get("ml_confidence"),
                    "threat_class": alert.get("ml_threat_class"),
                },
            },
        ).dict()

        threat.update(
            {
                "compound_score": result["compound_score"],
                "kill_chain": result["kill_chain"],
                "agents_involved": result["agents_involved"],
                "alert_count": result["alert_count"],
                "recommended_severity": result["recommended_severity"],
                "incident_id": str(uuid4()),
            }
        )

        try:
            self._maybe_take_response(threat)
        except Exception:
            pass

        return threat

    def _correlate_and_score(self, events: list[dict]) -> dict:
        agents = list({e.get("agent_id") for e in events if e.get("agent_id")})
        base_score = sum(
            SEVERITY_SCORES.get(_normalize_severity(e.get("severity", "LOW")), 0)
            for e in events
        )

        if len(agents) > 1:
            base_score *= 1.5

        kill_chain = analyze_kill_chain_progression(events)
        compound_score = base_score * (1 + kill_chain["progression_score"] * 0.2)

        if compound_score > 25:
            sev = "CRITICAL"
        elif compound_score > 15:
            sev = "HIGH"
        elif compound_score > 8:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        return {
            "source_ip": events[0].get("source_ip") if events else None,
            "compound_score": compound_score,
            "alert_count": len(events),
            "agents_involved": agents,
            "kill_chain": kill_chain,
            "recommended_severity": sev,
        }

    def _enrich_with_ml(self, alert: dict) -> None:
        """Optionally call an external ML service to enrich the alert."""
        if not self.ml_service_url:
            return

        features = {
            "severity": {
                "LOW": 0,
                "MEDIUM": 1,
                "HIGH": 2,
                "CRITICAL": 3,
            }.get(_normalize_severity(alert.get("severity")), 0),
            "type": alert.get("threat_type") or "unknown",
        }

        try:
            resp = requests.post(
                f"{self.ml_service_url.rstrip('/')}/predict",
                json={"features": features},
                timeout=2,
            )
            resp.raise_for_status()
            data = resp.json()
            alert["ml_severity"] = data.get("overall_severity")
            alert["ml_confidence"] = data.get("binary_confidence")
            alert["ml_threat_class"] = data.get("threat_class")
        except Exception:
            self.logger.debug("ML service enrichment failed (service may not be running)")

    def _maybe_take_response(self, threat: dict) -> None:
        sev = threat.get("recommended_severity", "LOW").upper()
        src_ip = threat.get("source_ip")

        if sev in ("CRITICAL", "HIGH") and src_ip:
            self.dispatcher.block_ip(src_ip)
            self.dispatcher.send_slack_alert(
                f"Automated block applied to {src_ip} (severity={sev})",
                sev,
            )
        elif sev == "MEDIUM" and src_ip:
            self.dispatcher.send_slack_alert(
                f"Medium severity alert for {src_ip}. Review recommended.",
                sev,
            )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    OrchestratorAgent().run()
