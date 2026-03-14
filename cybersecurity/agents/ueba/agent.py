"""
UEBA Agent — User and Entity Behavior Analytics
Builds per-user behavioral baselines and detects deviations.
Uses autoencoder + Z-score statistical models.
"""
import json, os
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.utils.es_client import get_es_client, index_event
from shared.utils.redis_client import get_redis
from shared.schemas.event import ThreatEvent

INPUT_TOPIC  = "raw.user.events"
OUTPUT_TOPIC = "alerts.ueba"
ES_INDEX     = os.getenv("ES_INDEX_ALERTS", "cyberdefense-alerts")

DEVIATION_THRESHOLD = 3.0  # Z-score threshold


def get_baseline(redis_client, user: str) -> dict:
    """Retrieve stored user baseline from Redis."""
    raw = redis_client.hgetall(f"baseline:{user}")
    return {k: float(v) for k, v in raw.items()} if raw else {}


def update_baseline(redis_client, user: str, event: dict) -> None:
    """Incrementally update user baseline (simplified — use proper streaming stats in prod)."""
    redis_client.hset(f"baseline:{user}", mapping={
        "avg_login_hour": event.get("hour", 9),
        "avg_files_accessed": event.get("files_accessed", 10),
    })


def analyze(event: dict, redis_client) -> ThreatEvent | None:
    user  = event.get("user")
    hour  = event.get("hour", 9)

    baseline = get_baseline(redis_client, user)
    if not baseline:
        update_baseline(redis_client, user, event)
        return None

    avg_hour = baseline.get("avg_login_hour", 9)
    # Simple off-hours detection (ML autoencoder replaces this in Phase 4)
    if hour < 5 or hour > 22:
        deviation = abs(hour - avg_hour)
        if deviation > DEVIATION_THRESHOLD:
            return ThreatEvent(
                agent_id="ueba-01",
                event_type="anomaly",
                severity="medium",
                confidence=round(min(0.5 + deviation * 0.05, 0.95), 2),
                user=user,
                mitre_ttp="T1078",
                details={"pattern": "off_hours_login", "hour": hour, "avg_hour": avg_hour},
            )

    update_baseline(redis_client, user, event)
    return None


def run():
    logger.info("👤 UEBA Agent starting...")
    consumer     = get_consumer([INPUT_TOPIC], group_id="ueba-group")
    producer     = get_producer()
    es           = get_es_client()
    redis_client = get_redis()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        event = json.loads(msg.value().decode("utf-8"))
        alert = analyze(event, redis_client)
        if alert:
            event_dict = alert.dict()
            publish(producer, OUTPUT_TOPIC, event_dict)
            index_event(es, ES_INDEX, event_dict)
            logger.warning(f"[UEBA] {alert.details}")


if __name__ == "__main__":
    run()
