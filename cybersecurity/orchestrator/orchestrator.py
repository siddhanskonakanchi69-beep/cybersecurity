"""
Orchestrator Agent
The central brain — subscribes to all agent alerts, correlates events,
deduplicates, and forwards classified threats to the ML engine / response agent.
"""
import json, os, time
from collections import defaultdict
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.utils.redis_client import get_redis

ALERT_TOPICS  = ["alerts.network", "alerts.logs", "alerts.ueba", "alerts.vuln"]
OUTPUT_TOPIC  = "threats.classified"
CORRELATION_WINDOW_SEC = 120  # 2-minute correlation window

# In-memory event buffer keyed by source_ip for correlation
event_buffer: dict = defaultdict(list)


def correlate(event: dict, redis_client) -> dict:
    """
    Correlate this event against recent events from the same source.
    If multiple agents flagged the same IP → boost severity & confidence.
    """
    src_ip = event.get("source_ip", "unknown")
    now    = time.time()

    # Load existing events for this IP from Redis (TTL-based)
    redis_key = f"corr:{src_ip}"
    existing  = redis_client.lrange(redis_key, 0, -1)
    related   = [json.loads(e) for e in existing]

    # Add current event
    redis_client.rpush(redis_key, json.dumps(event))
    redis_client.expire(redis_key, CORRELATION_WINDOW_SEC)

    agent_ids = set(e["agent_id"] for e in related) | {event["agent_id"]}
    multi_agent_hit = len(agent_ids) > 1

    enriched = dict(event)
    if multi_agent_hit:
        # Multiple agents agree → escalate
        enriched["confidence"] = min(event.get("confidence", 0.8) + 0.1, 1.0)
        if enriched.get("severity") == "high":
            enriched["severity"] = "critical"
        enriched["correlation_note"] = f"Corroborated by {len(agent_ids)} agents: {agent_ids}"
        logger.warning(f"🔗 CORRELATED THREAT from {src_ip} — {len(agent_ids)} agents agree!")

    enriched["orchestrator_id"] = "orchestrator-01"
    return enriched


def run():
    logger.info("🧠 Orchestrator starting — listening to all alert topics...")
    consumer     = get_consumer(ALERT_TOPICS, group_id="orchestrator-group")
    producer     = get_producer()
    redis_client = get_redis()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        event    = json.loads(msg.value().decode("utf-8"))
        enriched = correlate(event, redis_client)

        publish(producer, OUTPUT_TOPIC, enriched)
        logger.info(f"[ORCHESTRATOR] Forwarded {enriched['severity']} threat → {OUTPUT_TOPIC}")


if __name__ == "__main__":
    run()
