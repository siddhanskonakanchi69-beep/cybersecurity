"""
Shared Kafka producer/consumer wrapper used by all agents.
"""
import json
import os
from confluent_kafka import Producer, Consumer, KafkaError
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
GROUP_ID  = os.getenv("KAFKA_GROUP_ID", "cyberdefense-agents")


def get_producer() -> Producer:
    return Producer({"bootstrap.servers": BOOTSTRAP})


def get_consumer(topics: list[str], group_id: str = GROUP_ID) -> Consumer:
    c = Consumer({
        "bootstrap.servers": BOOTSTRAP,
        "group.id": group_id,
        "auto.offset.reset": "latest",
    })
    c.subscribe(topics)
    return c


def publish(producer: Producer, topic: str, event: dict) -> None:
    producer.produce(topic, value=json.dumps(event).encode("utf-8"))
    producer.flush()
    logger.debug(f"Published to {topic}: {event.get('event_type')} | {event.get('severity')}")
