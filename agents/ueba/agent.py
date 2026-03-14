"""
agents/ueba/agent.py
User and Entity Behavior Analytics (UEBA) Agent.

Uses scikit-learn IsolationForest for unsupervised anomaly detection.
Builds a per-user behavioral baseline from historical events stored in Redis,
then scores each new event — publishing high-deviation events as alerts.

Kafka:
  Consumes : raw.user.events
  Publishes : alerts.ueba

Run:
  python -m agents.ueba.agent
"""

from __future__ import annotations

import json
import os
import pickle
from collections import defaultdict
from datetime import datetime
from typing import Any

import numpy as np
from loguru import logger
from sklearn.ensemble import IsolationForest
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.utils.es_client import get_es_client, index_event
from shared.utils.redis_client import get_redis
from shared.schemas.event import ThreatEvent

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_TOPIC: str  = "raw.user.events"
OUTPUT_TOPIC: str = "alerts.ueba"
ES_INDEX: str     = os.getenv("ES_INDEX_ALERTS", "cyberdefense-alerts")

# Minimum events before IsolationForest fires (need enough data to learn)
MIN_SAMPLES: int        = 20
CONTAMINATION: float    = 0.05   # expected 5% anomaly rate
ANOMALY_LABEL: int      = -1     # IsolationForest returns -1 for anomalies
RETRAIN_EVERY: int      = 50     # retrain model every N new events per user

# In-memory event history per user (flushed to Redis periodically)
_event_buffer: dict[str, list[list[float]]] = defaultdict(list)
_models: dict[str, IsolationForest] = {}
_event_counts: dict[str, int] = defaultdict(int)


# ── Feature Engineering ───────────────────────────────────────────────────────

def extract_features(event: dict[str, Any]) -> list[float]:
    """
    Convert a raw user event dict into a numeric feature vector.

    Features:
        [0] hour_of_day       — 0–23, captures time-of-day patterns
        [1] day_of_week       — 0–6, captures weekday vs weekend
        [2] files_accessed    — volume of file activity
        [3] login_failures    — number of failed auth attempts
        [4] bytes_transferred — data movement volume
        [5] distinct_hosts    — lateral movement indicator
        [6] is_privileged     — 1 if admin/root action, else 0

    Returns:
        list of 7 floats
    """
    ts = event.get("timestamp", datetime.utcnow().isoformat())
    try:
        dt = datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        dt = datetime.utcnow()

    return [
        float(dt.hour),
        float(dt.weekday()),
        float(event.get("files_accessed", 0)),
        float(event.get("login_failures", 0)),
        float(event.get("bytes_transferred", 0)),
        float(event.get("distinct_hosts", 1)),
        float(1 if event.get("is_privileged", False) else 0),
    ]


# ── Model Management ──────────────────────────────────────────────────────────

def _get_or_train_model(user: str) -> IsolationForest | None:
    """
    Return the trained IsolationForest for a user.
    Trains a new model if enough data is available or retrains on schedule.

    Args:
        user: username string

    Returns:
        Fitted IsolationForest, or None if insufficient data
    """
    history = _event_buffer[user]

    if len(history) < MIN_SAMPLES:
        logger.debug(f"[UEBA] {user}: only {len(history)} samples, need {MIN_SAMPLES} to train")
        return None

    should_retrain = (
        user not in _models
        or _event_counts[user] % RETRAIN_EVERY == 0
    )

    if should_retrain:
        logger.info(f"[UEBA] Training IsolationForest for {user} on {len(history)} samples")
        model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(np.array(history))
        _models[user] = model

    return _models[user]


def _load_history_from_redis(redis_client, user: str) -> None:
    """
    Load stored feature history for a user from Redis into memory buffer.

    Args:
        redis_client: connected Redis instance
        user: username string
    """
    raw = redis_client.get(f"ueba:history:{user}")
    if raw:
        try:
            _event_buffer[user] = json.loads(raw)
        except json.JSONDecodeError:
            _event_buffer[user] = []


def _save_history_to_redis(redis_client, user: str) -> None:
    """
    Persist current in-memory feature history for a user to Redis.
    TTL of 7 days keeps storage bounded.

    Args:
        redis_client: connected Redis instance
        user: username string
    """
    redis_client.setex(
        f"ueba:history:{user}",
        60 * 60 * 24 * 7,   # 7 day TTL
        json.dumps(_event_buffer[user][-500:]),  # keep last 500 samples
    )


# ── Detection ─────────────────────────────────────────────────────────────────

def analyze(event: dict[str, Any], redis_client) -> ThreatEvent | None:
    """
    Score a user event using IsolationForest anomaly detection.

    Steps:
        1. Extract feature vector from raw event
        2. Load user history from Redis if not in memory
        3. Append features to user's history buffer
        4. Train/retrain IsolationForest if enough data
        5. Score current event — if anomaly, return ThreatEvent

    Args:
        event: raw user event dict from Kafka
        redis_client: connected Redis instance

    Returns:
        ThreatEvent if anomalous, None if normal
    """
    user: str = event.get("user", "unknown")
    features: list[float] = extract_features(event)

    # Load history from Redis on first encounter
    if user not in _event_buffer:
        _load_history_from_redis(redis_client, user)

    # Add current event to history
    _event_buffer[user].append(features)
    _event_counts[user] += 1

    # Persist every 10 events to avoid Redis round-trips
    if _event_counts[user] % 10 == 0:
        _save_history_to_redis(redis_client, user)

    model = _get_or_train_model(user)
    if model is None:
        return None

    # Score: -1 = anomaly, +1 = normal
    X = np.array([features])
    prediction: int = model.predict(X)[0]
    score: float = float(model.decision_function(X)[0])  # more negative = more anomalous

    if prediction == ANOMALY_LABEL:
        # Normalise score to 0–1 confidence range
        confidence: float = round(min(1.0, max(0.5, 0.5 + abs(score))), 2)

        logger.warning(
            f"[UEBA] Anomaly detected for {user} | score={score:.3f} | "
            f"features={features}"
        )

        return ThreatEvent(
            agent_id="ueba-agent-01",
            event_type="anomaly",
            severity=_score_to_severity(score),
            confidence=confidence,
            user=user,
            host=event.get("host"),
            source_ip=event.get("source_ip"),
            mitre_ttp="T1078",
            details={
                "pattern": "behavior_anomaly_isolation_forest",
                "anomaly_score": round(score, 4),
                "hour": features[0],
                "files_accessed": features[2],
                "login_failures": features[3],
                "bytes_transferred": features[4],
                "distinct_hosts": features[5],
                "is_privileged": bool(features[6]),
                "model": "IsolationForest",
                "samples_trained_on": len(_event_buffer[user]),
            },
        )

    return None


def _score_to_severity(score: float) -> str:
    """
    Map IsolationForest decision score to threat severity.

    IsolationForest returns negative scores for anomalies — more negative = worse.

    Args:
        score: raw decision function output (negative float)

    Returns:
        severity string: critical | high | medium
    """
    abs_score = abs(score)
    if abs_score > 0.3:
        return "critical"
    if abs_score > 0.15:
        return "high"
    return "medium"


# ── Main Loop ─────────────────────────────────────────────────────────────────

def run() -> None:
    """
    Main agent loop. Consumes user events from Kafka,
    runs IsolationForest scoring, publishes anomalies.
    """
    logger.info("👤 UEBA Agent starting (IsolationForest mode)...")

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

        try:
            event = json.loads(msg.value().decode("utf-8"))
            alert = analyze(event, redis_client)

            if alert:
                event_dict = alert.dict()
                publish(producer, OUTPUT_TOPIC, event_dict)
                index_event(es, ES_INDEX, event_dict)

        except Exception as exc:
            logger.exception(f"[UEBA] Error processing event: {exc}")


if __name__ == "__main__":
    run()