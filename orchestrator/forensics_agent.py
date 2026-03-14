"""
forensics_agent.py
Forensics Evidence Collection Agent.

Consumes classified threats from Kafka and stores forensic evidence
in MinIO (S3-compatible object store) for post-incident analysis.

Evidence stored per incident:
  - Full threat JSON
  - Raw log snapshot
  - Packet capture reference
  - Incident timeline

MinIO bucket : cyberdefense-forensics
Object path  : incidents/{date}/{incident_id}/evidence.json

Run:
  python -m orchestrator.forensics_agent
Health check:
  curl http://localhost:9000/minio/health/live
"""

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime
from typing import Any

from loguru import logger
from minio import Minio
from minio.error import S3Error
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_consumer, get_producer, publish

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_TOPIC: str   = "threats.classified"
OUTPUT_TOPIC: str  = "actions.taken"

MINIO_ENDPOINT: str    = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY: str  = os.getenv("MINIO_ROOT_USER", "admin")
MINIO_SECRET_KEY: str  = os.getenv("MINIO_ROOT_PASSWORD", "admin1234")
MINIO_BUCKET: str      = os.getenv("MINIO_BUCKET", "cyberdefense-forensics")
MINIO_SECURE: bool     = os.getenv("MINIO_SECURE", "false").lower() == "true"


# ── MinIO Client ──────────────────────────────────────────────────────────────

def get_minio_client() -> Minio:
    """
    Return a connected MinIO client.

    Returns:
        Minio client instance
    """
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def ensure_bucket(client: Minio, bucket: str) -> None:
    """
    Create the forensics bucket if it does not exist.

    Args:
        client: connected MinIO client
        bucket: bucket name to create
    """
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            logger.info(f"[FORENSICS] Created MinIO bucket: {bucket}")
        else:
            logger.debug(f"[FORENSICS] Bucket already exists: {bucket}")
    except S3Error as exc:
        logger.error(f"[FORENSICS] Failed to create bucket: {exc}")
        raise


# ── Evidence Building ─────────────────────────────────────────────────────────

def build_evidence_package(threat: dict[str, Any]) -> dict[str, Any]:
    """
    Build a structured forensic evidence package from a classified threat.

    Includes the full threat context, timeline, hash fingerprint,
    and metadata needed for post-incident review.

    Args:
        threat: classified threat dict from Kafka

    Returns:
        Evidence package dict ready for MinIO storage
    """
    incident_id: str = threat.get("incident_id", threat.get("event_id", "unknown"))
    collected_at: str = datetime.utcnow().isoformat()

    # Deterministic fingerprint for deduplication
    fingerprint: str = hashlib.sha256(
        json.dumps(threat, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    return {
        "incident_id": incident_id,
        "collected_at": collected_at,
        "fingerprint": fingerprint,
        "severity": threat.get("severity", "unknown"),
        "confidence": threat.get("confidence", 0.0),
        "source_ip": threat.get("source_ip"),
        "dest_ip": threat.get("dest_ip"),
        "user": threat.get("user"),
        "host": threat.get("host"),
        "mitre_ttp": threat.get("mitre_ttp"),
        "kill_chain": threat.get("kill_chain"),
        "compound_score": threat.get("compound_score"),
        "agents_involved": threat.get("agents_involved", []),
        "actions_taken": threat.get("actions_taken", []),
        "raw_details": threat.get("details", {}),
        "full_threat_record": threat,
        "evidence_version": "1.0",
        "retention_days": 90,
    }


def store_evidence(
    client: Minio,
    bucket: str,
    evidence: dict[str, Any],
) -> str:
    """
    Store a forensic evidence package in MinIO as a JSON object.

    Object path format:
        incidents/YYYY-MM-DD/{incident_id}/{fingerprint}.json

    Args:
        client: connected MinIO client
        bucket: target bucket name
        evidence: evidence package dict

    Returns:
        Full MinIO object path of stored evidence
    """
    import io

    date_str: str   = datetime.utcnow().strftime("%Y-%m-%d")
    incident_id: str = evidence["incident_id"]
    fingerprint: str = evidence["fingerprint"]

    object_path: str = f"incidents/{date_str}/{incident_id}/{fingerprint}.json"
    payload: bytes   = json.dumps(evidence, indent=2, default=str).encode("utf-8")
    payload_size: int = len(payload)

    try:
        client.put_object(
            bucket_name=bucket,
            object_name=object_path,
            data=io.BytesIO(payload),
            length=payload_size,
            content_type="application/json",
        )
        logger.info(
            f"[FORENSICS] Stored evidence: {object_path} "
            f"({payload_size} bytes) | severity={evidence['severity']}"
        )
        return object_path

    except S3Error as exc:
        logger.error(f"[FORENSICS] MinIO store failed: {exc}")
        raise


# ── Main Loop ─────────────────────────────────────────────────────────────────

def run() -> None:
    """
    Main forensics agent loop.

    Consumes classified threats from Kafka, builds evidence packages,
    stores them in MinIO, and publishes a confirmation to actions.taken.
    """
    logger.info("🔬 Forensics Agent starting — evidence store: MinIO")

    minio_client = get_minio_client()
    ensure_bucket(minio_client, MINIO_BUCKET)

    consumer = get_consumer([INPUT_TOPIC], group_id="forensics-group")
    producer = get_producer()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        try:
            threat   = json.loads(msg.value().decode("utf-8"))
            evidence = build_evidence_package(threat)
            path     = store_evidence(minio_client, MINIO_BUCKET, evidence)

            # Publish audit record to actions.taken
            audit = {
                "agent_id": "forensics-agent-01",
                "action": "evidence_stored",
                "incident_id": evidence["incident_id"],
                "minio_path": path,
                "bucket": MINIO_BUCKET,
                "severity": evidence["severity"],
                "timestamp": evidence["collected_at"],
            }
            publish(producer, OUTPUT_TOPIC, audit)

        except Exception as exc:
            logger.exception(f"[FORENSICS] Failed to process threat: {exc}")


if __name__ == "__main__":
    run()