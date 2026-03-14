"""
config/config.py
Central configuration for the Multi-Agent Cybersecurity Defense System.
All agents import from here — do NOT hardcode values elsewhere.

Verify with:
  python -c "from config.config import *; print('config OK')"
"""

import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# ─── Kafka ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
KAFKA_GROUP_ID: str          = os.getenv("KAFKA_GROUP_ID", "cyberdefense-agents")

# Kafka Topics
TOPIC_RAW_NETWORK   = "raw.network.events"
TOPIC_RAW_LOGS      = "raw.logs"
TOPIC_RAW_USER      = "raw.user.events"
TOPIC_RAW_VULN      = "raw.vuln.events"
TOPIC_ALERT_NETWORK = "alerts.network"
TOPIC_ALERT_LOGS    = "alerts.logs"
TOPIC_ALERT_UEBA    = "alerts.ueba"
TOPIC_ALERT_VULN    = "alerts.vuln"
TOPIC_THREATS       = "threats.classified"
TOPIC_ACTIONS       = "actions.taken"

ALL_TOPICS = [
    TOPIC_RAW_NETWORK, TOPIC_RAW_LOGS, TOPIC_RAW_USER, TOPIC_RAW_VULN,
    TOPIC_ALERT_NETWORK, TOPIC_ALERT_LOGS, TOPIC_ALERT_UEBA, TOPIC_ALERT_VULN,
    TOPIC_THREATS, TOPIC_ACTIONS,
]

# ─── Elasticsearch ────────────────────────────────────────────────────────────
ES_HOST: str          = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX_ALERTS: str  = os.getenv("ES_INDEX_ALERTS", "cyberdefense-alerts")
ES_INDEX_THREATS: str = os.getenv("ES_INDEX_THREATS", "cyberdefense-threats")

# ─── Redis ────────────────────────────────────────────────────────────────────
REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB: int   = int(os.getenv("REDIS_DB", 0))

# ─── ML / Detection ───────────────────────────────────────────────────────────
MODEL_PATH: str               = os.getenv("MODEL_PATH", "ml/models/threat_classifier.joblib")
CONFIDENCE_THRESHOLD: float   = float(os.getenv("MODEL_CONFIDENCE_THRESHOLD", 0.85))
ANOMALY_SENSITIVITY: float    = float(os.getenv("ANOMALY_SENSITIVITY", 0.92))
RETRAIN_INTERVAL_DAYS: int    = int(os.getenv("RETRAIN_INTERVAL_DAYS", 7))

# Detection thresholds
THRESHOLD_SYN_FLOOD_PPS: int    = int(os.getenv("THRESHOLD_SYN_FLOOD_PPS", 10000))
THRESHOLD_PORT_SCAN_PORTS: int  = int(os.getenv("THRESHOLD_PORT_SCAN_PORTS", 50))
THRESHOLD_BRUTE_FORCE: int      = int(os.getenv("THRESHOLD_BRUTE_FORCE", 10))
THRESHOLD_UEBA_ZSCORE: float    = float(os.getenv("THRESHOLD_UEBA_ZSCORE", 3.0))
THRESHOLD_CVSS_HIGH: float      = float(os.getenv("THRESHOLD_CVSS_HIGH", 7.0))
THRESHOLD_CVSS_CRITICAL: float  = float(os.getenv("THRESHOLD_CVSS_CRITICAL", 9.0))

# ─── Response / Mitigation ────────────────────────────────────────────────────
AUTO_BLOCK_IP: bool       = os.getenv("AUTO_BLOCK_IP", "true").lower() == "true"
AUTO_ISOLATE_HOST: bool   = os.getenv("AUTO_ISOLATE_HOST", "false").lower() == "true"
ALERT_WEBHOOK_URL: str    = os.getenv("ALERT_WEBHOOK_URL", "")
PAGERDUTY_API_KEY: str    = os.getenv("PAGERDUTY_API_KEY", "")

# Correlation window for orchestrator (seconds)
CORRELATION_WINDOW_SEC: int = int(os.getenv("CORRELATION_WINDOW_SEC", 120))

# ─── Threat Intel ─────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
MISP_URL: str           = os.getenv("MISP_URL", "")
MISP_API_KEY: str       = os.getenv("MISP_API_KEY", "")

# ─── General ──────────────────────────────────────────────────────────────────
LOG_LEVEL: str    = os.getenv("LOG_LEVEL", "INFO")
ENVIRONMENT: str  = os.getenv("ENVIRONMENT", "development")