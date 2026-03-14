"""
Response & Mitigation Agent
Consumes classified threats and executes automated playbooks.
Actions: block IP, isolate host, revoke credentials, alert admins.
"""
import json, os
import httpx
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from shared.utils.kafka_client import get_producer, get_consumer, publish
from shared.schemas.event import ThreatEvent

INPUT_TOPIC  = "threats.classified"
OUTPUT_TOPIC = "actions.taken"

AUTO_BLOCK_IP     = os.getenv("AUTO_BLOCK_IP", "true").lower() == "true"
AUTO_ISOLATE_HOST = os.getenv("AUTO_ISOLATE_HOST", "false").lower() == "true"
WEBHOOK_URL       = os.getenv("ALERT_WEBHOOK_URL", "")
CONFIDENCE_GATE   = float(os.getenv("MODEL_CONFIDENCE_THRESHOLD", 0.85))


# ─── Playbook Actions ──────────────────────────────────────────────────────────

def block_ip(ip: str) -> dict:
    """Add IP to firewall blocklist (stub — wire to your firewall API)."""
    logger.warning(f"🚫 BLOCKING IP: {ip}")
    # Example: call iptables API or cloud WAF
    # subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    return {"action": "block_ip", "target": ip, "status": "executed"}


def isolate_host(host: str) -> dict:
    """Isolate host to quarantine VLAN (stub — wire to your SDN/switch API)."""
    logger.warning(f"🔒 ISOLATING HOST: {host}")
    return {"action": "isolate_host", "target": host, "status": "executed"}


def alert_admin(event: dict, action_taken: str) -> None:
    """Send rich alert to Slack webhook."""
    if not WEBHOOK_URL:
        logger.info("No webhook URL configured — skipping Slack alert")
        return
    payload = {
        "text": f"*[{event['severity'].upper()}] CyberDefense Alert*",
        "attachments": [{
            "color": "#FF0000" if event["severity"] == "critical" else "#FFA500",
            "fields": [
                {"title": "Event Type", "value": event.get("event_type"), "short": True},
                {"title": "Confidence",  "value": f"{event.get('confidence', 0):.0%}", "short": True},
                {"title": "Source IP",   "value": event.get("source_ip", "N/A"), "short": True},
                {"title": "Host",        "value": event.get("host", "N/A"), "short": True},
                {"title": "MITRE TTP",   "value": event.get("mitre_ttp", "N/A"), "short": True},
                {"title": "Action",      "value": action_taken, "short": True},
                {"title": "Details",     "value": str(event.get("details", {}))},
            ]
        }]
    }
    try:
        httpx.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")


def execute_playbook(event: dict) -> list[dict]:
    """Route to appropriate playbook based on severity and MITRE TTP."""
    severity   = event.get("severity", "low")
    confidence = event.get("confidence", 0.0)
    actions    = []

    # Human-in-the-loop gate: low confidence → only alert, no auto-action
    if confidence < CONFIDENCE_GATE:
        logger.info(f"Confidence {confidence:.2%} below threshold — queuing for human review")
        alert_admin(event, "QUEUED FOR HUMAN REVIEW")
        return [{"action": "human_review", "reason": "low_confidence"}]

    # High/Critical → auto-mitigate
    if severity in ("critical", "high"):
        if AUTO_BLOCK_IP and event.get("source_ip"):
            actions.append(block_ip(event["source_ip"]))

        if AUTO_ISOLATE_HOST and event.get("host"):
            actions.append(isolate_host(event["host"]))

        action_summary = ", ".join(a["action"] for a in actions) or "alert_only"
        alert_admin(event, action_summary)

    elif severity == "medium":
        alert_admin(event, "ALERT_SENT")
        actions.append({"action": "alert_sent", "target": event.get("source_ip")})

    return actions


def run():
    logger.info("⚡ Response Agent starting...")
    consumer = get_consumer([INPUT_TOPIC], group_id="response-group")
    producer = get_producer()

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            logger.error(f"Kafka error: {msg.error()}")
            continue

        event   = json.loads(msg.value().decode("utf-8"))
        actions = execute_playbook(event)

        audit = {**event, "actions_taken": actions, "agent_id": "response-agent-01"}
        publish(producer, OUTPUT_TOPIC, audit)


if __name__ == "__main__":
    run()
