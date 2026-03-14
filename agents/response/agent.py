"""
Response & Mitigation Agent
Consumes classified threats and executes automated playbooks.
Actions: block IP, isolate host, revoke credentials, alert admins.
"""
import json, os, subprocess, time
import httpx
import redis
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

# Redis connection for blocklist persistence
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB   = int(os.getenv("REDIS_DB", 0))

try:
    rdb = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    rdb.ping()
    logger.info("Connected to Redis for blocklist persistence")
except Exception:
    rdb = None
    logger.warning("Redis unavailable - blocklist will be firewall-only")


# ─── Playbook Actions ──────────────────────────────────────────────────────────

def block_ip(ip: str) -> dict:
    """Block an IP using Windows Firewall and add it to Redis blocklist."""
    rule_name = f"CyberDefense-Block-{ip}"

    # Check if already blocked (avoid duplicates)
    if rdb and rdb.sismember("blocked_ips", ip):
        logger.info(f"IP {ip} is already blocked - skipping")
        return {"action": "block_ip", "target": ip, "status": "already_blocked"}

    # Block via Windows Firewall (inbound)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.warning(f"BLOCKED IP via Windows Firewall: {ip}")
            status = "executed"
        else:
            logger.error(f"Firewall block failed for {ip}: {result.stderr}")
            status = "firewall_error"
    except Exception as e:
        logger.error(f"Firewall command failed: {e}")
        status = "firewall_error"

    # Persist to Redis blocklist
    if rdb:
        rdb.sadd("blocked_ips", ip)
        rdb.hset(f"blocked_ip:{ip}", mapping={
            "blocked_at": str(int(time.time())),
            "rule_name": rule_name,
            "status": status,
        })

    return {"action": "block_ip", "target": ip, "status": status}


def unblock_ip(ip: str) -> dict:
    """Remove an IP block from Windows Firewall and Redis."""
    rule_name = f"CyberDefense-Block-{ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            capture_output=True, text=True, timeout=10
        )
        logger.info(f"UNBLOCKED IP: {ip}")
    except Exception as e:
        logger.error(f"Unblock failed: {e}")

    if rdb:
        rdb.srem("blocked_ips", ip)
        rdb.delete(f"blocked_ip:{ip}")

    return {"action": "unblock_ip", "target": ip, "status": "executed"}


def isolate_host(host: str) -> dict:
    """Block all traffic from a host via Windows Firewall."""
    rule_name = f"CyberDefense-Isolate-{host}"
    logger.warning(f"ISOLATING HOST: {host}")
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={host}"],
            capture_output=True, text=True, timeout=10
        )
        # Also block outbound
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}-out", "dir=out", "action=block",
             f"remoteip={host}"],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        logger.error(f"Isolate failed: {e}")
        return {"action": "isolate_host", "target": host, "status": "error"}
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
