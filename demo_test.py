#!/usr/bin/env python3
"""
Simple demo: Send test alerts through the system
"""
import json
import time
from datetime import datetime
from shared.utils.kafka_client import get_producer
from config.config import TOPIC_ALERT_NETWORK, TOPIC_ALERT_LOGS

def send_test_alerts():
    """Send sample alerts to trigger orchestrator"""
    producer = get_producer()
    
    alerts = [
        {
            "agent_id": "network_monitor",
            "timestamp": int(time.time()),
            "event_type": "port_scan",
            "threat_type": "network_scan",
            "severity": "HIGH",
            "confidence": 0.95,
            "source_ip": "192.168.1.100",
            "destination_ip": "0.0.0.0",
            "details": "Port scan detected on 15 unique ports in 30 seconds",
            "mitre_ttp": "T1046",
        },
        {
            "agent_id": "log_analyzer",
            "timestamp": int(time.time()),
            "event_type": "ssh_brute_force",
            "threat_type": "auth_attack",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "source_ip": "192.168.1.100",
            "user": "admin",
            "host": "server1",
            "details": "5+ failed SSH login attempts in 60 seconds",
            "mitre_ttp": "T1110.001",
        },
        {
            "agent_id": "ueba",
            "timestamp": int(time.time()),
            "event_type": "anomalous_behavior",
            "threat_type": "behavioral_anomaly",
            "severity": "MEDIUM",
            "confidence": 0.87,
            "source_ip": "192.168.1.100",
            "user": "admin",
            "host": "server1",
            "details": "User behavior anomaly detected by IsolationForest",
            "mitre_ttp": "T1588",
        },
    ]
    
    print("=" * 70)
    print("🚀 SENDING TEST ALERTS TO KAFKA")
    print("=" * 70)
    
    for i, alert in enumerate(alerts, 1):
        try:
            if alert.get("agent_id") == "network_monitor":
                topic = TOPIC_ALERT_NETWORK
            else:
                topic = TOPIC_ALERT_LOGS
            
            producer.produce(
                topic=topic,
                value=json.dumps(alert).encode("utf-8"),
                callback=lambda msg=None: None,
            )
            print(f"  [{i}] ✅ Sent {alert['threat_type']} to {topic}")
        except Exception as e:
            print(f"  [{i}] ❌ Failed: {e}")
    
    producer.flush()
    print("=" * 70)
    print("✅ All alerts sent! Orchestrator processing...")
    print("=" * 70)
    print("\n💡 To view results:")
    print("   • Kibana:         http://localhost:5601")
    print("   • Kafka UI:       http://localhost:8080")
    print("   • MinIO Console:  http://localhost:9001 (admin/admin1234)")
    print("=" * 70)

if __name__ == "__main__":
    send_test_alerts()
