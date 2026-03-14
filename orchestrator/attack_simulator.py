import time
from orchestrator import OrchestratorAgent

attacker_ip = "192.168.1.200"

attack_sequence = [
    {
        "agent_id": "network_monitor",
        "severity": "LOW",
        "threat_type": "port_scan",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery"
    },
    {
        "agent_id": "log_analyzer",
        "severity": "MEDIUM",
        "threat_type": "brute_force_ssh",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force"
    },
    {
        "agent_id": "behavior_monitor",
        "severity": "HIGH",
        "threat_type": "sql_injection",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public Facing Application"
    },
    {
        "agent_id": "behavior_monitor",
        "severity": "CRITICAL",
        "threat_type": "data_exfiltration",
        "mitre_technique_id": "T1041",
        "mitre_technique_name": "Exfiltration Over C2 Channel"
    }
]

orch = OrchestratorAgent(enable_kafka=False)

for attack in attack_sequence:

    event = {
        "agent_id": attack["agent_id"],
        "timestamp": int(time.time()),
        "severity": attack["severity"],
        "threat_type": attack["threat_type"],
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "mitre_technique_id": attack["mitre_technique_id"],
        "mitre_technique_name": attack["mitre_technique_name"],
        "description": attack["threat_type"],
        "raw_evidence": "",
        "recommended_action": "monitor"
    }

    print("\nALERT GENERATED:", attack["threat_type"])

    orch.process_alert(event)

    time.sleep(2)