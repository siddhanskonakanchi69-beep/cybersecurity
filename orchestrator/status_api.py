from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from .orchestrator import OrchestratorAgent
from .response_dispatcher import ResponseDispatcher

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orch = OrchestratorAgent(enable_kafka=False)
dispatcher = ResponseDispatcher()


@app.get("/")
def home():
    return {"message": "Cyber Kill Chain Defense API running"}


@app.get("/simulate_attack")
def simulate_attack():

    alerts = [
        {
            "agent_id": "network_monitor",
            "timestamp": 1,
            "severity": "LOW",
            "threat_type": "port_scan",
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.5",
            "mitre_technique_id": "T1046",
            "mitre_technique_name": "Network Service Discovery",
            "description": "Port scan detected",
            "raw_evidence": "",
            "recommended_action": "monitor"
        },
        {
            "agent_id": "log_analyzer",
            "timestamp": 2,
            "severity": "MEDIUM",
            "threat_type": "brute_force_ssh",
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.5",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "description": "SSH brute force",
            "raw_evidence": "",
            "recommended_action": "block"
        },
        {
            "agent_id": "behavior_monitor",
            "timestamp": 3,
            "severity": "HIGH",
            "threat_type": "sql_injection",
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.5",
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public Facing Application",
            "description": "SQL injection",
            "raw_evidence": "",
            "recommended_action": "block"
        },
        {
            "agent_id": "behavior_monitor",
            "timestamp": 4,
            "severity": "CRITICAL",
            "threat_type": "data_exfiltration",
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.5",
            "mitre_technique_id": "T1041",
            "mitre_technique_name": "Exfiltration Over C2 Channel",
            "description": "Data exfiltration",
            "raw_evidence": "",
            "recommended_action": "isolate"
        }
    ]

    for alert in alerts:
        orch.process_alert(alert)

    return {"message": "Attack simulation completed"}


@app.get("/incidents")
def get_incidents(limit: int = 20):

    incidents = []

    for ip, events in orch.correlation_window.items():
        for e in events:
            incidents.append(e)

    incidents.sort(key=lambda x: x["timestamp"], reverse=True)

    return incidents[:limit]


@app.get("/blocked_ips")
def get_blocked_ips():
    return dispatcher.get_blocked_ips()


@app.get("/status")
def get_status():
    return {
        "agents_active": [
            "network_monitor",
            "log_analyzer",
            "behavior_monitor",
            "vuln_scanner"
        ],
        "last_updated": datetime.utcnow()
    }