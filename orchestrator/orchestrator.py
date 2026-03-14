import time
import json
import threading
from collections import defaultdict, deque
from uuid import uuid4

from kill_chain import analyze_kill_chain_progression


SEVERITY_SCORES = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 10
}


class OrchestratorAgent:

    def __init__(self, enable_kafka=False):

        self.correlation_window = defaultdict(lambda: deque(maxlen=100))

        self.lock = threading.Lock()

        self.running = True

    def process_alert(self, threat_report):

        source_ip = threat_report["source_ip"]

        with self.lock:
            self.correlation_window[source_ip].append(threat_report)

        result = self.correlate_and_score(source_ip)

        if result["compound_score"] >= 8:
            self.decide_response(result)

    def correlate_and_score(self, source_ip):

        events = list(self.correlation_window[source_ip])

        agents = list(set(e["agent_id"] for e in events))

        base_score = sum(SEVERITY_SCORES[e["severity"]] for e in events)

        if len(agents) > 1:
            base_score *= 1.5

        kill_chain = analyze_kill_chain_progression(events)

        compound_score = base_score * (1 + kill_chain["progression_score"] * 0.2)

        if compound_score > 25:
            sev = "CRITICAL"
        elif compound_score > 15:
            sev = "HIGH"
        elif compound_score > 8:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        return {
            "source_ip": source_ip,
            "compound_score": compound_score,
            "alert_count": len(events),
            "agents_involved": agents,
            "kill_chain": kill_chain,
            "recommended_severity": sev
        }

    def decide_response(self, result):

        sev = result["recommended_severity"]

        if sev == "CRITICAL":
            action = "AUTO_BLOCKED"
        elif sev == "HIGH":
            action = "AUTO_BLOCKED"
        elif sev == "MEDIUM":
            action = "PENDING_REVIEW"
        else:
            action = "LOGGED"

        self.log_incident(result, action)

    def log_incident(self, result, action):

        incident = {
            "incident_id": str(uuid4()),
            "timestamp": int(time.time()),
            "source_ip": result["source_ip"],
            "compound_score": result["compound_score"],
            "alert_count": result["alert_count"],
            "agents_involved": result["agents_involved"],
            "kill_chain": result["kill_chain"],
            "severity": result["recommended_severity"],
            "action_taken": action
        }

        print("\n=== INCIDENT DETECTED ===")
        print(json.dumps(incident, indent=2))