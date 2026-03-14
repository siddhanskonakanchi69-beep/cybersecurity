from typing import List, Dict

KILL_CHAIN_STAGES = {
    1: "Reconnaissance",
    2: "Weaponization",
    3: "Delivery",
    4: "Exploitation",
    5: "Installation",
    6: "Command & Control",
    7: "Actions on Objectives"
}

KILL_CHAIN_MAP = {
    "port_scan": "Reconnaissance",
    "vuln_scan": "Reconnaissance",
    "brute_force_ssh": "Delivery",
    "brute_force_http": "Delivery",
    "sql_injection": "Exploitation",
    "path_traversal": "Exploitation",
    "privilege_escalation": "Installation",
    "dns_tunneling": "Command & Control",
    "lateral_movement": "Command & Control",
    "data_exfiltration": "Actions on Objectives",
    "anomalous_behavior": "Actions on Objectives"
}

STAGE_NAME_TO_NUM = {v: k for k, v in KILL_CHAIN_STAGES.items()}


def analyze_kill_chain_progression(events: List[Dict]) -> Dict:

    if not events:
        return {
            "source_ip": None,
            "stages_detected": [],
            "progression_score": 0,
            "is_apt_pattern": False,
            "narrative": "No events"
        }

    source_ip = events[0]["source_ip"]

    detected_stages = set()

    for event in events:
        threat = event["threat_type"]

        if threat in KILL_CHAIN_MAP:
            stage = STAGE_NAME_TO_NUM[KILL_CHAIN_MAP[threat]]
            detected_stages.add(stage)

    stages = sorted(list(detected_stages))

    progression_score = max(stages) if stages else 0

    is_apt = all(stage in detected_stages for stage in [1, 2, 3])

    names = [KILL_CHAIN_STAGES[s] for s in stages]

    narrative = "Attacker progressed through: " + " → ".join(names)

    return {
        "source_ip": source_ip,
        "stages_detected": stages,
        "progression_score": progression_score,
        "is_apt_pattern": is_apt,
        "narrative": narrative
    }