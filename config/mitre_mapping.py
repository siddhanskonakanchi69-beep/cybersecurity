# config/mitre_mapping.py

MITRE_MAP: dict[str, dict] = {
    "port_scan": {
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic":         "Discovery",
        "url":            "https://attack.mitre.org/techniques/T1046/",
    },
    "syn_flood": {
        "technique_id":   "T1498",
        "technique_name": "Network Denial of Service",
        "tactic":         "Impact",
        "url":            "https://attack.mitre.org/techniques/T1498/",
    },
    "brute_force_ssh": {
        "technique_id":   "T1110.001",
        "technique_name": "Password Guessing",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/001/",
    },
    "brute_force_http": {
        "technique_id":   "T1110.001",
        "technique_name": "Password Guessing",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/001/",
    },
    "sql_injection": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "url":            "https://attack.mitre.org/techniques/T1190/",
    },
    "path_traversal": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "url":            "https://attack.mitre.org/techniques/T1083/",
    },
    "dns_tunneling": {
        "technique_id":   "T1071.004",
        "technique_name": "DNS Application Layer Protocol",
        "tactic":         "Command And Control",
        "url":            "https://attack.mitre.org/techniques/T1071/004/",
    },
    "data_exfiltration": {
        "technique_id":   "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic":         "Exfiltration",
        "url":            "https://attack.mitre.org/techniques/T1041/",
    },
    "lateral_movement": {
        "technique_id":   "T1021",
        "technique_name": "Remote Services",
        "tactic":         "Lateral Movement",
        "url":            "https://attack.mitre.org/techniques/T1021/",
    },
    "privilege_escalation": {
        "technique_id":   "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic":         "Privilege Escalation",
        "url":            "https://attack.mitre.org/techniques/T1068/",
    },
    "anomalous_behavior": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Defense Evasion",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
    "vulnerability_found": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "url":            "https://attack.mitre.org/techniques/T1190/",
    },
}

_UNKNOWN_ENTRY: dict = {
    "technique_id":   "T0000",
    "technique_name": "Unknown Technique",
    "tactic":         "Unknown",
    "url":            "https://attack.mitre.org/",
}


def get_mitre_info(threat_type: str) -> dict:
    """Return MITRE ATT&CK info for a given threat type string.

    Falls back to a safe default if the threat type is not mapped.
    """
    return MITRE_MAP.get(threat_type, _UNKNOWN_ENTRY)
