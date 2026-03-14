import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from agents.log_analyzer.agent import analyze, failed_auth_counter

def test_brute_force_detected():
    failed_auth_counter.clear()
    for _ in range(10):
        result = analyze({"message": "Failed password for admin from 9.9.9.9", "host": "auth-server"})
    assert result is not None
    assert result.mitre_ttp == "T1110"

def test_root_login_detected():
    event = {"message": "Accepted publickey for root from 1.1.1.1 port 22", "host": "web-01"}
    alert = analyze(event)
    assert alert is not None
    assert alert.severity == "critical"
