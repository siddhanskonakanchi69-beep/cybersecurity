import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from agents.network_monitor.agent import analyze

def test_syn_flood_detected():
    raw = {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "packets_per_second": 15000, "distinct_ports": 1}
    alert = analyze(raw)
    assert alert is not None
    assert alert.severity == "critical"
    assert alert.mitre_ttp == "T1498"

def test_port_scan_detected():
    raw = {"src_ip": "5.6.7.8", "dst_ip": "10.0.0.2", "packets_per_second": 100, "distinct_ports": 80}
    alert = analyze(raw)
    assert alert is not None
    assert alert.severity == "high"
    assert alert.mitre_ttp == "T1046"

def test_normal_traffic_no_alert():
    raw = {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.3", "packets_per_second": 500, "distinct_ports": 3}
    alert = analyze(raw)
    assert alert is None
