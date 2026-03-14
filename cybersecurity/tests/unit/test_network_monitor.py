import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from agents.network_monitor.agent import NetworkMonitorAgent


@pytest.fixture
def agent():
    """Create agent instance with mocked Kafka producer."""
    a = NetworkMonitorAgent.__new__(NetworkMonitorAgent)
    # Minimal init without Kafka connection
    import threading
    from collections import defaultdict
    a.lock = threading.Lock()
    a.port_events = defaultdict(list)
    a.syn_events = defaultdict(list)
    a.session_bytes = defaultdict(int)
    a.alerted_exfil = set()
    a.alerted_scan = set()
    a.alerted_syn = set()
    a._published = []

    # Mock publish
    def mock_publish(report):
        a._published.append(report)

    a._publish = mock_publish
    return a


def test_port_scan_build_report(agent):
    """Test that _build_report produces correct ThreatReport dict."""
    report = agent._build_report(
        severity="CRITICAL",
        threat_type="port_scan",
        src_ip="1.2.3.4",
        dst_ip="10.0.0.1",
        description="Port scan test",
        raw_evidence="test evidence",
        recommended_action="block",
    )
    assert report["severity"] == "CRITICAL"
    assert report["threat_type"] == "port_scan"
    assert report["mitre_technique_id"] == "T1046"
    assert report["mitre_technique_name"] == "Network Service Discovery"
    assert report["source_ip"] == "1.2.3.4"
    assert report["destination_ip"] == "10.0.0.1"
    assert "timestamp" in report
    assert "agent_id" in report


def test_port_scan_detection(agent):
    """Simulate enough unique ports to trigger port scan detection."""
    import time
    now = time.time()

    # Feed 20 unique ports in rapid succession — exceeds PORT_SCAN_LIMIT (15)
    for port in range(1, 21):
        agent._handle_port_scan("192.168.1.100", "10.0.0.1", port, now + port * 0.1)

    assert len(agent._published) >= 1
    alert = agent._published[0]
    assert alert["threat_type"] == "port_scan"
    assert alert["severity"] == "CRITICAL"
    assert alert["source_ip"] == "192.168.1.100"


def test_no_port_scan_below_threshold(agent):
    """Traffic below threshold should not trigger alerting."""
    import time
    now = time.time()
    for port in range(1, 10):  # only 9 ports (< 15 threshold)
        agent._handle_port_scan("10.10.10.10", "10.0.0.1", port, now)

    assert len(agent._published) == 0


def test_syn_flood_detection(agent):
    """Simulate SYN flood by sending >200 SYN events in 1 second."""
    import time
    now = time.time()
    for i in range(250):
        agent._handle_syn_flood("5.6.7.8", "10.0.0.1", now + i * 0.001)

    assert len(agent._published) >= 1
    alert = agent._published[0]
    assert alert["threat_type"] == "syn_flood"
    assert alert["severity"] == "HIGH"


def test_exfil_detection(agent):
    """Simulate large data transfer exceeding 50 MB threshold."""
    chunk = 1024 * 1024  # 1 MB per call
    for _ in range(55):
        agent._handle_exfil("172.16.0.5", "93.184.216.34", 54321, 443, chunk)

    assert len(agent._published) >= 1
    alert = agent._published[0]
    assert alert["threat_type"] == "data_exfiltration"
    assert alert["severity"] == "HIGH"
