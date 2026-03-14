import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from agents.log_analyzer.agent import (
    LogAnalyzerAgent, SSH_FAIL_RE, SSH_SUCCESS_RE,
    SQLI_PATTERNS, PATH_TRAVERSAL_RE,
)


@pytest.fixture
def agent():
    """Create agent with mocked Kafka and no file system side effects."""
    a = LogAnalyzerAgent.__new__(LogAnalyzerAgent)
    import threading
    from collections import defaultdict
    a.lock = threading.Lock()
    a.ssh_failures = defaultdict(list)
    a.ssh_success_alerted = set()
    a._published = []

    def mock_publish(report):
        a._published.append(report)

    def mock_emit(report):
        a._published.append(report)

    a._publish = mock_publish
    a._emit = mock_emit
    return a


# ─── Regex sanity checks ──────────────────────────────────────────────────────

def test_ssh_fail_pattern():
    line = "Mar 14 10:30:01 server sshd[1234]: Failed password for admin from 9.9.9.9 port 22 ssh2"
    m = SSH_FAIL_RE.search(line)
    assert m is not None
    assert m.group(1) == "9.9.9.9"


def test_ssh_success_pattern():
    line = "Mar 14 10:31:00 server sshd[1234]: Accepted password for admin from 9.9.9.9 port 22 ssh2"
    m = SSH_SUCCESS_RE.search(line)
    assert m is not None
    assert m.group(1) == "9.9.9.9"


def test_sql_injection_union_select():
    payload = "GET /login?user=admin UNION SELECT 1,2,3-- HTTP/1.1"
    matched = any(p.search(payload) for p in SQLI_PATTERNS)
    assert matched


def test_sql_injection_or_1_equals_1():
    payload = "GET /login?user=admin OR 1=1 HTTP/1.1"
    matched = any(p.search(payload) for p in SQLI_PATTERNS)  
    assert matched


def test_sql_injection_drop_table():
    payload = "GET /api?q=DROP TABLE users HTTP/1.1"
    matched = any(p.search(payload) for p in SQLI_PATTERNS)
    assert matched


def test_path_traversal_detected():
    line = 'GET /../../etc/passwd HTTP/1.1'
    assert PATH_TRAVERSAL_RE.search(line) is not None


def test_path_traversal_backslash():
    line = r'GET /..\..\windows\system32\config\sam HTTP/1.1'
    assert PATH_TRAVERSAL_RE.search(line) is not None


def test_normal_traffic_no_match():
    line = "GET /index.html HTTP/1.1"
    assert PATH_TRAVERSAL_RE.search(line) is None
    assert not any(p.search(line) for p in SQLI_PATTERNS)


# ─── Agent integration (mocked) ───────────────────────────────────────────────

def test_brute_force_ssh_detection(agent):
    """Simulate >5 failed SSH logins within window — should trigger alert."""
    import time

    for i in range(8):
        line = f"Mar 14 10:30:{i:02d} server sshd[1234]: Failed password for admin from 10.10.10.10 port 22 ssh2"
        agent._analyze_auth_line(line)

    assert len(agent._published) >= 1
    alert = agent._published[0]
    assert alert["threat_type"] == "brute_force_ssh"
    assert alert["severity"] == "HIGH"
    assert alert["source_ip"] == "10.10.10.10"


def test_credential_stuffing_detection(agent):
    """Simulate failed logins followed by a success — should trigger CRITICAL."""
    import time

    # 5 failures
    for i in range(5):
        line = f"Failed password for admin from 5.5.5.5 port 22 ssh2"
        agent._analyze_auth_line(line)

    # Then a success
    success_line = "Accepted password for admin from 5.5.5.5 port 22 ssh2"
    agent._analyze_auth_line(success_line)

    # Should have at least one CRITICAL alert for credential stuffing
    critical_alerts = [a for a in agent._published if a["severity"] == "CRITICAL"]
    assert len(critical_alerts) >= 1


def test_sql_injection_detection(agent):
    """SQL injection line should trigger CRITICAL alert."""
    line = '192.168.1.50 - - [14/Mar/2026:10:30:01 +0000] "GET /login?user=admin UNION SELECT 1,2,3-- HTTP/1.1" 200 1234'
    agent._analyze_http_line(line)
    assert len(agent._published) >= 1
    assert agent._published[0]["threat_type"] == "sql_injection"
    assert agent._published[0]["severity"] == "CRITICAL"


def test_path_traversal_alert(agent):
    """Path traversal line should trigger HIGH alert."""
    line = '10.0.0.5 - - [14/Mar/2026:10:30:01 +0000] "GET /../../etc/passwd HTTP/1.1" 200 500'
    agent._analyze_http_line(line)
    assert len(agent._published) >= 1
    assert agent._published[0]["threat_type"] == "path_traversal"
    assert agent._published[0]["severity"] == "HIGH"
