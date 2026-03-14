# 🛡️ CyberDefense Multi-Agent Threat Detection System

**A production-grade distributed cybersecurity threat detection and automated response platform.**

Built with Apache Kafka, Elasticsearch, ML-powered anomaly detection, and 4+ specialized intelligent agents working in concert to detect, correlate, and respond to threats in real-time.

---

## 🚀 Quick Start

### Prerequisites
- Docker Desktop / Docker Engine
- 8GB RAM minimum
- Python 3.10+

### 1. Start Infrastructure
```bash
docker compose up -d
```

This starts:
- ✅ Kafka (broker + KRaft controller)
- ✅ Elasticsearch 8.x
- ✅ Kibana (dashboards)
- ✅ Redis (state store)
- ✅ MinIO (forensics)
- ✅ Kafka UI (topic browser)

### 2. Create Kafka Topics
```bash
chmod +x kafka-topics.sh
./kafka-topics.sh
```

### 3. Verify Infrastructure Health
```bash
chmod +x verify-infra.sh
./verify-infra.sh
```

Expected output:
```
✅ Elasticsearch is healthy (status: green)
✅ Kibana is available
✅ Kafka broker is responding
✅ Redis ping → PONG
```

### 4. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 5. Run Agents (Each in a separate terminal)
```bash
# Terminal 1: Network Monitor
python -m agents.network_monitor.agent

# Terminal 2: Log Analyzer
python -m agents.log_analyzer.agent

# Terminal 3: UEBA (User Behavior Analytics)
python -m agents.ueba.agent

# Terminal 4: Vulnerability Scanner
python -m agents.vuln_scanner.agent

# Terminal 5: Orchestrator (Central Correlator)
python -m orchestrator.orchestrator

# Terminal 6: Response Agent
python -m agents.response.agent

# Terminal 7: Status API (Monitoring)
python -m orchestrator.status_api
```

### 6. Trigger Demo Attack Sequence
```bash
chmod +x demo/trigger_attacks.sh
./demo/trigger_attacks.sh localhost
```

This simulates 12 different attack types and demonstrates:
- ✅ Network-layer detection (port scans, SYN floods, DNS tunneling)
- ✅ Auth attacks (SSH brute force, SQL injection, path traversal)
- ✅ Behavioral anomalies (privilege escalation, lateral movement)
- ✅ Vulnerability detection (CVE matching)
- ✅ Multi-stage correlation (kill chain attack progression)
- ✅ Automated response (IP blocking, incident logging)

### 7. View Dashboards

**Kibana (Threat Visualization)**
```
http://localhost:5601

Index: cyberdefense-alerts
Index: cyberdefense-threats
```

**Kafka UI (Topic Browser)**
```
http://localhost:8080

Topics:
  - alerts.network, alerts.logs, alerts.ueba, alerts.vuln
  - threats.classified
  - actions.taken
```

**Orchestrator API (Real-time Status)**
```
http://localhost:8002

Endpoints:
  GET  /              - Health check
  GET  /threats       - Recent classified threats
  GET  /blocked_ips   - Currently blocked IPs
  GET  /stats         - Agent health & event counts
  GET  /actions       - Response action history
  POST /simulate      - Trigger demo attack
```

---

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   DATA SOURCES                              │
│  (Network | Logs | User Activity | Vulnerability Scans)     │
└────────────┬────────────────────────────────────────────────┘
             │
     ┌───────▼────────────────────────────────┐
     │         KAFKA MESSAGE BUS               │
     │  (Decoupling, Replay, Scaling)         │
     └──────────────┬──────────────────────────┘
                    │
      ┌─────────────┼─────────────────────┐
      │             │                     │
      ▼             ▼                     ▼
  ┌────────┐   ┌────────┐           ┌─────────┐
  │Network │   │ Log    │           │  UEBA   │
  │Monitor │   │Analyzer│  ...      │ Agent   │
  └────┬───┘   └───┬────┘           └────┬────┘
       │           │                     │
       └───────────┼─────────────────────┘
                   │
          ┌────────▼──────────┐
          │   Orchestrator    │
          │  (Correlation,    │
          │   Scoring,        │
          │   Kill Chain)     │
          └────────┬──────────┘
                   │
         ┌─────────┼──────────┐
         │         │          │
         ▼         ▼          ▼
    ┌─────────┐ ┌──────┐ ┌─────────┐
    │Response │ │Forens│ │Dashboard│
    │ Agent   │ │ics   │ │   API   │
    └─────────┘ └──────┘ └─────────┘
         │         │          │
         └─────────┼──────────┘
                   │
      ┌────────────┼─────────────┐
      │            │             │
      ▼            ▼             ▼
   ┌──────┐   ┌────────┐    ┌──────┐
   │Block │   │MinIO   │    │Slack │
   │IP    │   │Evidence│    │Alert │
   └──────┘   └────────┘    └──────┘
```

---

## 🎯 Agents Overview

### 1. Network Monitor
**Detects**: Port scans, SYN floods, DNS tunneling, data exfiltration

```python
# Monitors live network traffic via tcpdump/scapy
# Thresholds:
#   - Port scan: >15 unique ports in 30s → CRITICAL
#   - SYN flood: >200 SYN packets/s → HIGH
#   - Data exfil: >50MB per session → HIGH
```

**MITRE ATT&CK Coverage**: T1046, T1498, T1071, T1041

### 2. Log Analyzer
**Detects**: SSH brute force, SQL injection, path traversal, command injection

```python
# Watches /var/log/auth.log and /var/log/apache2/access.log
# Regex patterns for:
#   - Failed SSH: "Failed password from X" → count >= 5 → HIGH
#   - SQL injection: UNION, DROP, --, etc. → CRITICAL
#   - Path traversal: ../ or ..\\ in URI → HIGH
```

**MITRE ATT&CK Coverage**: T1110, T1190, T1083, T1059

### 3. UEBA Agent (User/Entity Behavior Analytics)
**Detects**: Anomalous user activity patterns

```python
# Builds per-user behavior baseline via IsolationForest
# Features: hour_of_day, day_of_week, files_accessed, login_failures, etc.
# Anomaly threshold: deviation > 0.3 std from baseline → CRITICAL
```

**MITRE ATT&CK Coverage**: T1078, T1548, T1021

### 4. Vulnerability Scanner
**Detects**: Known CVEs in running services

```python
# Matches service version to CVE database
# Severity map: CVSS >= 9.0 → CRITICAL, >= 7.0 → HIGH
# Outputs CVE ID, CVSS score, patch availability
```

**MITRE ATT&CK Coverage**: T1518

### 5. Response Agent
**Actions**: Block IP, isolate container, send alerts, log forensics

```python
# Routes based on severity:
#   CRITICAL/HIGH → Auto-block IP + isolate + Slack alert
#   MEDIUM → Slack alert only (human review)
#   LOW → Log only
```

### 6. Orchestrator
**Core Logic**: Correlate per-agent alerts, score threat severity, decide response

```python
# Correlation window: 120 seconds (configurable)
# Scoring formula: compound_score = Σ(severity) × multi_agent_boost × kill_chain_multiplier
# Kill chain mapping: port_scan→Recon, sql_injection→Exploitation, etc.
# Response thresholds: > 25 → CRITICAL, > 15 → HIGH, > 8 → MEDIUM
```

---

## 📈 Kafka Topics

| Topic | Direction | Purpose |
|-------|-----------|---------|
| `raw.network.events` | → Network Monitor | Real-time network packets |
| `raw.logs` | → Log Analyzer | System/auth log lines |
| `raw.user.events` | → UEBA | User activity events |
| `raw.vuln.events` | → Vuln Scanner | Vulnerability scan results |
| `alerts.network` | → Orchestrator | Network monitor alerts |
| `alerts.logs` | → Orchestrator | Log analyzer alerts |
| `alerts.ueba` | → Orchestrator | Behavioral anomalies |
| `alerts.vuln` | → Orchestrator | Vulnerability findings |
| `threats.classified` | → Response + Forensics | Correlated, scored threats |
| `actions.taken` | Audit | All response actions |

---

## 🔍 Example Alert Flow

```
User runs: nmap -sS -p 1-20 localhost

1. Network Monitor detects 20 unique ports in 2 seconds
   → Publishes to alerts.network with severity=CRITICAL

2. Orchestrator consumes from alerts.network
   → Correlates by source_ip
   → Scores compound_score = 10 (CRITICAL)
   → Maps threat_type "port_scan" → MITRE T1046
   → Publishes to threats.classified

3. Response Agent consumes from threats.classified
   → Sees severity=CRITICAL
   → Calls dispatcher.block_ip("192.168.1.100")
   → Sends Slack alert
   → Logs action to Redis

4. Forensics Agent
   → Stores evidence JSON to MinIO
   → Incident ID, timestamp, full alert context
   → TTL: 90 days

5. Dashboard (Kibana)
   → Displays alert on threat timeline
   → Shows kill chain progression
   → Links to evidence in MinIO
```

---

## 🛠️ Configuration

### `.env` or `config/config.env`

```env
# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_GROUP_ID=cyberdefense-agents

# Elasticsearch
ES_HOST=http://localhost:9200
ES_INDEX_ALERTS=cyberdefense-alerts
ES_INDEX_THREATS=cyberdefense-threats

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# ML / Detection
MODEL_CONFIDENCE_THRESHOLD=0.85
ANOMALY_SENSITIVITY=0.92
CORRELATION_WINDOW_SEC=120

# Response Actions
AUTO_BLOCK_IP=true
AUTO_ISOLATE_HOST=false
SLACK_WEBHOOK_URL=       # Optional

# MinIO Forensics
MINIO_ENDPOINT=localhost:9000
MINIO_ROOT_USER=admin
MINIO_ROOT_PASSWORD=admin1234
MINIO_BUCKET=cyberdefense-forensics
```

---

## 📚 ML Models

**Location**: `ml_models/`

### Pre-trained Models
- `isolation_forest.pkl` — Unsupervised anomaly detection
- `random_forest.pkl` — 5-class threat classification (normal, probe, r2l, u2r, dos)
- `gradient_boost.pkl` — Binary attack/normal classifier
- `scaler.pkl` — Feature standardization

### API Endpoints

```bash
# Prediction
POST /predict
{
  "features": {"severity": 2, "type": "port_scan"}
}
→ {
    "anomaly_score": -0.15,
    "is_anomaly": true,
    "threat_class": "probe",
    "overall_severity": "HIGH",
    "model_agreement": true
  }

# Explainability (SHAP)
POST /explain
{
  "features": {...}
}
→ {
    "top_features": {
      "severity": 0.45,
      "port_count": 0.38,
      ...
    }
  }

# Online Learning
POST /retrain
{
  "features": {...},
  "true_label": "u2r",
  "feedback": "Confirmed privilege escalation"
}
→ {"status": "feedback_recorded", ...}
```

---

## 🧪 Testing

### Run Unit Tests
```bash
pytest tests/unit/ -v
```

### Run Integration Tests
```bash
pytest tests/integration/ -v
```

### Smoke Test
```bash
./verify-infra.sh
```

### Full VAPT Demo
```bash
./demo/trigger_attacks.sh localhost
```

---

## 📖 Project Structure

```
cybersecurity/
├── agents/
│   ├── network_monitor/      # Port scan, SYN flood, DNS tunnel
│   ├── log_analyzer/         # SSH brute, SQL injection
│   ├── ueba/                 # User behavior anomalies
│   ├── vuln_scanner/         # CVE matching
│   └── response/             # Automated actions
├── orchestrator/
│   ├── orchestrator.py       # Central correlator
│   ├── response_dispatcher.py # Action execution
│   ├── kill_chain.py         # MITRE mapping
│   ├── forensics_agent.py    # Evidence collection
│   └── status_api.py         # REST monitoring
├── ml_models/
│   ├── serve.py              # Prediction API
│   ├── train.py              # Model training
│   ├── feature_engineering.py
│   └── models/               # Pre-trained models
├── shared/
│   ├── schemas/              # Pydantic event models
│   └── utils/                # Kafka, ES, Redis clients
├── config/
│   ├── config.py             # Central configuration
│   ├── config.env            # Environment variables
│   └── mitre_mapping.py      # ATT&CK mapping
├── tests/
│   ├── unit/                 # Agent unit tests
│   └── integration/          # End-to-end tests
├── dashboard/                # Kibana saved objects
├── demo/                     # Attack simulation
├── docker-compose.yml        # Infrastructure as code
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

---

## 🔐 Security Best Practices

✅ **MITRE ATT&CK Coverage**
- Detects threats across kill chain stages
- Maps each detection to specific techniques

✅ **Audit Trail**
- Every alert indexed in Elasticsearch
- Every response action logged
- ML predictions explainable (SHAP)

✅ **Data Retention**
- Kafka: 7 days (incident replay)
- Elasticsearch: 30 days (tunable)
- MinIO: 90 days (compliance)
- Redis: TTL-aware (auto-expiring blocks)

✅ **Graceful Degradation**
- ML service down? Use rule-based scoring
- Redis unavailable? In-memory fallback
- Elasticsearch slow? Async indexing

---

## 🚀 Scaling Considerations

### Horizontal Scaling
- **Agents**: Run multiple instances per agent type; Kafka auto-distributes tasks
- **Orchestrator**: Shard by source_ip; use Redis locks for consistency
- **Status API**: Stateless; add load balancer

### Vertical Scaling
- **Network Monitor**: Increase packet capture threads
- **Orchestrator**: Increase correlation window buffer size
- **ML Service**: Add GPU, batch predictions

### Cost Optimization
- Kafka message retention: tune per compliance needs
- Elasticsearch index lifecycle: roll old indices to warm tier
- MinIO lifecycle: tier evidence to cheaper S3 after 30 days

---

## 📞 Support & Contribution

For issues, feature requests, or improvements:
1. Check documentation in `REVIEW_2_PITCH.md`
2. Run `verify-infra.sh` to validate setup
3. Check agent logs for error messages
4. Review Kibana for alert patterns

---

## 📄 License

[Your License Here]

---

## 🎓 References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Apache Kafka Documentation](https://kafka.apache.org/docs/)
- [Elasticsearch Security Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api.html)
- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [SHAP Model Explainability](https://github.com/slundberg/shap)

---

**Last Updated**: March 14, 2026  
**Version**: 2.0 (Review 2 Complete)
