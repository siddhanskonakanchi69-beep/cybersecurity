# 🛡️ Multi-Agent Cybersecurity Defense System

A collaborative agentic AI framework that deploys multiple intelligent agents to monitor, analyze, and respond to cybersecurity threats in real time.

## Architecture

```
Data Sources (Network, Logs, Users, Endpoints)
        ↓
┌──────────────────────────────────┐
│         Orchestrator Agent        │  ← Correlates & routes
└──────────────┬───────────────────┘
       ┌───────┴────────┐
  ┌────▼────┐  ┌────────▼──────┐  ┌─────▼──────┐  ┌────▼────────┐
  │ Network │  │ Log Analyzer  │  │ UEBA Agent │  │Vuln Scanner │
  │ Monitor │  │               │  │            │  │             │
  └────┬────┘  └───────┬───────┘  └─────┬──────┘  └────┬────────┘
       └───────────────▼──────────────────┘
                ┌───────▼────────┐
                │ Threat Classifier│  ← ML Engine (XGBoost)
                └───────┬────────┘
                ┌───────▼────────┐
                │Response & Mitig│  ← Block IP, Isolate, Alert
                └────────────────┘
```

## Repo Structure

```
cybersecurity/
├── agents/
│   ├── network_monitor/     # Network traffic anomaly detection
│   ├── log_analyzer/        # System log parsing & pattern matching
│   ├── ueba/                # User behavior analytics
│   ├── vuln_scanner/        # CVE / vulnerability detection
│   └── response/            # Automated mitigation playbooks
├── orchestrator/            # Central coordination & event correlation
├── ml/
│   ├── training/            # Model training scripts
│   ├── models/              # Saved model artifacts
│   └── data/                # Training datasets
├── dashboard/               # Kibana dashboards
├── shared/
│   ├── schemas/             # Pydantic event schemas
│   └── utils/               # Kafka, ES, Redis clients
├── tests/
│   ├── unit/
│   └── integration/
├── docker-compose.yml
├── .env.example
└── requirements.txt
```

## Quick Start

```bash
# 1. Clone & configure
git clone https://github.com/siddhanskonakanchi69-beep/cybersecurity.git
cd cybersecurity
cp .env.example .env   # fill in your keys

# 2. Start infrastructure
docker compose up -d

# 3. Create Kafka topics
chmod +x kafka-topics.sh && ./kafka-topics.sh

# 4. Verify everything is live
chmod +x verify-infra.sh && ./verify-infra.sh

# 5. Install Python deps
pip install -r requirements.txt

# 6. Run agents (each in a separate terminal)
python -m agents.network_monitor.agent
python -m agents.log_analyzer.agent
python -m agents.ueba.agent
python -m agents.vuln_scanner.agent
python -m orchestrator.orchestrator
python -m agents.response.agent
```

## Kafka Topics

| Topic | Direction | Description |
|---|---|---|
| `raw.network.events` | → Network Monitor | Raw network telemetry |
| `raw.logs` | → Log Analyzer | System / auth logs |
| `raw.user.events` | → UEBA | User activity events |
| `raw.vuln.events` | → Vuln Scanner | Scan results |
| `alerts.network/logs/ueba/vuln` | → Orchestrator | Per-agent alerts |
| `threats.classified` | → Response Agent | Correlated, scored threats |
| `actions.taken` | Audit | All mitigation actions |

## Running Tests

```bash
pytest tests/ -v
```

## Tech Stack
- **Agent Framework**: LangGraph / custom Kafka consumers
- **Message Bus**: Apache Kafka (KRaft)
- **Storage**: Elasticsearch 8.x + Redis 7
- **Visualization**: Kibana
- **ML**: XGBoost, scikit-learn, PyTorch (LSTM autoencoder)
- **Orchestration**: Docker Compose → Kubernetes (prod)
