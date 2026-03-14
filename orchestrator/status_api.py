"""
Status & Monitoring API for the Orchestrator.
Provides real-time visibility into threat detection and response actions.

Endpoints:
  GET /              — Health check
  GET /threats       — Recent threats from Elasticsearch
  GET /blocked_ips   — Currently blocked IPs from Redis
  GET /actions       — Recent response actions
  GET /stats         — Agent health & event counts
  POST /simulate     — Trigger demo attack sequence (testing only)

Run:
  uvicorn orchestrator.status_api:app --host 0.0.0.0 --port 8002
"""

import json
import logging
import os
from datetime import datetime, timedelta

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger as loguru_logger

from orchestrator.orchestrator import OrchestratorAgent
from orchestrator.response_dispatcher import ResponseDispatcher
from shared.utils.es_client import get_es_client
from shared.utils.redis_client import get_redis

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="CyberDefense Orchestrator API",
    description="Real-time threat detection & response monitoring",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global clients
orch = None
dispatcher = None
es = None
redis = None


@app.on_event("startup")
async def startup():
    """Initialize clients on app start."""
    global orch, dispatcher, es, redis
    loguru_logger.info("[StatusAPI] Initializing...")
    orch = OrchestratorAgent()
    dispatcher = ResponseDispatcher()
    es = get_es_client()
    redis = get_redis()
    loguru_logger.info("[StatusAPI] Ready")


@app.get("/", tags=["Health"])
def health():
    """
    Health check endpoint.
    
    Returns:
        JSON with status and component health
    """
    return {
        "status": "healthy",
        "service": "CyberDefense Orchestrator",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "orchestrator": "running",
            "dispatcher": "running",
            "elasticsearch": "connected" if es else "disconnected",
            "redis": "connected" if redis else "disconnected",
        },
    }


@app.get("/threats", tags=["Threats"])
def get_threats(limit: int = 50, severity: str = None):
    """
    Fetch recent classified threats from Elasticsearch.
    
    Args:
        limit: Maximum number of threats to return (default 50)
        severity: Filter by severity (critical, high, medium, low)
    
    Returns:
        List of threat events with metadata
    """
    if not es:
        return {"error": "Elasticsearch not connected", "threats": []}

    try:
        query = {"size": limit, "sort": [{"timestamp": {"order": "desc"}}]}

        if severity:
            query["query"] = {"term": {"severity": severity.lower()}}

        result = es.search(index="cyberdefense-threats", body=query)
        threats = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]

        return {
            "count": len(threats),
            "total": result.get("hits", {}).get("total", {}).get("value", 0),
            "threats": threats,
        }
    except Exception as e:
        loguru_logger.error(f"[StatusAPI] Threat query failed: {e}")
        return {"error": str(e), "threats": []}


@app.get("/blocked_ips", tags=["Response"])
def get_blocked_ips():
    """
    Get list of currently blocked IP addresses.
    
    Returns:
        List of blocked IPs with remaining TTL
    """
    try:
        blocked = dispatcher.get_blocked_ips()
        return {
            "count": len(blocked),
            "blocked_ips": blocked,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        loguru_logger.error(f"[StatusAPI] Blocked IPs query failed: {e}")
        return {"error": str(e), "blocked_ips": []}


@app.get("/actions", tags=["Response"])
def get_recent_actions(limit: int = 100):
    """
    Get recent response actions (blocks, isolations, alerts).
    
    Args:
        limit: Maximum number of actions to return
    
    Returns:
        List of action records with timestamps
    """
    try:
        actions = dispatcher.get_action_history(limit=limit)
        return {
            "count": len(actions),
            "actions": actions,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        loguru_logger.error(f"[StatusAPI] Action history query failed: {e}")
        return {"error": str(e), "actions": []}


@app.get("/stats", tags=["Status"])
def get_agent_stats():
    """
    Get detection agent health and event statistics.
    
    Returns:
        Per-agent event counts and health status
    """
    if not es:
        return {"alert": "Elasticsearch not connected", "agents": {}}

    try:
        agents_status = {
            "network-monitor": {"events": 0, "status": "unknown"},
            "log-analyzer": {"events": 0, "status": "unknown"},
            "ueba": {"events": 0, "status": "unknown"},
            "vuln-scanner": {"events": 0, "status": "unknown"},
        }

        # Query event counts per agent from the last hour
        for agent_id in agents_status.keys():
            result = es.count(
                index="cyberdefense-alerts",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"agent_id": agent_id}},
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": (
                                                datetime.utcnow()
                                                - timedelta(hours=1)
                                            ).isoformat()
                                        }
                                    }
                                },
                            ]
                        }
                    }
                },
            )
            agents_status[agent_id]["events"] = result.get("count", 0)
            agents_status[agent_id]["status"] = "active" if result.get("count", 0) > 0 else "idle"

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "agents": agents_status,
        }
    except Exception as e:
        loguru_logger.error(f"[StatusAPI] Stats query failed: {e}")
        return {"error": str(e), "agents": {}}


@app.post("/simulate", tags=["Testing"])
def simulate_attack_sequence():
    """
    Trigger a demo attack sequence (network + log + behavior).
    
    **WARNING: Testing only. Simulates events without real attacks.**
    
    Returns:
        Summary of simulated events
    """
    try:
        events = {
            "network": [
                {
                    "agent_id": "network-monitor",
                    "threat_type": "port_scan",
                    "source_ip": "192.168.1.200",
                    "severity": "CRITICAL",
                    "description": "Port scan simulation",
                },
                {
                    "agent_id": "network-monitor",
                    "threat_type": "syn_flood",
                    "source_ip": "203.0.113.5",
                    "severity": "HIGH",
                    "description": "SYN flood simulation",
                },
            ],
            "logs": [
                {
                    "agent_id": "log-analyzer",
                    "threat_type": "brute_force_ssh",
                    "source_ip": "192.168.1.200",
                    "severity": "HIGH",
                    "description": "SSH brute force simulation",
                },
                {
                    "agent_id": "log-analyzer",
                    "threat_type": "sql_injection",
                    "source_ip": "10.10.10.50",
                    "severity": "CRITICAL",
                    "description": "SQL injection simulation",
                },
            ],
            "behavior": [
                {
                    "agent_id": "ueba",
                    "threat_type": "anomaly",
                    "user": "admin",
                    "severity": "MEDIUM",
                    "description": "User behavior anomaly simulation",
                },
            ],
        }

        # In a real scenario, these would be published to Kafka
        loguru_logger.info("[StatusAPI] Simulated attack sequence:")
        for category, alerts in events.items():
            loguru_logger.info(f"  {category}: {len(alerts)} alerts")

        return {
            "status": "simulated",
            "alerts": sum(len(v) for v in events.values()),
            "timestamp": datetime.utcnow().isoformat(),
            "events": events,
        }

    except Exception as e:
        loguru_logger.error(f"[StatusAPI] Simulation failed: {e}")
        return {"error": str(e), "alerts": 0}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("orchestrator.status_api:app", host="0.0.0.0", port=8002, reload=False)
