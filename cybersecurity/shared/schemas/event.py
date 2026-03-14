"""
Standardized event schema shared across all agents.
Every agent publishes and consumes this format via Kafka.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid


class ThreatEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str                        # anomaly | alert | info | action
    severity: str                          # critical | high | medium | low | info
    confidence: float = Field(ge=0.0, le=1.0)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    mitre_ttp: Optional[str] = None       # e.g. T1498, T1078
    details: Dict[str, Any] = {}
    raw_log: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
