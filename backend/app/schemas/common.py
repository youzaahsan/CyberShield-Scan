from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class AlertResponse(BaseModel):
    id: int
    title: str
    severity: str
    message: str
    channel: str
    is_read: bool
    delivered: bool
    created_at: datetime

    class Config:
        from_attributes = True

class ScheduleCreate(BaseModel):
    name: str
    target: str
    frequency: str = "DAILY" # ONCE, DAILY, WEEKLY, CUSTOM
    is_enabled: bool = True

class ScheduleResponse(BaseModel):
    id: int
    name: str
    target: str
    frequency: str
    is_enabled: bool
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True

class TopologyNode(BaseModel):
    id: str
    label: str
    type: str # gateway, host, service
    ip: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    open_ports_count: int = 0
    os: str = "Unknown"

class TopologyEdge(BaseModel):
    source: str
    target: str
    relationship: str
    inferred: bool = False

class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]

class RiskAssessmentResponse(BaseModel):
    overall_score: float
    overall_level: str
    high_risk_hosts_count: int
    medium_risk_hosts_count: int
    low_risk_hosts_count: int
    factors: List[Dict[str, Any]]
    recommendations_priority: List[Dict[str, Any]]
