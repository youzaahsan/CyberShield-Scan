from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from backend.app.models.scan import ScanStatus, ScanProfile

class ScanCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    target: str = Field(..., description="IPv4, IP range, or CIDR (e.g. 192.168.1.1, 10.0.0.1-10.0.0.5, 127.0.0.1/32)")
    profile: ScanProfile = ScanProfile.TOP_100
    custom_ports: Optional[str] = Field(None, description="Comma separated ports e.g. '80,443,8000-8080'")

class ScanResponse(BaseModel):
    id: int
    name: str
    target: str
    profile: ScanProfile
    custom_ports: Optional[str] = None
    status: ScanStatus
    progress_percentage: float
    current_phase: str
    hosts_discovered: int
    hosts_scanned: int
    ports_scanned: int
    services_detected: int
    vulnerabilities_found: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class PortResponse(BaseModel):
    id: int
    port_number: int
    protocol: str
    state: str
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    tls_version: Optional[str] = None
    http_server_header: Optional[str] = None

    class Config:
        from_attributes = True

class HostResponse(BaseModel):
    id: int
    scan_id: int
    ip_address: str
    hostname: Optional[str] = None
    status: str
    os_name: str
    os_confidence: str
    os_evidence: Optional[str] = None
    risk_score: float
    risk_level: str
    discovered_at: datetime
    last_seen: datetime
    ports: List[PortResponse] = []

    class Config:
        from_attributes = True
