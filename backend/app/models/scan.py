from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Enum, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum
from backend.app.core.database import Base

class ScanStatus(str, enum.Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class ScanProfile(str, enum.Enum):
    TOP_20 = "Top 20"
    TOP_100 = "Top 100"
    TOP_1000 = "Top 1000"
    COMMON = "Common Ports"
    CUSTOM = "Custom Ports"
    FULL = "Full Range"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False) # IP, CIDR, or comma list
    profile = Column(Enum(ScanProfile), default=ScanProfile.TOP_100, nullable=False)
    custom_ports = Column(String(500), nullable=True) # e.g. "80,443,8080-8090"
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    progress_percentage = Column(Float, default=0.0, nullable=False)
    current_phase = Column(String(100), default="Initialized", nullable=False)
    
    hosts_discovered = Column(Integer, default=0)
    hosts_scanned = Column(Integer, default=0)
    ports_scanned = Column(Integer, default=0)
    services_detected = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
