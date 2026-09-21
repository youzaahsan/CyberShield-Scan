from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.core.database import Base

class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True) # IPv4 or IPv6
    hostname = Column(String(255), nullable=True)
    mac_address = Column(String(50), nullable=True)
    status = Column(String(20), default="UP", nullable=False) # UP, DOWN
    
    # OS Detection evidence-based attributes
    os_name = Column(String(100), default="Unknown", nullable=False)
    os_confidence = Column(String(20), default="Potential", nullable=False) # Confirmed, Likely, Potential
    os_evidence = Column(Text, nullable=True)
    
    # Aggregated metrics
    risk_score = Column(Float, default=0.0, nullable=False) # 0 to 100
    risk_level = Column(String(20), default="LOW", nullable=False) # LOW, MODERATE, MEDIUM, HIGH, CRITICAL
    
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scan = relationship("Scan", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")

class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port_number = Column(Integer, nullable=False, index=True)
    protocol = Column(String(10), default="TCP", nullable=False) # TCP, UDP
    state = Column(String(20), default="OPEN", nullable=False) # OPEN, CLOSED, FILTERED
    
    service_name = Column(String(100), default="Unknown", nullable=False)
    product = Column(String(150), default="Unknown", nullable=True)
    version = Column(String(100), default="Unknown", nullable=True)
    banner = Column(Text, nullable=True)
    
    # Web & TLS security inspection fields
    tls_version = Column(String(50), nullable=True)
    tls_cipher = Column(String(100), nullable=True)
    http_server_header = Column(String(255), nullable=True)
    missing_headers = Column(Text, nullable=True) # JSON list string of missing security headers

    host = relationship("Host", back_populates="ports")
    vulnerabilities = relationship("Vulnerability", back_populates="port")
