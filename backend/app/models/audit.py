from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from datetime import datetime, timezone
from backend.app.core.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False, index=True) # e.g. LOGIN, SCAN_START, SCAN_CANCEL, VULN_STATUS_CHANGE
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    message = Column(Text, nullable=False)
    channel = Column(String(50), default="SYSTEM", nullable=False) # EMAIL, TELEGRAM, SYSTEM
    is_read = Column(Boolean, default=False, nullable=False)
    delivered = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    frequency = Column(String(50), default="DAILY", nullable=False) # ONCE, DAILY, WEEKLY, CUSTOM
    is_enabled = Column(Boolean, default=True, nullable=False)
    next_run = Column(DateTime, nullable=True)
    last_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
