from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from datetime import datetime, timezone
import enum
from backend.app.core.database import Base

class UserRole(str, enum.Enum):
    ADMIN = "Admin"
    SECURITY_ANALYST = "Security Analyst"
    VIEWER = "Viewer"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = Column(DateTime, nullable=True)
