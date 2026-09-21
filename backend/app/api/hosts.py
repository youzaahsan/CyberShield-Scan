from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.core.database import get_db
from backend.app.models.host import Host
from backend.app.models.user import User
from backend.app.schemas.scan import HostResponse
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/hosts", tags=["Hosts"])

@router.get("", response_model=List[HostResponse])
def list_hosts(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Host)
    if scan_id:
        query = query.filter(Host.scan_id == scan_id)
    return query.order_by(Host.risk_score.desc()).all()

@router.get("/{host_id}", response_model=HostResponse)
def get_host(host_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    return host
