from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.core.database import get_db
from backend.app.models.host import Port
from backend.app.models.user import User
from backend.app.schemas.scan import PortResponse
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/ports", tags=["Ports"])

@router.get("", response_model=List[PortResponse])
def list_ports(
    host_id: Optional[int] = None,
    state: Optional[str] = "OPEN",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Port)
    if host_id:
        query = query.filter(Port.host_id == host_id)
    if state:
        query = query.filter(Port.state == state)
    return query.order_by(Port.port_number.asc()).all()

@router.get("/{port_id}", response_model=PortResponse)
def get_port(port_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    port = db.query(Port).filter(Port.id == port_id).first()
    if not port:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Port not found")
    return port
