from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from backend.app.core.database import get_db
from backend.app.models.host import Port
from backend.app.models.user import User
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/services", tags=["Services"])

@router.get("", response_model=List[Dict[str, Any]])
def list_services(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    services = (
        db.query(
            Port.service_name,
            Port.product,
            func.count(Port.id).label("count")
        )
        .filter(Port.state == "OPEN")
        .group_by(Port.service_name, Port.product)
        .order_by(func.count(Port.id).desc())
        .all()
    )
    return [
        {
            "service_name": s.service_name,
            "product": s.product or "Unknown",
            "count": s.count
        }
        for s in services
    ]
