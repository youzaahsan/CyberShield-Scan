from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.core.database import get_db
from backend.app.models.vulnerability import CVE
from backend.app.models.user import User
from backend.app.schemas.vulnerability import CVEResponse
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/cves", tags=["CVE Intelligence"])

@router.get("", response_model=List[CVEResponse])
def search_cves(
    query: Optional[str] = Query(None, description="Search CVE ID, vendor, product, or description"),
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    q = db.query(CVE)
    if query:
        search_pattern = f"%{query}%"
        q = q.filter(
            (CVE.cve_id.ilike(search_pattern)) |
            (CVE.product.ilike(search_pattern)) |
            (CVE.vendor.ilike(search_pattern)) |
            (CVE.description.ilike(search_pattern))
        )
    if vendor:
        q = q.filter(CVE.vendor.ilike(f"%{vendor}%"))
    if product:
        q = q.filter(CVE.product.ilike(f"%{product}%"))
        
    return q.order_by(CVE.cvss.desc()).limit(limit).all()

@router.get("/{cve_id}", response_model=CVEResponse)
def get_cve(cve_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    if not cve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"CVE {cve_id} not found")
    return cve
