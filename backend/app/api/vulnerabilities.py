from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.core.database import get_db
from backend.app.models.vulnerability import Vulnerability, VulnStatus, VulnSeverity
from backend.app.models.user import User, UserRole
from backend.app.models.audit import AuditLog
from backend.app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityStatusUpdate
from backend.app.api.deps import get_current_user, RequireRole

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

@router.get("", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    host_id: Optional[int] = None,
    severity: Optional[VulnSeverity] = None,
    status_filter: Optional[VulnStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Vulnerability)
    if host_id:
        query = query.filter(Vulnerability.host_id == host_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status_filter:
        query = query.filter(Vulnerability.status == status_filter)
    return query.order_by(Vulnerability.cvss.desc()).all()

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return vuln

@router.patch("/{vuln_id}/status", response_model=VulnerabilityResponse)
def update_vulnerability_status(
    vuln_id: int,
    update_data: VulnerabilityStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequireRole([UserRole.ADMIN, UserRole.SECURITY_ANALYST]))
):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    
    old_status = vuln.status
    vuln.status = update_data.status
    db.commit()
    db.refresh(vuln)

    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="VULN_STATUS_CHANGE",
        details=f"Finding {vuln.finding_id} status changed from {old_status} to {vuln.status}"
    )
    db.add(audit)
    db.commit()

    return vuln
