from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
import asyncio
from backend.app.core.database import get_db
from backend.app.models.scan import Scan, ScanStatus
from backend.app.models.user import User, UserRole
from backend.app.models.audit import AuditLog
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.api.deps import get_current_user, RequireRole
from backend.app.scanner.engine import run_scan_lifecycle, cancel_scan_job

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Scan).order_by(Scan.created_at.desc()).all()

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequireRole([UserRole.ADMIN, UserRole.SECURITY_ANALYST]))
):
    new_scan = Scan(
        name=scan_in.name,
        target=scan_in.target,
        profile=scan_in.profile,
        custom_ports=scan_in.custom_ports,
        status=ScanStatus.PENDING,
        created_by_id=current_user.id,
        current_phase="Queued"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="SCAN_CREATED",
        details=f"Scan #{new_scan.id} target={new_scan.target} profile={new_scan.profile}"
    )
    db.add(audit)
    db.commit()

    # Trigger async scan in background
    background_tasks.add_task(run_scan_lifecycle, new_scan.id)

    return new_scan

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan

@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequireRole([UserRole.ADMIN, UserRole.SECURITY_ANALYST]))
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status in [ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel scan in {scan.status} state")
    
    # Cancel running task if active
    cancel_scan_job(scan_id)

    scan.status = ScanStatus.CANCELLED
    scan.current_phase = "Cancelled by user"
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)

    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="SCAN_CANCELLED",
        details=f"Scan #{scan.id} cancelled"
    )
    db.add(audit)
    db.commit()

    return scan
