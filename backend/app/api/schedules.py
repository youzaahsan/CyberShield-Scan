from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone, timedelta
from backend.app.core.database import get_db
from backend.app.models.audit import ScanSchedule
from backend.app.models.user import User, UserRole
from backend.app.schemas.common import ScheduleCreate, ScheduleResponse
from backend.app.api.deps import get_current_user, RequireRole

router = APIRouter(prefix="/schedules", tags=["Schedules"])

@router.get("", response_model=List[ScheduleResponse])
def list_schedules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(ScanSchedule).order_by(ScanSchedule.created_at.desc()).all()

@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
def create_schedule(
    sched_in: ScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequireRole([UserRole.ADMIN, UserRole.SECURITY_ANALYST]))
):
    next_time = datetime.now(timezone.utc) + timedelta(days=1 if sched_in.frequency == "DAILY" else 7)
    schedule = ScanSchedule(
        name=sched_in.name,
        target=sched_in.target,
        frequency=sched_in.frequency,
        is_enabled=sched_in.is_enabled,
        next_run=next_time
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule

@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequireRole([UserRole.ADMIN]))
):
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    db.delete(schedule)
    db.commit()
    return None
