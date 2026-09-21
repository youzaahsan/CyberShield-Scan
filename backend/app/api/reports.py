from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import json
from backend.app.core.database import get_db
from backend.app.models.scan import Scan
from backend.app.models.host import Host
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.user import User
from backend.app.models.audit import AuditLog
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/summary/{scan_id}")
def get_report_summary(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        
    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    vulns = db.query(Vulnerability).join(Host).filter(Host.scan_id == scan_id).all()
    
    crit = sum(1 for v in vulns if v.severity == "CRITICAL")
    high = sum(1 for v in vulns if v.severity == "HIGH")
    med = sum(1 for v in vulns if v.severity == "MEDIUM")
    low = sum(1 for v in vulns if v.severity == "LOW")

    return {
        "report_id": f"REP-SCAN-{scan.id}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "profile": scan.profile,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at
        },
        "executive_summary": {
            "total_hosts": len(hosts),
            "total_vulnerabilities": len(vulns),
            "severity_breakdown": {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low
            },
            "overall_posture": "Critical Attention Required" if (crit > 0 or high > 2) else "Moderate Risk"
        },
        "findings": [
            {
                "finding_id": v.finding_id,
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity,
                "cvss": v.cvss,
                "confidence": v.confidence,
                "host_ip": v.host.ip_address if v.host else "Unknown",
                "service": v.service,
                "recommendation": v.recommendation
            }
            for v in vulns
        ]
    }

@router.post("/generate/{scan_id}")
def generate_report(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        
    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="REPORT_GENERATED",
        details=f"Generated executive security report for Scan #{scan.id}"
    )
    db.add(audit)
    db.commit()

    return {
        "status": "Generated",
        "report_id": f"REP-SCAN-{scan.id}",
        "download_url": f"/api/reports/download/{scan.id}?format=json"
    }
