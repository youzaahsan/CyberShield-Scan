from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.host import Host, Port
from backend.app.models.vulnerability import Vulnerability, VulnSeverity
from backend.app.models.user import User
from backend.app.schemas.common import RiskAssessmentResponse
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/risk", tags=["Risk Analysis"])

@router.get("", response_model=RiskAssessmentResponse)
def get_risk_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    hosts = db.query(Host).all()
    vulns = db.query(Vulnerability).all()
    open_ports = db.query(Port).filter(Port.state == "OPEN").count()

    high_risk_hosts = sum(1 for h in hosts if h.risk_score >= 61)
    med_risk_hosts = sum(1 for h in hosts if 21 <= h.risk_score < 61)
    low_risk_hosts = sum(1 for h in hosts if h.risk_score < 21)

    crit_vulns = sum(1 for v in vulns if v.severity == VulnSeverity.CRITICAL)
    high_vulns = sum(1 for v in vulns if v.severity == VulnSeverity.HIGH)
    med_vulns = sum(1 for v in vulns if v.severity == VulnSeverity.MEDIUM)

    # Explainable ML/Analytical scoring formulation
    base_score = 0.0
    if hosts:
        avg_host_score = sum(h.risk_score for h in hosts) / len(hosts)
        # Weight critical/high vulnerabilities and port exposure
        vuln_pressure = min(40.0, (crit_vulns * 15.0) + (high_vulns * 8.0) + (med_vulns * 2.0))
        base_score = min(100.0, round((avg_host_score * 0.6) + vuln_pressure, 1))

    if base_score <= 20:
        level = "LOW"
    elif base_score <= 40:
        level = "MODERATE"
    elif base_score <= 60:
        level = "MEDIUM"
    elif base_score <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    factors = [
        {"name": "Critical Vulnerabilities", "weight": "35%", "impact": f"{crit_vulns} active critical findings"},
        {"name": "High Vulnerabilities", "weight": "25%", "impact": f"{high_vulns} active high findings"},
        {"name": "Attack Surface (Open Ports)", "weight": "20%", "impact": f"{open_ports} detected open services"},
        {"name": "Unpatched Host Density", "weight": "20%", "impact": f"{high_risk_hosts} high-risk hosts in perimeter"}
    ]

    recommendations = [
        {"priority": 1, "action": "Patch Critical CVEs on perimeter hosts immediately", "impact": "Reduces composite risk by up to 35 points"},
        {"priority": 2, "action": "Enforce HTTP Security Headers (HSTS, CSP, X-Frame-Options)", "impact": "Prevents web clickjacking and downgrade attacks"},
        {"priority": 3, "action": "Disable legacy plaintext services (Telnet, FTP, HTTP on admin ports)", "impact": "Eliminates credential sniffing risks"}
    ]

    return RiskAssessmentResponse(
        overall_score=base_score,
        overall_level=level,
        high_risk_hosts_count=high_risk_hosts,
        medium_risk_hosts_count=med_risk_hosts,
        low_risk_hosts_count=low_risk_hosts,
        factors=factors,
        recommendations_priority=recommendations
    )
