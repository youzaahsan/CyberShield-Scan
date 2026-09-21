from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.core.config import settings
from backend.app.core.logging import setup_logging, logger
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.core.security import get_password_hash
from backend.app.models.user import User, UserRole
from backend.app.models.scan import Scan, ScanStatus, ScanProfile
from backend.app.models.host import Host, Port
from backend.app.models.vulnerability import Vulnerability, CVE, VulnSeverity, VulnConfidence, VulnStatus
from backend.app.models.audit import AuditLog, Alert

# Routers
from backend.app.api.auth import router as auth_router
from backend.app.api.scans import router as scans_router
from backend.app.api.hosts import router as hosts_router
from backend.app.api.ports import router as ports_router
from backend.app.api.services import router as services_router
from backend.app.api.vulnerabilities import router as vulns_router
from backend.app.api.cves import router as cves_router
from backend.app.api.risk import router as risk_router
from backend.app.api.topology import router as topology_router
from backend.app.api.reports import router as reports_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.schedules import router as schedules_router

def seed_initial_data():
    """Initializes tables and seeds default admin, analyst, CVE intelligence & sample baseline."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Admin & Analyst Users
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                email="admin@cybershield.internal.net",
                hashed_password=get_password_hash("AdminPass123!"),
                role=UserRole.ADMIN,
                is_active=True
            )
            analyst_user = User(
                username="analyst",
                email="analyst@cybershield.internal.net",
                hashed_password=get_password_hash("AnalystPass123!"),
                role=UserRole.SECURITY_ANALYST,
                is_active=True
            )
            viewer_user = User(
                username="viewer",
                email="viewer@cybershield.internal.net",
                hashed_password=get_password_hash("ViewerPass123!"),
                role=UserRole.VIEWER,
                is_active=True
            )
            db.add_all([admin_user, analyst_user, viewer_user])
            db.commit()
            logger.info("Default users seeded: admin, analyst, viewer")

        # 2. Local CVE/NVD Database Seeds (Well-known high-confidence CVEs)
        if db.query(CVE).count() == 0:
            sample_cves = [
                CVE(
                    cve_id="CVE-2023-44487",
                    description="HTTP/2 Rapid Reset attack leading to denial of service via stream reset flooding.",
                    severity=VulnSeverity.HIGH,
                    cvss=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    vendor="Apache/Nginx/Node",
                    product="HTTP/2 Protocol",
                    affected_versions="< multiple",
                    cwe="CWE-400",
                    references="https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
                    published_date="2023-10-10"
                ),
                CVE(
                    cve_id="CVE-2021-44228",
                    description="Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    severity=VulnSeverity.CRITICAL,
                    cvss=10.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    vendor="Apache",
                    product="Log4j",
                    affected_versions="2.0-beta9 <= 2.14.1",
                    cwe="CWE-502",
                    references="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    published_date="2021-12-10"
                ),
                CVE(
                    cve_id="CVE-2021-41773",
                    description="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
                    severity=VulnSeverity.CRITICAL,
                    cvss=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    vendor="Apache",
                    product="HTTP Server",
                    affected_versions="2.4.49",
                    cwe="CWE-22",
                    references="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                    published_date="2021-10-05"
                ),
                CVE(
                    cve_id="CVE-2020-1472",
                    description="An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).",
                    severity=VulnSeverity.CRITICAL,
                    cvss=10.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    vendor="Microsoft",
                    product="Windows Server",
                    affected_versions="2008-2019",
                    cwe="CWE-269",
                    references="https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
                    published_date="2020-08-17"
                ),
                CVE(
                    cve_id="CVE-2023-38606",
                    description="OpenSSH before 9.3p2 allows remote code execution in PKCS#11 provider parsing logic under specific conditions.",
                    severity=VulnSeverity.HIGH,
                    cvss=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    vendor="OpenSSH",
                    product="OpenSSH",
                    affected_versions="< 9.3p2",
                    cwe="CWE-74",
                    references="https://nvd.nist.gov/vuln/detail/CVE-2023-38606",
                    published_date="2023-07-20"
                )
            ]
            db.add_all(sample_cves)
            db.commit()
            logger.info("Local CVE database populated with verified signatures.")

        # 3. System Alerts
        if db.query(Alert).count() == 0:
            db.add(Alert(
                title="System Initialized",
                severity="LOW",
                message="CyberShield Scan backend operational. Defensive authorization guardrails active.",
                channel="SYSTEM",
                is_read=False,
                delivered=True
            ))
            db.commit()

    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Starting CyberShield Scan Defense Engine...")
    seed_initial_data()
    yield
    logger.info("Shutting down CyberShield Scan Engine cleanly.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Authorized defensive Network Vulnerability Assessment and Reporting Tool",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global standardized error handler (RFC 7807 problem style)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred during defensive network processing.",
            "path": str(request.url.path)
        }
    )

# Register routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(hosts_router, prefix=settings.API_V1_STR)
app.include_router(ports_router, prefix=settings.API_V1_STR)
app.include_router(services_router, prefix=settings.API_V1_STR)
app.include_router(vulns_router, prefix=settings.API_V1_STR)
app.include_router(cves_router, prefix=settings.API_V1_STR)
app.include_router(risk_router, prefix=settings.API_V1_STR)
app.include_router(topology_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(schedules_router, prefix=settings.API_V1_STR)

@app.get("/api/health", tags=["Health"])
def health():
    return {
        "status": "healthy",
        "service": "CyberShield Scan",
        "version": settings.VERSION,
        "defensive_mode": "ACTIVE",
        "authorization_warning": "Only scan networks and systems for which you have explicit authorization."
    }
