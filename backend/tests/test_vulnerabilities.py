import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.database import Base
from backend.app.models.scan import Scan, ScanStatus, ScanProfile
from backend.app.models.host import Host, Port
from backend.app.models.vulnerability import Vulnerability, VulnSeverity, VulnStatus
from backend.app.scanner.vulnerability_engine import assess_vulnerabilities
from backend.app.scanner.engine import calculate_host_risk_score

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

def test_vulnerability_assessment_telnet_and_headers(db):
    scan = Scan(name="Audit Scan", target="192.168.1.100", profile=ScanProfile.TOP_20)
    db.add(scan)
    db.commit()

    host = Host(scan_id=scan.id, ip_address="192.168.1.100", status="UP")
    db.add(host)
    db.commit()

    port23 = Port(
        host_id=host.id,
        port_number=23,
        service_name="telnet",
        banner="Linux telnetd version 0.17",
        state="OPEN"
    )
    port80 = Port(
        host_id=host.id,
        port_number=80,
        service_name="http",
        product="nginx",
        version="1.18.0",
        missing_headers='["Content-Security-Policy", "X-Frame-Options"]',
        state="OPEN"
    )
    db.add_all([port23, port80])
    db.commit()

    vulns = assess_vulnerabilities(db, host, [port23, port80])
    assert len(vulns) >= 2
    
    # Verify telnet finding
    telnet_finding = next((v for v in vulns if "Telnet" in v.title), None)
    assert telnet_finding is not None
    assert telnet_finding.severity == VulnSeverity.HIGH
    assert telnet_finding.cve_id == "CWE-319"

    # Verify HTTP security header finding
    header_finding = next((v for v in vulns if "Security Headers Missing" in v.title), None)
    assert header_finding is not None
    assert header_finding.severity == VulnSeverity.LOW

def test_vulnerability_assessment_log4j_and_smb(db):
    scan = Scan(name="Vuln Scan", target="192.168.1.50", profile=ScanProfile.COMMON)
    db.add(scan)
    db.commit()

    host = Host(scan_id=scan.id, ip_address="192.168.1.50", status="UP")
    db.add(host)
    db.commit()

    port445 = Port(
        host_id=host.id,
        port_number=445,
        service_name="microsoft-ds",
        product="Windows Server SMB",
        state="OPEN"
    )
    port8080 = Port(
        host_id=host.id,
        port_number=8080,
        service_name="http-proxy",
        product="Elasticsearch Log4j",
        banner="Elasticsearch 7.10 (log4j-core-2.11.1)",
        state="OPEN"
    )
    db.add_all([port445, port8080])
    db.commit()

    vulns = assess_vulnerabilities(db, host, [port445, port8080])
    
    # Check EternalBlue or Zerologon detection on 445
    smb_vuln = next((v for v in vulns if v.port_id == port445.id), None)
    assert smb_vuln is not None
    assert smb_vuln.severity == VulnSeverity.CRITICAL

    # Check Log4j CVE-2021-44228
    log4j_vuln = next((v for v in vulns if v.cve_id == "CVE-2021-44228"), None)
    assert log4j_vuln is not None
    assert log4j_vuln.cvss == 10.0

def test_risk_score_calculation():
    # Construct mock port and vuln objects
    class MockPort:
        def __init__(self, num): self.port_number = num
    class MockVuln:
        def __init__(self, sev): self.severity = sev

    ports = [MockPort(80), MockPort(445)]
    vulns = [MockVuln(VulnSeverity.CRITICAL), MockVuln(VulnSeverity.HIGH)]

    score, level = calculate_host_risk_score(ports, vulns)
    assert score >= 70.0
    assert level in ["HIGH", "CRITICAL"]
