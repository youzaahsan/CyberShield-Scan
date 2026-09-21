"""
Central Scanner Engine Orchestrator for CyberShield Scan.
Manages target parsing, concurrency bounded sweeps, port inspection,
database persistence, risk scoring calculation, and status progression.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional, Dict
from sqlalchemy.orm import Session

from backend.app.core.database import SessionLocal
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.models.scan import Scan, ScanStatus
from backend.app.models.host import Host, Port
from backend.app.models.vulnerability import Vulnerability, CVE, VulnSeverity, VulnConfidence, VulnStatus
from backend.app.scanner.parser import parse_targets, parse_ports
from backend.app.scanner.discovery import discover_hosts
from backend.app.scanner.port_scanner import scan_tcp_port
from backend.app.scanner.banner_grabber import inspect_tls, inspect_http_security
from backend.app.scanner.fingerprint import fingerprint_os_and_device
from backend.app.scanner.vulnerability_engine import assess_vulnerabilities

# Global dictionary to support graceful cancellation of active scans
active_tasks: Dict[int, asyncio.Task] = {}

def calculate_host_risk_score(ports: list, vulns: list) -> tuple[float, str]:
    """
    Computes a mathematical 0-100 risk score based on:
    - Open critical ports (SMB 445, Telnet 23, RDP 3389)
    - Vulnerability CVSS scores and severities
    - Missing HTTP security headers
    """
    score = 0.0
    
    # Port exposure risks
    port_weights = {
        23: 15.0,  # Telnet unencrypted
        445: 20.0, # SMB critical attack vector
        3389: 10.0, # Remote Desktop exposed
        21: 8.0,   # FTP unencrypted
        1433: 10.0, # Database exposed directly
        3306: 8.0,
        5432: 8.0,
        27017: 12.0, # MongoDB often unauthenticated
        6379: 12.0   # Redis often unauthenticated
    }
    
    for p in ports:
        score += port_weights.get(p.port_number, 1.0)

    # Vulnerability scores
    for v in vulns:
        if v.severity == VulnSeverity.CRITICAL:
            score += 35.0
        elif v.severity == VulnSeverity.HIGH:
            score += 20.0
        elif v.severity == VulnSeverity.MEDIUM:
            score += 10.0
        elif v.severity == VulnSeverity.LOW:
            score += 3.0

    score = min(100.0, score)
    
    if score >= 80.0:
        level = "CRITICAL"
    elif score >= 60.0:
        level = "HIGH"
    elif score >= 35.0:
        level = "MEDIUM"
    elif score >= 15.0:
        level = "MODERATE"
    else:
        level = "LOW"

    return round(score, 1), level


async def run_scan_lifecycle(scan_id: int):
    """
    Executes the full scanning lifecycle for scan_id:
    Phase 1: Target Expansion
    Phase 2: Host Discovery Sweep
    Phase 3: Deep Port & Service Inspection
    Phase 4: Vulnerability & Correlation Analysis
    Phase 5: Aggregation & Finalization
    """
    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"[ScanEngine] Scan {scan_id} not found in database.")
            return

        if scan.status == ScanStatus.CANCELLED:
            return

        # Initialize scan
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.current_phase = "Target Resolution"
        scan.progress_percentage = 5.0
        db.commit()

        # 1. Parse target IPs
        targets = parse_targets(scan.target)
        if not targets:
            scan.status = ScanStatus.FAILED
            scan.error_message = "No valid IPv4 or hostname targets found in target specification."
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        # 2. Host Discovery
        scan.current_phase = f"Host Discovery (Checking {len(targets)} targets)"
        scan.progress_percentage = 15.0
        db.commit()

        discovered_hosts = await discover_hosts(
            targets,
            concurrency=settings.DEFAULT_CONCURRENCY_LIMIT,
            timeout=settings.DEFAULT_TIMEOUT_SECONDS
        )

        scan.hosts_discovered = len(discovered_hosts)
        scan.progress_percentage = 25.0
        db.commit()

        if not discovered_hosts:
            scan.current_phase = "No active hosts responding"
            scan.status = ScanStatus.COMPLETED
            scan.progress_percentage = 100.0
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        # 3. Port & Service Inspection
        ports_to_scan = parse_ports(scan.profile, scan.custom_ports)
        total_port_checks = len(discovered_hosts) * len(ports_to_scan)
        ports_checked_count = 0
        total_vulns_found = 0
        total_services_found = 0

        port_semaphore = asyncio.Semaphore(settings.DEFAULT_CONCURRENCY_LIMIT)

        # Iterate hosts and scan
        for host_idx, host_info in enumerate(discovered_hosts):
            ip = host_info["ip"]
            scan.current_phase = f"Scanning Host {ip} ({host_idx+1}/{len(discovered_hosts)})"
            db.commit()

            new_host = Host(
                scan_id=scan.id,
                ip_address=ip,
                hostname=host_info.get("hostname"),
                status="UP" if host_info.get("is_up") else "UNKNOWN",
                os_name="Detecting...",
                os_confidence="Potential"
            )
            db.add(new_host)
            db.commit()
            db.refresh(new_host)

            open_ports_records = []
            banners_collected = []

            async def scan_single_port(port_num: int):
                nonlocal ports_checked_count
                async with port_semaphore:
                    res = await scan_tcp_port(ip, port_num, timeout=settings.DEFAULT_TIMEOUT_SECONDS)
                    ports_checked_count += 1
                    return res

            port_tasks = [scan_single_port(p) for p in ports_to_scan]
            scan_results = await asyncio.gather(*port_tasks, return_exceptions=True)

            for port_res in scan_results:
                if isinstance(port_res, dict) and port_res.get("state") == "OPEN":
                    p_num = port_res["port"]
                    banner = port_res.get("banner")
                    if banner:
                        banners_collected.append(banner)

                    # Inspect TLS and HTTP if applicable
                    tls_ver = port_res.get("tls_version")
                    tls_cip = port_res.get("tls_cipher")
                    if p_num in [443, 8443] or "https" in port_res.get("service", ""):
                        tls_data = await inspect_tls(ip, p_num)
                        if tls_data.get("has_tls"):
                            tls_ver = tls_data.get("tls_version")
                            tls_cip = tls_data.get("tls_cipher")

                    missing_headers_str = None
                    http_header = port_res.get("http_server_header")
                    if p_num in [80, 443, 3000, 8000, 8080, 8443]:
                        http_sec = await inspect_http_security(ip, p_num, use_tls=(p_num in [443, 8443]))
                        if http_sec.get("missing_headers"):
                            missing_headers_str = json.dumps(http_sec.get("missing_headers"))
                        if http_sec.get("http_server_header"):
                            http_header = http_sec.get("http_server_header")

                    port_obj = Port(
                        host_id=new_host.id,
                        port_number=p_num,
                        protocol="TCP",
                        state="OPEN",
                        service_name=port_res.get("service", "unknown"),
                        product=port_res.get("product"),
                        version=port_res.get("version"),
                        banner=banner,
                        tls_version=tls_ver,
                        tls_cipher=tls_cip,
                        http_server_header=http_header,
                        missing_headers=missing_headers_str
                    )
                    db.add(port_obj)
                    open_ports_records.append(port_obj)
                    total_services_found += 1

            db.commit()

            # Update host OS fingerprint based on open ports and banners
            os_data = fingerprint_os_and_device(
                [p.port_number for p in open_ports_records],
                banners_collected
            )
            new_host.os_name = os_data["os_name"]
            new_host.os_confidence = os_data["os_confidence"]
            new_host.os_evidence = os_data["os_evidence"]

            # Evaluate vulnerabilities for this host using enriched CVE and security rule engine
            vulns_for_host = assess_vulnerabilities(db, new_host, open_ports_records)
            for v in vulns_for_host:
                db.add(v)
            db.commit()

            total_vulns_found += len(vulns_for_host)

            # Calculate risk score
            h_score, h_level = calculate_host_risk_score(open_ports_records, vulns_for_host)
            new_host.risk_score = h_score
            new_host.risk_level = h_level
            db.commit()

            # Update progress
            scan.hosts_scanned = host_idx + 1
            scan.ports_scanned = ports_checked_count
            scan.services_detected = total_services_found
            scan.vulnerabilities_found = total_vulns_found
            scan.progress_percentage = min(95.0, 25.0 + (70.0 * (host_idx + 1) / len(discovered_hosts)))
            db.commit()

        # Phase 5: Finalization
        scan.current_phase = "Completed"
        scan.status = ScanStatus.COMPLETED
        scan.progress_percentage = 100.0
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"[ScanEngine] Scan {scan_id} finished successfully.")

    except asyncio.CancelledError:
        logger.warn(f"[ScanEngine] Scan {scan_id} cancelled.")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan and scan.status != ScanStatus.COMPLETED:
            scan.status = ScanStatus.CANCELLED
            scan.current_phase = "Cancelled by user"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as e:
        logger.error(f"[ScanEngine] Scan {scan_id} error: {str(e)}")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.current_phase = f"Failed: {str(e)[:100]}"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        active_tasks.pop(scan_id, None)
        db.close()


def evaluate_host_vulnerabilities(db: Session, host: Host, ports: list) -> list:
    """
    Correlates open ports, detected services, and missing headers against security rules & CVEs.
    """
    vulns = []
    finding_idx = 1

    for p in ports:
        # Check unencrypted telnet
        if p.port_number == 23:
            vulns.append(Vulnerability(
                finding_id=f"VULN-{host.id}-{finding_idx}",
                cve_id="CVE-2020-10188",
                host_id=host.id,
                port_id=p.id,
                service="telnet",
                title="Unencrypted Telnet Service Detected",
                severity=VulnSeverity.HIGH,
                cvss=7.5,
                confidence=VulnConfidence.CONFIRMED,
                description="Telnet transmits authentication credentials and commands in cleartext without encryption.",
                evidence=f"Port 23/TCP open. Banner: {p.banner or 'Telnet daemon responding'}",
                impact="Eavesdropping, credential theft, and unauthorized remote access over the wire.",
                recommendation="Disable telnet daemon immediately and replace with SSHv2 (port 22) with key authentication.",
                status=VulnStatus.OPEN
            ))
            finding_idx += 1

        # Check SMB exposure
        if p.port_number == 445:
            vulns.append(Vulnerability(
                finding_id=f"VULN-{host.id}-{finding_idx}",
                cve_id="CVE-2017-0144",
                host_id=host.id,
                port_id=p.id,
                service="microsoft-ds",
                title="Exposed SMB File Sharing Port (445/TCP)",
                severity=VulnSeverity.HIGH,
                cvss=8.1,
                confidence=VulnConfidence.LIKELY,
                description="Direct SMB service exposure over network boundaries is a high-priority vector for lateral movement and worm propagation.",
                evidence="Port 445/TCP responding to TCP SYN probes.",
                impact="Network infiltration, remote code execution vulnerability, and unauthorized share access.",
                recommendation="Block SMB inbound traffic at firewall boundaries and enforce SMB signing/encryption.",
                status=VulnStatus.OPEN
            ))
            finding_idx += 1

        # Check missing HTTP security headers
        if p.missing_headers:
            try:
                missing_list = json.loads(p.missing_headers)
                if missing_list:
                    vulns.append(Vulnerability(
                        finding_id=f"VULN-{host.id}-{finding_idx}",
                        cve_id="CWE-693",
                        host_id=host.id,
                        port_id=p.id,
                        service=p.service_name,
                        title=f"Missing Security Headers on Port {p.port_number}",
                        severity=VulnSeverity.LOW,
                        cvss=3.7,
                        confidence=VulnConfidence.CONFIRMED,
                        description=f"The web service lacks important defensive HTTP headers: {', '.join(missing_list)}.",
                        evidence=f"HTTP HEAD inspection missing: {', '.join(missing_list)}",
                        impact="Elevates risk of Clickjacking (X-Frame-Options), MIME sniffing, and MITM attacks.",
                        recommendation=f"Configure web server to emit standard defensive headers: {', '.join(missing_list)}.",
                        status=VulnStatus.OPEN
                    ))
                    finding_idx += 1
            except Exception:
                pass

        # Check database exposed
        if p.port_number in [3306, 5432, 27017, 6379]:
            vulns.append(Vulnerability(
                finding_id=f"VULN-{host.id}-{finding_idx}",
                cve_id="CWE-284",
                host_id=host.id,
                port_id=p.id,
                service=p.service_name,
                title=f"Directly Exposed Database Port ({p.port_number}/TCP)",
                severity=VulnSeverity.MEDIUM,
                cvss=6.5,
                confidence=VulnConfidence.CONFIRMED,
                description=f"Database port {p.port_number} is exposed directly to the network without an internal proxy or VPN restriction.",
                evidence=f"Port {p.port_number} open with banner: {p.banner or 'Active database socket'}",
                impact="Brute-force password guessing, credential stuffing, and data exfiltration.",
                recommendation="Restrict database binding to 127.0.0.1 or place behind private VPC subnets with strict security groups.",
                status=VulnStatus.OPEN
            ))
            finding_idx += 1

    return vulns


def start_scan_job(scan_id: int):
    """
    Launches run_scan_lifecycle asynchronously as a background task.
    """
    loop = asyncio.get_event_loop()
    task = loop.create_task(run_scan_lifecycle(scan_id))
    active_tasks[scan_id] = task
    return task

def cancel_scan_job(scan_id: int) -> bool:
    """
    Cancels active scan task gracefully.
    """
    task = active_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False
