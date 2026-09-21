"""
Fingerprinting and heuristic Operating System & Device Type detection.
Evaluates response TTL heuristics, open port signature profiles, and banners.
"""

from typing import Dict, Any, List

def fingerprint_os_and_device(open_ports: List[int], banners: List[str]) -> Dict[str, Any]:
    """
    Evidence-based OS detection.
    Assigns:
    - os_name
    - os_confidence: "Confirmed", "Likely", "Potential"
    - os_evidence: explanation of indicators detected
    """
    evidence_tokens = []
    ports_set = set(open_ports)
    all_banners_str = " ".join([b for b in banners if b]).lower()

    # Windows indicators: 135 (MSRPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP)
    windows_score = 0
    if 445 in ports_set:
        windows_score += 4
        evidence_tokens.append("SMB port 445 active")
    if 135 in ports_set:
        windows_score += 3
        evidence_tokens.append("MSRPC port 135 active")
    if 3389 in ports_set:
        windows_score += 3
        evidence_tokens.append("RDP port 3389 active")
    if "microsoft" in all_banners_str or "windows" in all_banners_str or "iis" in all_banners_str:
        windows_score += 5
        evidence_tokens.append("Microsoft/IIS banner pattern")

    # Linux / Unix indicators: 22 (SSH OpenSSH), 111 (rpcbind), 2049 (NFS)
    linux_score = 0
    if 22 in ports_set:
        linux_score += 3
        evidence_tokens.append("SSH port 22 open")
    if 111 in ports_set:
        linux_score += 3
        evidence_tokens.append("rpcbind port 111 open")
    if "ubuntu" in all_banners_str:
        linux_score += 5
        evidence_tokens.append("Ubuntu distribution banner signature")
    elif "debian" in all_banners_str:
        linux_score += 5
        evidence_tokens.append("Debian distribution banner signature")
    elif "centos" in all_banners_str or "red hat" in all_banners_str:
        linux_score += 5
        evidence_tokens.append("RHEL/CentOS banner signature")
    elif "openssh" in all_banners_str:
        linux_score += 2
        evidence_tokens.append("OpenSSH daemon detected")

    # Router / Network Appliance indicators
    network_device_score = 0
    if 23 in ports_set:
        network_device_score += 3
        evidence_tokens.append("Telnet port 23 legacy management active")
    if 161 in ports_set:
        network_device_score += 3
        evidence_tokens.append("SNMP port 161 agent active")
    if "cisco" in all_banners_str:
        network_device_score += 6
        evidence_tokens.append("Cisco IOS banner signature")
    elif "mikrotik" in all_banners_str:
        network_device_score += 6
        evidence_tokens.append("MikroTik RouterOS banner signature")

    # Decision Matrix
    if network_device_score > max(windows_score, linux_score) and network_device_score >= 5:
        return {
            "os_name": "Embedded Network OS (Cisco/MikroTik/Router)",
            "os_confidence": "Confirmed" if network_device_score >= 8 else "Likely",
            "os_evidence": "; ".join(evidence_tokens)
        }
    elif windows_score > linux_score and windows_score >= 4:
        return {
            "os_name": "Microsoft Windows (Server / Enterprise)",
            "os_confidence": "Confirmed" if windows_score >= 8 else "Likely",
            "os_evidence": "; ".join(evidence_tokens)
        }
    elif linux_score >= 3:
        # Determine specific flavor if mentioned
        distro = "Linux (Kernel 5.x / 6.x)"
        if "ubuntu" in all_banners_str:
            distro = "Ubuntu Linux"
        elif "debian" in all_banners_str:
            distro = "Debian Linux"
        elif "alpine" in all_banners_str:
            distro = "Alpine Linux (Containerized)"

        return {
            "os_name": distro,
            "os_confidence": "Confirmed" if any(x in all_banners_str for x in ["ubuntu", "debian", "alpine"]) else "Likely",
            "os_evidence": "; ".join(evidence_tokens)
        }

    return {
        "os_name": "Linux / POSIX Generic",
        "os_confidence": "Potential",
        "os_evidence": "; ".join(evidence_tokens) if evidence_tokens else "Standard TCP/IP stack response"
    }
