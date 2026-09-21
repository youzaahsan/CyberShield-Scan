"""
Target and port specification parser for CyberShield Scan.
Supports single IPv4, CIDR notations (e.g. 192.168.1.0/24), IP ranges (e.g. 10.0.0.1-10.0.0.50),
comma-separated lists, hostnames (localhost, domain names), and port ranges (80,443,8000-8080).
"""

import ipaddress
import socket
from typing import List, Set
from backend.app.models.scan import ScanProfile

# Standard curated port lists
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999,
    10000, 32768, 49152, 49153, 49154
]

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162,
    389, 443, 445, 465, 514, 587, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 2375,
    2376, 2379, 3000, 3306, 3389, 5000, 5432, 5672, 5900, 6379, 6443, 8000, 8080,
    8443, 8888, 9000, 9092, 9200, 9300, 11211, 27017, 27018
]

def parse_targets(target_str: str, max_targets: int = 256) -> List[str]:
    """
    Parses a target string which can contain:
    - Single IP (192.168.1.10)
    - CIDR block (192.168.1.0/24 or 192.168.1.0/28)
    - IP Range (192.168.1.1-192.168.1.20)
    - Hostname / Domain (localhost, internal-corp.local)
    - Comma-separated or space-separated list of the above
    
    Restricted to max_targets (default 256) for safety and performance.
    """
    cleaned = target_str.replace(";", ",").replace("\n", ",").replace(" ", ",")
    parts = [p.strip() for p in cleaned.split(",") if p.strip()]
    discovered_ips: List[str] = []
    seen: Set[str] = set()

    for part in parts:
        # Check for IP Range: 192.168.1.5-192.168.1.15
        if "-" in part and not part.startswith("-"):
            range_parts = part.split("-")
            if len(range_parts) == 2:
                start_str, end_str = range_parts[0].strip(), range_parts[1].strip()
                try:
                    # Could be 192.168.1.1 - 192.168.1.10 or 192.168.1.1 - 10
                    start_ip = ipaddress.IPv4Address(start_str)
                    if "." in end_str:
                        end_ip = ipaddress.IPv4Address(end_str)
                    else:
                        octets = start_str.split(".")
                        octets[-1] = end_str
                        end_ip = ipaddress.IPv4Address(".".join(octets))

                    start_int = int(start_ip)
                    end_int = int(end_ip)
                    if start_int <= end_int and (end_int - start_int) <= max_targets:
                        for current_int in range(start_int, end_int + 1):
                            ip_str = str(ipaddress.IPv4Address(current_int))
                            if ip_str not in seen:
                                seen.add(ip_str)
                                discovered_ips.append(ip_str)
                                if len(discovered_ips) >= max_targets:
                                    return discovered_ips
                        continue
                except Exception:
                    pass

        # Check for CIDR: e.g. 192.168.1.0/24
        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                # Cap network expansion
                count = 0
                for host in network.hosts():
                    host_str = str(host)
                    if host_str not in seen:
                        seen.add(host_str)
                        discovered_ips.append(host_str)
                        count += 1
                        if len(discovered_ips) >= max_targets:
                            return discovered_ips
                continue
            except Exception:
                pass

        # Check single IPv4 / IPv6
        try:
            ip_obj = ipaddress.ip_address(part)
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                discovered_ips.append(ip_str)
            continue
        except ValueError:
            pass

        # Resolve hostname / domain
        try:
            resolved_ip = socket.gethostbyname(part)
            if resolved_ip not in seen:
                seen.add(resolved_ip)
                discovered_ips.append(resolved_ip)
        except Exception:
            # Keep the literal string if unresolvable, so scanner handles error gracefully
            if part not in seen:
                seen.add(part)
                discovered_ips.append(part)

        if len(discovered_ips) >= max_targets:
            break

    return discovered_ips[:max_targets]


def parse_ports(profile: ScanProfile, custom_ports: str = None) -> List[int]:
    """
    Returns ordered, unique list of port integers for a given profile and optional custom port definition.
    """
    if profile == ScanProfile.TOP_20:
        return sorted(list(set(TOP_20_PORTS)))
    elif profile == ScanProfile.TOP_100:
        return sorted(list(set(TOP_100_PORTS)))
    elif profile == ScanProfile.COMMON:
        return sorted(list(set(COMMON_PORTS)))
    elif profile == ScanProfile.TOP_1000:
        # Construct top 1000 by taking top 100 + common + well-known ports up to 1024
        ports = set(TOP_100_PORTS) | set(COMMON_PORTS) | set(range(1, 1025))
        return sorted(list(ports))[:1000]
    elif profile == ScanProfile.FULL:
        # Safe upper bound for practical scans in dev/preview: ports 1-10000
        return list(range(1, 10001))
    elif profile == ScanProfile.CUSTOM:
        if not custom_ports:
            return sorted(list(set(TOP_20_PORTS)))
        
        ports: Set[int] = set()
        cleaned = custom_ports.replace(";", ",").replace(" ", ",")
        for token in cleaned.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                parts = token.split("-")
                if len(parts) == 2:
                    try:
                        p_start = max(1, int(parts[0].strip()))
                        p_end = min(65535, int(parts[1].strip()))
                        if p_start <= p_end:
                            for p in range(p_start, min(p_end + 1, p_start + 5000)):
                                ports.add(p)
                    except ValueError:
                        continue
            else:
                try:
                    p = int(token)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    continue
        return sorted(list(ports)) if ports else sorted(list(set(TOP_20_PORTS)))

    return sorted(list(set(TOP_100_PORTS)))
