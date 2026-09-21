"""
Fast host discovery module for CyberShield Scan.
Performs ICMP / TCP SYN-connect sweeps across candidate IP targets to verify live hosts.
"""

import asyncio
import socket
from typing import List, Dict, Any, Optional

async def is_host_alive(ip: str, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Checks if a target host is active by probing standard ubiquitous ports (80, 443, 22, 135, 445).
    If any connect succeeds or returns connection refused (RST), the host is alive.
    Also queries reverse DNS PTR for hostname resolution.
    """
    probe_ports = [80, 443, 22, 135, 445, 8000, 3000]
    is_up = False
    responding_port = None

    # Probe ports concurrently
    async def probe_port(port: int) -> bool:
        nonlocal is_up, responding_port
        if is_up:
            return True
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            is_up = True
            responding_port = port
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, socket.error) as e:
            # Connection refused means host network stack is active!
            if isinstance(e, ConnectionRefusedError) or getattr(e, 'errno', None) in (111, 10061):
                is_up = True
                responding_port = port
                return True
            return False
        except (asyncio.TimeoutError, OSError):
            return False

    tasks = [probe_port(p) for p in probe_ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    # For localhost / loopback, always alive
    if ip in ["127.0.0.1", "localhost", "::1"]:
        is_up = True

    # Reverse DNS resolution
    hostname = None
    if is_up:
        try:
            loop = asyncio.get_running_loop()
            host_info = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            hostname = host_info[0] if host_info else None
        except Exception:
            hostname = None

    return {
        "ip": ip,
        "is_up": is_up,
        "hostname": hostname,
        "responding_port": responding_port
    }

async def discover_hosts(target_ips: List[str], concurrency: int = 50, timeout: float = 1.0) -> List[Dict[str, Any]]:
    """
    Sweeps a list of target IPs concurrently with bounded semaphore.
    Returns list of discovered active hosts.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def bound_check(ip: str):
        async with semaphore:
            return await is_host_alive(ip, timeout=timeout)

    discovered = await asyncio.gather(*(bound_check(ip) for ip in target_ips), return_exceptions=False)
    
    # Filter only hosts that responded or if list was small (<= 3 targets, include all for deep scan)
    if len(target_ips) <= 3:
        # If user explicitly scanned 1-3 IPs (e.g. 127.0.0.1 or single server), always scan them
        for res in discovered:
            results.append(res)
    else:
        for res in discovered:
            if res["is_up"]:
                results.append(res)

    return results
