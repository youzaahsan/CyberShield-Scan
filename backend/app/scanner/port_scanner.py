"""
Asynchronous TCP Connect and UDP Port Scanner for CyberShield Scan.
Performs safe, non-destructive port probing with banner grabbing, timeouts,
and clean socket teardown.
"""

import asyncio
import socket
import ssl
from typing import Dict, Any, Optional

WELL_KNOWN_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "http-alt",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "upnp",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    6443: "kubernetes",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "cslistener",
    9092: "kafka",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

async def scan_tcp_port(ip: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Attempts non-destructive asynchronous TCP connect to ip:port.
    If open, attempts initial banner grabbing with short timeout.
    Guarantees clean socket close.
    """
    result = {
        "port": port,
        "protocol": "TCP",
        "state": "CLOSED",
        "service": WELL_KNOWN_SERVICES.get(port, "unknown"),
        "banner": None,
        "product": None,
        "version": None,
        "tls_version": None,
        "tls_cipher": None,
        "http_server_header": None,
        "missing_headers": None
    }

    reader = None
    writer = None

    try:
        connect_coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
        result["state"] = "OPEN"

        # Attempt banner grabbing based on common protocol types
        try:
            # 1. First check if service sends immediate welcome banner (SSH, FTP, SMTP, MySQL)
            banner_bytes = b""
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=0.8)
            except (asyncio.TimeoutError, ConnectionResetError):
                pass

            # 2. If no immediate banner and looks like HTTP/HTTPS/Web service, send a gentle HTTP probe
            if not banner_bytes and port in [80, 443, 3000, 8000, 8080, 8443, 8888, 5000, 9000, 9090]:
                try:
                    probe = b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: CyberShield-Audit/1.0\r\nConnection: close\r\n\r\n"
                    writer.write(probe)
                    await asyncio.wait_for(writer.drain(), timeout=0.5)
                    banner_bytes = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                except Exception:
                    pass

            if banner_bytes:
                banner_str = banner_bytes.decode("latin1", errors="replace").strip()
                result["banner"] = banner_str[:500]

                # Parse basic service identification from banner
                if "SSH-" in banner_str:
                    result["service"] = "ssh"
                    parts = banner_str.split()
                    if len(parts) > 0 and parts[0].startswith("SSH-"):
                        result["product"] = "OpenSSH" if "OpenSSH" in parts[0] else "SSH"
                        result["version"] = parts[0].replace("SSH-2.0-", "").replace("SSH-1.99-", "")
                elif "HTTP/" in banner_str:
                    result["service"] = "http" if port != 443 else "https"
                    for line in banner_str.split("\r\n"):
                        if line.lower().startswith("server:"):
                            result["http_server_header"] = line.split(":", 1)[1].strip()
                            result["product"] = result["http_server_header"].split("/")[0]
                            if "/" in result["http_server_header"]:
                                result["version"] = result["http_server_header"].split("/")[1].split()[0]
                elif "FTP" in banner_str or "220 " in banner_str:
                    result["service"] = "ftp"
                elif "SMTP" in banner_str or banner_str.startswith("220"):
                    result["service"] = "smtp"
                elif "mysql" in banner_str.lower() or "mariadb" in banner_str.lower():
                    result["service"] = "mysql"
                    result["product"] = "MySQL"

        except Exception:
            pass

    except (ConnectionRefusedError, socket.error):
        result["state"] = "CLOSED"
    except asyncio.TimeoutError:
        result["state"] = "FILTERED"
    except Exception:
        result["state"] = "CLOSED"
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return result

async def scan_udp_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Safe UDP probe for standard services (DNS, SNMP, NTP).
    """
    result = {
        "port": port,
        "protocol": "UDP",
        "state": "OPEN|FILTERED",
        "service": WELL_KNOWN_SERVICES.get(port, "unknown"),
        "banner": None,
        "product": None,
        "version": None
    }
    
    # Specific lightweight probe payloads
    probes = {
        53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00", # DNS query header
        123: b"\x1b" + 47 * b"\0", # NTP request
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\t\x06\x05\x2b\x06\x01\x02\x01\x05\x00" # SNMP v2c public
    }

    payload = probes.get(port, b"\x00")
    
    try:
        loop = asyncio.get_running_loop()
        def _probe_sync():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(payload, (ip, port))
                data, _ = sock.recvfrom(1024)
                return True, data
            except socket.timeout:
                return False, None
            except socket.error:
                return False, None
            finally:
                sock.close()

        has_data, raw_banner = await loop.run_in_executor(None, _probe_sync)
        if has_data and raw_banner:
            result["state"] = "OPEN"
            result["banner"] = raw_banner.decode("latin1", errors="replace")[:200]
        else:
            result["state"] = "FILTERED"
    except Exception:
        result["state"] = "FILTERED"

    return result
