"""
Advanced service banner grabber, TLS/SSL cipher inspector, and HTTP security header evaluator.
"""

import asyncio
import socket
import ssl
import json
from typing import Dict, Any, List

RECOMMENDED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

async def inspect_tls(ip: str, port: int = 443, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Connects with TLS context to inspect TLS protocol version and negotiated cipher suite.
    """
    tls_info = {
        "tls_version": None,
        "tls_cipher": None,
        "has_tls": False,
        "cert_subject": None,
        "cert_issuer": None
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_running_loop()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context),
            timeout=timeout
        )
        tls_info["has_tls"] = True
        
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            tls_info["tls_version"] = ssl_obj.version()
            cipher = ssl_obj.cipher()
            if cipher:
                tls_info["tls_cipher"] = cipher[0]

        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    return tls_info

async def inspect_http_security(ip: str, port: int, use_tls: bool = False, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Sends HTTP/1.1 request and parses response headers for Server leak and missing security headers.
    """
    result = {
        "http_server_header": None,
        "missing_headers": [],
        "present_headers": {}
    }

    try:
        scheme = "https" if use_tls or port in [443, 8443] else "http"
        context = None
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context),
            timeout=timeout
        )

        req = f"HEAD / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: CyberShield-Audit/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()

        raw_response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        text = raw_response.decode("latin1", errors="replace")
        lines = text.split("\r\n")
        
        found_headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                found_headers[k.strip().lower()] = v.strip()

        if "server" in found_headers:
            result["http_server_header"] = found_headers["server"]

        result["present_headers"] = found_headers

        missing = []
        for header in RECOMMENDED_SECURITY_HEADERS:
            if header.lower() not in found_headers:
                missing.append(header)
        result["missing_headers"] = missing

    except Exception:
        pass

    return result
