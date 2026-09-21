import pytest
import asyncio
from backend.app.scanner.parser import parse_targets, parse_ports
from backend.app.scanner.fingerprint import fingerprint_os_and_device
from backend.app.models.scan import ScanProfile

def test_parse_targets_single_and_cidr():
    # Single IP
    ips = parse_targets("192.168.1.1")
    assert ips == ["192.168.1.1"]

    # CIDR /30 (should expand to 2 usable host IPs)
    ips = parse_targets("192.168.1.0/30")
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips
    assert len(ips) == 2

    # Comma separated mixed
    ips = parse_targets("10.0.0.1, 10.0.0.2, 127.0.0.1")
    assert "10.0.0.1" in ips
    assert "127.0.0.1" in ips
    assert len(ips) == 3

    # IP Range
    ips = parse_targets("192.168.1.10-192.168.1.13")
    assert len(ips) == 4
    assert "192.168.1.10" in ips
    assert "192.168.1.13" in ips

def test_parse_ports_profiles():
    top20 = parse_ports(ScanProfile.TOP_20)
    assert len(top20) == 20
    assert 80 in top20
    assert 443 in top20
    assert 22 in top20

    top100 = parse_ports(ScanProfile.TOP_100)
    assert len(top100) >= 90

    custom = parse_ports(ScanProfile.CUSTOM, "80, 443, 8080-8085")
    assert 80 in custom
    assert 443 in custom
    assert 8080 in custom
    assert 8085 in custom
    assert len(custom) == 8

def test_fingerprint_os():
    # Windows signature
    win = fingerprint_os_and_device([445, 135, 3389], ["Microsoft-IIS/10.0"])
    assert "Windows" in win["os_name"]
    assert win["os_confidence"] in ["Confirmed", "Likely"]

    # Linux signature
    lin = fingerprint_os_and_device([22, 80], ["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", "nginx/1.18.0"])
    assert "Ubuntu" in lin["os_name"] or "Linux" in lin["os_name"]
    assert lin["os_confidence"] in ["Confirmed", "Likely"]
