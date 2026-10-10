"""Shared utilities: target validation, port-spec parsing, helpers."""
from __future__ import annotations

import ipaddress
import socket


def validate_target(target: str) -> bool:
    """Accepts a single IP, a CIDR network, or a hostname."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def resolve(host: str) -> str:
    """Resolve a hostname to an IP; returns the input on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,1-1000' into a sorted, deduplicated, validated port list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    invalid = [p for p in ports if not 0 < p < 65536]
    if invalid:
        raise ValueError(f"port out of range 1-65535: {invalid}")
    return sorted(ports)
