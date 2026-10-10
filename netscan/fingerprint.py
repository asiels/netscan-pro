"""Service and OS fingerprinting heuristics (banner + TTL based)."""

from __future__ import annotations

import re

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    27017: "MongoDB",
}

# (regex, product name) -- banner signature database
BANNER_HINTS: list[tuple[str, str]] = [
    (r"OpenSSH[_-]([\d.]+)", "OpenSSH"),
    (r"Apache/?([\d.]*)", "Apache httpd"),
    (r"nginx/?([\d.]*)", "nginx"),
    (r"vsftpd ([\d.]+)", "vsftpd"),
    (r"Microsoft-IIS/?([\d.]*)", "Microsoft IIS"),
    (r"microsoft-ds|Windows", "Windows SMB"),
    (r"ProFTPD", "ProFTPD"),
    (r"MySQL", "MySQL"),
    (r"PostgreSQL", "PostgreSQL"),
    (r"Redis", "Redis"),
    (r"RDP|Terminal Services", "Microsoft RDP"),
]


def guess_service(port: int, banner: str | None) -> str:
    """Identify a service from its banner, falling back to the well-known port map."""
    if banner:
        for pattern, name in BANNER_HINTS:
            if re.search(pattern, banner, re.IGNORECASE):
                return name
    return SERVICE_MAP.get(port, "unknown")


def guess_os(ttl: int | None) -> str:
    """Rough OS family guess from the IP TTL."""
    if ttl is None:
        return "unknown"
    if ttl <= 64:
        return "Linux/Unix (TTL<=64)"
    if ttl <= 128:
        return "Windows (TTL<=128)"
    return "Network device (TTL>128)"


def get_ttl(host: str) -> int | None:
    """Best-effort TTL probe via ICMP (requires scapy + privileges)."""
    try:
        from scapy.all import ICMP, IP, sr1
    except ImportError:
        return None
    try:
        resp = sr1(IP(dst=host) / ICMP(), timeout=2, verbose=False)
        if resp:
            return resp.ttl
    except Exception:
        pass
    return None
