"""Scan engines: classic threaded TCP connect, stealth SYN, async (core)."""

from __future__ import annotations

import contextlib
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor

from .core.registry import register_engine

_CRLF = b"\r\n"


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """Grab a service banner from an open port (best-effort)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            with contextlib.suppress(OSError):
                s.sendall(_CRLF)
            data = s.recv(1024)
            return data.decode(errors="ignore").strip() or None
    except OSError:
        return None


@register_engine("connect")
def tcp_connect_scan(
    host: str, ports: Iterable[int], timeout: float = 1.0, max_workers: int = 200
) -> list[int]:
    """Reliable full-TCP connect scan; needs no special privileges."""

    def check(port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = ex.map(check, ports)
    return sorted(p for p in results if p is not None)


@register_engine("syn")
def syn_scan(host: str, ports: Iterable[int], timeout: float = 1.0) -> list[int]:
    """Stealth half-open SYN scan via raw packets. Requires root/admin."""
    from scapy.all import IP, TCP, conf, sr1  # lazy: needs privileges anyway

    conf.verb = 0
    open_ports: list[int] = []
    for port in ports:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN+ACK
            open_ports.append(port)
            sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=0.2)  # RST teardown
    return sorted(open_ports)


@register_engine("async")
def async_scan_engine(
    host: str, ports: Iterable[int], timeout: float = 1.0, concurrency: int = 500
) -> list[int]:
    """Default engine: high-throughput asyncio connect scan."""
    from .core.async_engine import scan

    return scan(host, list(ports), timeout=timeout, concurrency=concurrency)
