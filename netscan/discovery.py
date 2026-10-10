"""Host discovery: ARP (LAN), ICMP ping sweep, TCP-probe fallback."""

from __future__ import annotations

import ipaddress
import socket

from rich.console import Console

console = Console()


def _scapy():
    from scapy.all import ARP, ICMP, IP, Ether, sr1, srp

    return ARP, Ether, ICMP, IP, sr1, srp


def arp_scan(network: str, timeout: int = 2) -> list[dict]:
    """Fast LAN host discovery via ARP. Requires root/admin."""
    ARP, Ether, _, _, _, srp = _scapy()
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc, "method": "ARP"} for _, rcv in answered]


def icmp_scan(network: str, timeout: int = 2) -> list[dict]:
    """Ping sweep across a CIDR range."""
    _, _, ICMP, IP, sr1, _ = _scapy()
    hosts = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]
    live = []
    for host in hosts:
        reply = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=False)
        if reply:
            live.append({"ip": host, "mac": None, "method": "ICMP"})
    return live


def tcp_probe(host: str, ports: tuple[int, ...] = (80, 443, 22), timeout: float = 1.0) -> bool:
    """Fallback discovery: host counts as 'up' if any common port connects."""
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return True
        except OSError:
            continue
    return False
