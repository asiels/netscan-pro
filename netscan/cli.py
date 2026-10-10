"""Command-line interface for NetScan Pro."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from rich.console import Console

from . import __version__
from .config import load_config
from .core.models import HostResult, PortResult, PortState, Vulnerability
from .core.registry import available_engines, get_engine
from .discovery import arp_scan, icmp_scan, tcp_probe
from .fingerprint import get_ttl, guess_os, guess_service
from .portscan import grab_banner  # side effect: registers engines
from .report import print_table, to_csv, to_html, to_json
from .utils import parse_ports, resolve, validate_target
from .vulns import check_banner, lookup_cves

console = Console()
log = logging.getLogger("netscan")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="NetScan Pro - modular, async-first network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  netscan -t 192.168.1.0/24 --discover arp
  netscan -t scanme.nmap.org -p 1-1024 --engine async
  netscan -t 192.168.1.1 -p 22,80,443 --engine syn --report html -o reports/full
  netscan -t 10.0.0.5 --nvd --config scan.toml""",
    )
    p.add_argument("-t", "--target", help="IP, CIDR, or hostname")
    p.add_argument("-p", "--ports", help="e.g. 22,80,1-1000")
    p.add_argument("--engine", choices=available_engines(), help="scan engine")
    p.add_argument("--discover", choices=["arp", "icmp", "none"], help="discovery mode")
    p.add_argument("--timeout", type=float, help="per-port timeout (seconds)")
    p.add_argument("--concurrency", type=int, help="max concurrent probes (async engine)")
    p.add_argument("--report", choices=["json", "csv", "html", "table"], help="output format")
    p.add_argument("-o", "--output", default="reports/scan_report", help="report path prefix")
    p.add_argument("--config", help="JSON config file; CLI flags override it")
    p.add_argument("--nvd", action="store_true", help="enrich findings via the NVD API")
    p.add_argument("--nvd-api-key", help="NVD API key (higher rate limits)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def discover_hosts(target: str, mode: str) -> list[str]:
    console.rule(f"[bold cyan]Host Discovery ({mode.upper()})[/]")
    try:
        hosts = [h["ip"] for h in (arp_scan(target) if mode == "arp" else icmp_scan(target))]
    except PermissionError:
        console.print("[red]Root/admin required for this discovery mode.[/]")
        sys.exit(1)
    if not hosts and "/" not in target:
        hosts = [resolve(target)] if tcp_probe(resolve(target)) else []
    console.print(f"[green]{len(hosts)} live host(s) found.[/]")
    return hosts


async def enrich_with_nvd(result: HostResult, api_key: str | None) -> None:
    """Look up NVD CVEs for each detected service (fail-soft)."""
    for port in result.ports:
        if port.service == "unknown":
            continue
        cves = await lookup_cves(port.service, api_key=api_key)
        port.vulns += [
            Vulnerability(name=c["id"], severity="NVD", description=c["description"], source="nvd")
            for c in cves
        ]


def scan_host(host: str, ports: list[int], args: argparse.Namespace) -> HostResult:
    engine = get_engine(args.engine)
    kwargs: dict = {"timeout": args.timeout}
    if args.engine == "async":
        kwargs["concurrency"] = args.concurrency
    open_ports = engine(host, ports, **kwargs)
    result = HostResult(host=host, os_guess=guess_os(get_ttl(host)))
    for port in open_ports:
        banner = grab_banner(host, port)
        service = guess_service(port, banner)
        result.ports.append(
            PortResult(
                port=port,
                state=PortState.OPEN,
                service=service,
                banner=banner,
                vulns=check_banner(banner, service),
            )
        )
    return result


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # config file first, CLI flags win
    cfg = load_config(args.config)
    for key, default in cfg.items():
        if getattr(args, key, None) is None:
            setattr(args, key, default)

    if not args.target:
        parser.error("a target is required (-t/--target)")
    if not validate_target(args.target):
        console.print(f"[red]Invalid target: {args.target}[/]")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    hosts = (
        discover_hosts(args.target, args.discover)
        if "/" in args.target and args.discover != "none"
        else [resolve(args.target)]
    )

    console.rule(f"[bold cyan]Port Scan[/] engine={args.engine} ports={len(ports)}")
    results: list[HostResult] = []
    with console.status("[bold green]Scanning...") as status:
        for host in hosts:
            status.update(f"[bold green]Scanning {host}...")
            result = scan_host(host, ports, args)
            results.append(result)
            console.print(f"  → {host}: {result.open_port_count} open port(s)")

    if args.nvd:
        console.rule("[bold cyan]NVD Enrichment[/]")
        asyncio.run(asyncio.gather(*(enrich_with_nvd(r, args.nvd_api_key) for r in results)))

    if args.report == "table":
        print_table(results)
    else:
        path = f"{args.output}.{args.report}"
        {"json": to_json, "csv": to_csv, "html": to_html}[args.report](results, path)
        console.print(f"[green]Report saved to {path}[/]")


if __name__ == "__main__":
    main()
