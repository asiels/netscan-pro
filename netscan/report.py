"""Report exporters: terminal table (rich), JSON, CSV, HTML."""
from __future__ import annotations

import csv
import datetime
import json

from rich.console import Console
from rich.table import Table

from .core.models import HostResult


def print_table(results: list[HostResult]) -> None:
    table = Table(title="NetScan Pro Results")
    for col in ("Host", "Port", "Service", "OS Guess", "Findings"):
        table.add_column(col)
    for host in results:
        for p in host.ports:
            sevs = "; ".join(f"{v.severity}" for v in p.vulns) or "—"
            table.add_row(host.host, str(p.port), p.service, host.os_guess, sevs)
    Console().print(table)


def to_json(results: list[HostResult], path: str) -> None:
    with open(path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)


def to_csv(results: list[HostResult], path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "os_guess", "port", "service", "banner", "vulns"])
        for host in results:
            for p in host.ports:
                writer.writerow(
                    [host.host, host.os_guess, p.port, p.service, p.banner or "", len(p.vulns)]
                )


def to_html(results: list[HostResult], path: str) -> None:
    rows = ""
    for host in results:
        for p in host.ports:
            vulns = "".join(
                f"<span class='sev'>{v.severity}</span> {v.name} &mdash; {v.description}<br>"
                for v in p.vulns
            )
            rows += (
                f"<tr><td>{host.host}</td><td>{host.os_guess}</td><td>{p.port}</td>"
                f"<td>{p.service}</td><td>{p.banner or ''}</td><td>{vulns or '—'}</td></tr>"
            )

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>NetScan Pro Report</title>
<style>
body{{font-family:system-ui;margin:2rem;background:#0d1117;color:#c9d1d9}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #30363d;padding:8px;text-align:left;font-size:14px}}
th{{background:#161b22}}
h1{{color:#58a6ff}} .sev{{color:#f85149;font-weight:bold}}
</style></head><body>
<h1>NetScan Pro Report</h1>
<p>Generated: {datetime.datetime.now():%Y-%m-%d %H:%M}</p>
<table><tr><th>Host</th><th>OS Guess</th><th>Port</th><th>Service</th>
<th>Banner</th><th>Findings</th></tr>{rows}</table>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)
