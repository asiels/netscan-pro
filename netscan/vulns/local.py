"""Local vulnerability signature database.

Matches service banners against known-vulnerable version patterns.
Offline, zero-dependency, and deterministic -- which is exactly why unit
tests for the vuln pipeline run against this module and not the network.
"""
from __future__ import annotations

import re

from ..core.models import Vulnerability

# product -> list of rules; 'vulnerable_below' triggers a semver comparison
VULN_DB: list[dict] = [
    {
        "name": "OpenSSH CVE-2023-38408",
        "product": "OpenSSH",
        "pattern": r"OpenSSH[_-]([\d.]+)",
        "vulnerable_below": "9.3",
        "severity": "High",
        "description": "ssh-agent PKCS#11 provider code execution.",
    },
    {
        "name": "vsftpd 2.3.4 backdoor",
        "product": "vsftpd",
        "pattern": r"vsftpd 2\.3\.4",
        "severity": "Critical",
        "description": "vsftpd 2.3.4 contains a known malicious backdoor.",
    },
]


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def check_banner(banner: str | None, service: str) -> list[Vulnerability]:
    """Match a banner against the local vulnerability database."""
    if not banner:
        return []
    findings = []
    for rule in VULN_DB:
        if service != rule["product"]:
            continue
        match = re.search(rule["pattern"], banner, re.IGNORECASE)
        if not match:
            continue
        if "vulnerable_below" in rule:
            found = _version_tuple(match.group(1))
            limit = _version_tuple(rule["vulnerable_below"])
            if found >= limit:
                continue
        findings.append(
            Vulnerability(
                name=rule["name"],
                severity=rule["severity"],
                description=rule["description"],
            )
        )
    return findings
