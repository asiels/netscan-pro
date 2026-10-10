"""Vulnerability intelligence: local signature DB + NVD API enrichment."""

from .local import VULN_DB, check_banner
from .nvd import lookup_cves

__all__ = ["VULN_DB", "check_banner", "lookup_cves"]
