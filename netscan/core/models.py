"""Typed data models shared across all scanner modules.

Every module speaks in these dataclasses, so the CLI, reporters and tests
all share one schema. Serialisation lives here, not scattered in reporters.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class PortState(str, Enum):
    """State of a scanned port."""

    OPEN = "open"
    FILTERED = "filtered"


@dataclass(frozen=True)
class Vulnerability:
    """A matched vulnerability (local DB or NVD)."""

    name: str
    severity: str
    description: str
    source: str = "local-db"


@dataclass
class PortResult:
    """Result for a single port."""

    port: int
    state: PortState = PortState.OPEN
    service: str = "unknown"
    banner: str | None = None
    vulns: list[Vulnerability] = field(default_factory=list)


@dataclass
class HostResult:
    """Aggregated result for one host."""

    host: str
    os_guess: str = "unknown"
    discovered_via: str | None = None
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_port_count(self) -> int:
        return sum(1 for p in self.ports if p.state == PortState.OPEN)

    def to_dict(self) -> dict:
        return asdict(self)
