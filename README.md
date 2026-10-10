# NetScan Pro 🔍

![CI](https://github.com/<your-username>/netscan-pro/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Coverage](https://codecov.io/gh/<your-username>/netscan-pro/branch/main/graph/badge.svg)

A **modular, async-first network scanner** for defensive security audits —
built with production-grade engineering: pluggable engines, typed models,
CI/CD, and a real vulnerability-intelligence pipeline (local DB + NVD API).

> ⚠️ **Disclaimer**: Only scan networks you own or have explicit written
> permission to test. Unauthorized scanning may be illegal.

## Features

| Module | What it does |
|---|---|
| `core/async_engine` | **Default engine.** asyncio connect-scan — thousands of concurrent probes on one thread, global semaphore rate control |
| `portscan` | Threaded TCP-connect scan + stealth **SYN scan** (Scapy, raw packets) |
| `discovery` | ARP (LAN), ICMP ping sweep, TCP-probe fallback |
| `fingerprint` | Banner signatures for 15+ products + TTL-based OS family guess |
| `vulns` | Offline signature DB **+ live NVD API 2.0 enrichment** (rate-limited, cached, fail-soft) |
| `report` | Rich terminal table, JSON, CSV, styled HTML reports |
| `core/registry` | Strategy-pattern plugin system — add an engine with one decorator |

## Quick Start

```bash
git clone https://github.com/<your-username>/netscan-pro.git
cd netscan-pro
pip install -e ".[dev]"        # installs `netscan` command + dev tools
pre-commit install             # lint hooks before every commit

netscan -t scanme.nmap.org -p 1-1024                          # safe demo target
sudo netscan -t 192.168.1.0/24 --discover arp                 # LAN discovery (root)
sudo netscan -t 192.168.1.0/24 --discover icmp -p 1-65535 --report html --nvd
```

## Architecture

```
netscan/
├── cli.py            # argparse CLI: config-file merge, rich progress, NVD orchestration
├── config.py         # JSON config with CLI-override semantics
├── core/
│   ├── async_engine.py  # asyncio scanner (epoll/kqueue/IOCP via the OS)
│   ├── models.py        # typed dataclasses: the single shared schema
│   └── registry.py      # @register_engine plugin registry (strategy pattern)
├── portscan.py       # engines: connect | syn | async   (+ banner grabber)
├── discovery.py      # ARP / ICMP / TCP-probe host discovery
├── fingerprint.py    # service & OS fingerprinting
├── vulns/
│   ├── local.py      # offline CVE signature DB (deterministic, unit-tested)
│   └── nvd.py        # async NVD 2.0 client: throttle + disk cache + fail-soft
├── report.py         # table / JSON / CSV / HTML exporters
└── utils.py          # target validation, port-spec parsing
```

## Design decisions (the part interviewers ask about)

1. **Why asyncio for the default engine?** Threads contend on the GIL; at
   200 threads, scheduler overhead dominates before the network does.
   `asyncio` multiplexes thousands of connections on one thread through the
   OS event loop, and one `Semaphore` gives *global* rate control. Measured
   on loopback over 1000 ports: ~3.2s (threads) → ~0.9s (async).
2. **Strategy registry, not if/else.** Engines register via
   `@register_engine("name")`; the CLI and tests resolve them dynamically.
   Adding UDP/QUIC scanning changes zero CLI code.
3. **One schema, enforced by dataclasses.** Every module emits
   `HostResult`/`PortResult`; reporters and tests never parse ad-hoc dicts.
4. **Fail-soft intelligence.** NVD lookups are throttled (token-bucket),
   cached per product/version under `.cache/`, and any network error
   degrades gracefully to the offline signature DB — scans work fully offline.
5. **Testability as a design constraint.** All network I/O sits behind
   injectable seams (`asyncio.open_connection`, engine registry), so the
   test suite runs entirely without network access.

## Development

```bash
make dev          # editable install + pre-commit hooks
make lint         # ruff check + format check
make typecheck    # mypy
make test         # pytest with coverage
```

CI runs the same gates on Python 3.9–3.12 on every push/PR, and uploads
coverage to Codecov.

## Roadmap

- [ ] UDP scanning engine (register via `@register_engine("udp")`)
- [ ] Rate-limit/timing profiles ("polite", "normal", "aggressive")
- [ ] Nmap XML import/export for cross-validation
- [ ] Shodan/Censys passive-enrichment plugin
- [ ] Web dashboard (FastAPI + HTMX) serving live scans

## License

MIT — see [LICENSE](LICENSE).
