# Changelog

## [2.0.0] - 2026-10-10

### Added
- asyncio scanning engine (default) with global concurrency control
- Strategy-pattern engine registry (`@register_engine`)
- Typed data models (`HostResult`, `PortResult`, `Vulnerability`, `PortState`)
- NVD API 2.0 enrichment: async, rate-limited, disk-cached, fail-soft
- JSON config file support; CLI flags override config
- Test suite (pytest), CI (GitHub Actions: ruff, mypy, pytest, codecov)
- pre-commit hooks, Makefile, pyproject packaging with console script

### Changed
- Project is pip-installable: `pip install -e .` provides the `netscan` command
- HTML/CSV/JSON exporters consume typed models instead of ad-hoc dicts

## [1.0.0] - 2026-10-10

- Initial release: discovery, connect/SYN scans, fingerprinting, local vuln DB, reports
