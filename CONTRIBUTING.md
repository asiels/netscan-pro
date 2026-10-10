# Contributing

1. Fork and clone the repo.
2. `make dev` — installs the package in editable mode with dev tools and git hooks.
3. Write tests for new behaviour (`tests/` mirrors `netscan/`).
4. `make lint && make typecheck && make test` must pass.
5. Open a PR; CI runs the same checks on Python 3.9–3.12.

## Conventions

- Engine functions are registered via `@register_engine("name")` in
  `netscan/portscan.py` (or a new module imported by the CLI).
- All scan results flow through the dataclasses in `netscan/core/models.py`.
- Network I/O must be mockable: tests never touch the network.
