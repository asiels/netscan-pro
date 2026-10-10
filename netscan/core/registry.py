"""Strategy-pattern registry for pluggable scan engines.

New engines (UDP, QUIC, custom) are added by decorating a function with
@register_engine("name") -- no changes to the CLI are required.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

_ENGINE_REGISTRY: dict[str, Callable[..., Any]] = {}


def register_engine(name: str) -> Callable[[F], F]:
    """Decorator registering a scan engine under `name`."""

    def decorator(fn: F) -> F:
        _ENGINE_REGISTRY[name] = fn
        return fn

    return decorator


def get_engine(name: str) -> Callable[..., Any]:
    """Resolve an engine by name, with a helpful error on typos."""
    try:
        return _ENGINE_REGISTRY[name]
    except KeyError as exc:
        available = ", ".join(available_engines())
        raise ValueError(f"unknown engine {name!r}; available: {available}") from exc


def available_engines() -> list[str]:
    return sorted(_ENGINE_REGISTRY)
