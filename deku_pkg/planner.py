"""Deterministic dependency planning; no downloads or system changes."""
from __future__ import annotations

from typing import Any

from .catalog import CatalogError, validate_catalog


class PlanError(ValueError):
    """Raised when a requested dependency plan cannot be resolved."""


def create_plan(catalog: Any, requested: list[str]) -> list[dict[str, Any]]:
    """Return dependency-first plan for a catalog with one candidate per name."""
    try:
        catalog = validate_catalog(catalog)
    except CatalogError as exc:
        raise PlanError(str(exc)) from exc
    if not isinstance(requested, list) or not requested:
        raise PlanError("requested packages must be a non-empty list")
    if any(not isinstance(name, str) for name in requested):
        raise PlanError("requested package names must be strings")
    if len(set(requested)) != len(requested):
        raise PlanError("requested package list contains duplicates")

    packages = {package["name"]: package for package in catalog["packages"]}
    order: list[str] = []
    state: dict[str, int] = {}  # 1 = visiting, 2 = complete

    def visit(name: str, chain: list[str]) -> None:
        if name not in packages:
            raise PlanError(f"missing dependency: {name} (required by {' -> '.join(chain) or 'request'})")
        status = state.get(name, 0)
        if status == 1:
            raise PlanError("dependency cycle: " + " -> ".join(chain + [name]))
        if status == 2:
            return
        state[name] = 1
        for dependency in sorted(packages[name]["dependencies"]):
            visit(dependency, chain + [name])
        state[name] = 2
        order.append(name)

    for name in sorted(requested):
        visit(name, [])

    return [
        {
            "name": name,
            "version": packages[name]["version"],
            "sha256": packages[name]["artifact"]["sha256"],
            "size_bytes": packages[name]["artifact"]["size_bytes"],
        }
        for name in order
    ]
