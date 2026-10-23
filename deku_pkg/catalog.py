"""Catalog validation for the plan-only Deku package prototype."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_NAME = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARCHES = {"x86_64", "aarch64"}


class CatalogError(ValueError):
    """Raised when catalog metadata is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogError(message)


def validate_catalog(catalog: Any) -> dict[str, Any]:
    _require(isinstance(catalog, dict), "catalog must be an object")
    _require(set(catalog) == {"schema_version", "architecture", "packages"},
             "catalog must contain exactly schema_version, architecture, and packages")
    _require(type(catalog["schema_version"]) is int and catalog["schema_version"] == 1,
             "unsupported catalog schema_version")
    _require(isinstance(catalog["architecture"], str) and catalog["architecture"] in _ARCHES,
             "unsupported catalog architecture")
    _require(isinstance(catalog["packages"], list), "packages must be an array")

    seen: set[str] = set()
    for i, package in enumerate(catalog["packages"]):
        prefix = f"packages[{i}]"
        required = {"name", "version", "license", "architectures", "dependencies", "artifact"}
        _require(isinstance(package, dict) and set(package) == required,
                 f"{prefix} has missing or unsupported fields")
        _require(isinstance(package["name"], str) and _NAME.fullmatch(package["name"]) is not None,
                 f"{prefix}.name is invalid")
        _require(package["name"] not in seen, f"duplicate package name: {package['name']}")
        seen.add(package["name"])
        _require(isinstance(package["version"], str) and 1 <= len(package["version"]) <= 128,
                 f"{prefix}.version is invalid")
        _require(isinstance(package["license"], str) and 1 <= len(package["license"].strip()) <= 128,
                 f"{prefix}.license is required")
        arches = package["architectures"]
        _require(isinstance(arches, list) and arches and all(isinstance(a, str) and a in _ARCHES for a in arches),
                 f"{prefix}.architectures is invalid")
        _require(len(set(arches)) == len(arches), f"{prefix}.architectures has duplicates")
        _require(catalog["architecture"] in arches, f"{prefix} is not built for catalog architecture")
        deps = package["dependencies"]
        _require(isinstance(deps, list) and all(isinstance(d, str) and _NAME.fullmatch(d) is not None for d in deps),
                 f"{prefix}.dependencies is invalid")
        _require(len(set(deps)) == len(deps), f"{prefix}.dependencies has duplicates")
        _require(package["name"] not in deps, f"{prefix} depends on itself")
        artifact = package["artifact"]
        _require(isinstance(artifact, dict) and set(artifact) == {"filename", "sha256", "size_bytes"},
                 f"{prefix}.artifact has missing or unsupported fields")
        filename = artifact["filename"]
        _require(isinstance(filename, str) and filename and "/" not in filename and "\\" not in filename and filename not in {".", ".."},
                 f"{prefix}.artifact.filename must be a simple filename")
        _require(isinstance(artifact["sha256"], str) and _SHA256.fullmatch(artifact["sha256"]) is not None,
                 f"{prefix}.artifact.sha256 must be a 64-character lowercase SHA-256 digest")
        _require(type(artifact["size_bytes"]) is int and artifact["size_bytes"] > 0,
                 f"{prefix}.artifact.size_bytes must be a positive integer")
    return catalog


def load_catalog(path: str | Path) -> dict[str, Any]:
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            catalog = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"cannot read valid JSON catalog: {exc}") from exc
    return validate_catalog(catalog)
