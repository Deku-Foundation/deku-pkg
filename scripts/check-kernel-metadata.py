#!/usr/bin/env python3
"""Validate the structure and safety invariants of the kernel research snapshot."""
import json
import re
import sys
from datetime import date
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "kernel" / "versions.json"
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    print(f"ERROR: cannot read valid JSON from {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)

errors = []
if data.get("schema_version") != 1:
    errors.append("schema_version must be 1")
try:
    date.fromisoformat(data["checked_on"])
except (KeyError, TypeError, ValueError):
    errors.append("checked_on must be an ISO date (YYYY-MM-DD)")

if data.get("status") != "research-only":
    errors.append("status must remain research-only until package/build/boot gates exist")
if data.get("architecture") != "x86_64":
    errors.append("initial architecture must be x86_64")
if data.get("preferred_track") not in {"stable", "longterm"}:
    errors.append("preferred_track must be stable or longterm")

candidates = data.get("candidates")
if not isinstance(candidates, dict):
    errors.append("candidates must be an object")
    candidates = {}

for track in ("stable", "longterm", "mainline"):
    item = candidates.get(track)
    if not isinstance(item, dict):
        errors.append(f"missing candidate: {track}")
        continue
    version = item.get("version", "")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
        errors.append(f"{track}.version must be a numeric kernel version")
    if item.get("release_type") != track:
        errors.append(f"{track}.release_type must match its key")
    source = item.get("source", "")
    if not isinstance(source, str) or not source.startswith("https://cdn.kernel.org/"):
        errors.append(f"{track}.source must use the official kernel.org CDN")
    if item.get("promoted") is not False:
        errors.append(f"{track} must not be promoted by metadata alone")

integrity = data.get("integrity")
if not isinstance(integrity, dict):
    errors.append("integrity must be an object")
else:
    # A source hash and signature/build evidence must be explicitly reviewed;
    # this checker deliberately never treats a metadata edit as test evidence.
    if integrity.get("signature_verified") is not False and not integrity.get("signing_evidence"):
        errors.append("signature verification requires explicit signing_evidence")
    if integrity.get("build_tested") is True and not integrity.get("build_evidence"):
        errors.append("build_tested requires build_evidence")
    if integrity.get("boot_tested") is True and not integrity.get("boot_evidence"):
        errors.append("boot_tested requires boot_evidence")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Kernel metadata structure and promotion safeguards: OK")
print("Reminder: this check does not fetch sources, verify signatures, compile the kernel, or boot-test it.")
