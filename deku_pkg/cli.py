"""CLI for validating a catalog and printing a dependency plan."""
import argparse
import json
import sys
from pathlib import Path

from .catalog import CatalogError, load_catalog
from .planner import PlanError, create_plan


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan Deku package dependencies without installing anything")
    parser.add_argument("--catalog", required=True, help="local JSON catalog")
    parser.add_argument("--install", nargs="+", required=True, metavar="PACKAGE", help="package names to plan")
    args = parser.parse_args()
    try:
        catalog = load_catalog(args.catalog)
        plan = create_plan(catalog, args.install)
    except (CatalogError, PlanError) as exc:
        print(f"cannot create plan: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"mode": "plan-only", "architecture": catalog["architecture"], "packages": plan},
                     indent=2, sort_keys=True))
    print("No artifacts downloaded; no files installed; no system changes performed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
