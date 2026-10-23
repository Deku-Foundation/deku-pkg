from copy import deepcopy
import json
import unittest
from pathlib import Path

from deku_pkg.catalog import CatalogError, validate_catalog
from deku_pkg.planner import PlanError, create_plan

EXAMPLE = Path(__file__).parents[1] / "examples" / "catalog.json"


class PackagePlannerTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def test_catalog_fixture_is_valid(self):
        self.assertEqual(validate_catalog(self.catalog), self.catalog)

    def test_dependencies_appear_before_requested_package(self):
        plan = create_plan(self.catalog, ["hello-deku"])
        self.assertEqual([p["name"] for p in plan], ["libsample", "hello-deku"])

    def test_plan_is_deterministic(self):
        first = create_plan(self.catalog, ["hello-deku"])
        second = create_plan(self.catalog, ["hello-deku"])
        self.assertEqual(first, second)

    def test_missing_dependency_fails(self):
        catalog = deepcopy(self.catalog)
        catalog["packages"][1]["dependencies"] = ["missing-lib"]
        with self.assertRaisesRegex(PlanError, "missing dependency"):
            create_plan(catalog, ["hello-deku"])

    def test_dependency_cycle_fails(self):
        catalog = deepcopy(self.catalog)
        catalog["packages"][0]["dependencies"] = ["hello-deku"]
        with self.assertRaisesRegex(PlanError, "cycle"):
            create_plan(catalog, ["hello-deku"])

    def test_duplicate_package_names_fail(self):
        catalog = deepcopy(self.catalog)
        catalog["packages"].append(deepcopy(catalog["packages"][0]))
        with self.assertRaisesRegex(CatalogError, "duplicate package"):
            validate_catalog(catalog)

    def test_path_traversal_artifact_name_fails(self):
        catalog = deepcopy(self.catalog)
        catalog["packages"][0]["artifact"]["filename"] = "../escape.deku"
        with self.assertRaisesRegex(CatalogError, "simple filename"):
            validate_catalog(catalog)

    def test_empty_request_fails(self):
        with self.assertRaisesRegex(PlanError, "non-empty"):
            create_plan(self.catalog, [])


if __name__ == "__main__":
    unittest.main()
