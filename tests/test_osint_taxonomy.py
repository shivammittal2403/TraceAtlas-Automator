"""Inventory, semantics and capability-preservation checks for requested labels."""
from collections import Counter
import unittest

from traceatlas.addons.intelligence_v1.registry import catalog
from traceatlas.osint_taxonomy import build_taxonomy, resolve_route


class TaxonomyTests(unittest.TestCase):
    def setUp(self):
        self.manifest = catalog()
        self.routes = build_taxonomy(self.manifest)

    def test_requested_coverage_and_group_counts(self):
        self.assertEqual(len(self.routes), 140)
        self.assertEqual(Counter(row["group_id"] for row in self.routes.values()),
                         {1: 9, 2: 21, 3: 14, 4: 16, 5: 15, 6: 15,
                          7: 17, 8: 12, 9: 7, 10: 14})
        self.assertEqual(Counter(row["route_kind"] for row in self.routes.values()),
                         {"exact": 66, "legacy_alias": 12, "parent_discipline": 62})

    def test_all_routes_use_registered_contracts(self):
        registered = {row["id"] for row in self.manifest["modules"]}
        self.assertTrue(all(row["canonical_id"] in registered for row in self.routes.values()))

    def test_case_normalization_preserves_actual_backend_id(self):
        route = resolve_route("  relationint  ", self.manifest)
        self.assertEqual(route["requested_discipline"], "RELATIONINT")
        self.assertEqual(route["canonical_id"], "RELATIONSHIPINT")
        self.assertEqual(route["route_kind"], "legacy_alias")

    def test_semantically_different_names_keep_distinct_routes(self):
        expected = {"NETWORKINT": "RELATIONSHIPINT", "NETINT": "netint",
                    "METADATAINT": "docint", "MOBILEINT": "techint", "POLICYINT": "govint"}
        for label, backend in expected.items():
            self.assertEqual(self.routes[label]["canonical_id"], backend)
        for label in ("NETWORKINT", "METADATAINT", "MOBILEINT", "POLICYINT"):
            self.assertEqual(self.routes[label]["route_kind"], "parent_discipline")
            self.assertFalse(self.routes[label]["dedicated_handler"])
            self.assertTrue(self.routes[label]["scope_note"])

    def test_catalog_statuses_and_hashes_are_preserved(self):
        registered = {row["id"]: row for row in self.manifest["modules"]}
        for route in self.routes.values():
            item = registered[route["canonical_id"]]
            self.assertEqual(route["execution_mode"], item["mode"])
            self.assertEqual(route["live_verified"], item["live_verified"])
            self.assertEqual(route["hosted_verified"], item["hosted_verified"])
            self.assertEqual(route["module_sha256"], item["file_sha256"])

    def test_unknown_input_cannot_become_an_import_path(self):
        for label in ("os", "../../other", "osint;whoami", "__import__", None):
            with self.subTest(label=label), self.assertRaises(ValueError):
                resolve_route(label, self.manifest)

    def test_absent_backend_does_not_silently_fall_back(self):
        manifest = {**self.manifest, "modules": [
            row for row in self.manifest["modules"] if row["id"] != "RELATIONSHIPINT"]}
        with self.assertRaises(ValueError):
            build_taxonomy(manifest)


if __name__ == "__main__":
    unittest.main()
