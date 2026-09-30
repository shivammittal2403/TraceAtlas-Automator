from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.opencti_connectors import OpenCTIConnectorCatalog
from traceatlas.policy import PolicyError


REPO = Path(__file__).resolve().parents[1]
VENDOR = REPO / "third_party" / "opencti-connectors"


class OpenCTIConnectorTests(unittest.TestCase):
    def setUp(self):
        self.catalog = OpenCTIConnectorCatalog()

    def test_complete_connector_inventory_is_catalogued_and_disabled(self):
        snapshot = self.catalog.snapshot
        self.assertEqual(snapshot["connector_count"], 308)
        self.assertEqual(
            snapshot["upstream_commit"],
            "55ca0dfa4129050cb607fdaf6b1a7457e0ae3476",
        )
        self.assertEqual(snapshot["category_counts"], {
            "external-import": 178,
            "internal-enrichment": 77,
            "internal-export-file": 7,
            "internal-import-file": 6,
            "stream": 40,
        })
        rows = self.catalog.list(limit=1000)
        self.assertEqual(len(rows), 308)
        self.assertTrue(all(row["execution_enabled"] is False for row in rows))
        self.assertEqual(len({row["id"] for row in rows}), 308)

    def test_metadata_and_secret_names_are_exposed_without_values(self):
        shodan = self.catalog.get("internal-enrichment/shodan")
        self.assertTrue(shodan["compose_available"])
        self.assertIn("OPENCTI_TOKEN", shodan["required_env"])
        self.assertIn("SHODAN_TOKEN", shodan["secret_env"])
        encoded = json.dumps(shodan)
        self.assertNotIn("ChangeMe", encoded)

    def test_plan_requires_authority_and_never_executes(self):
        with self.assertRaises(PolicyError):
            self.catalog.plan(
                "external-import/misp", VENDOR, authorized=False, owned_org=True
            )
        with patch.dict("os.environ", {}, clear=True):
            plan = self.catalog.plan(
                "external-import/misp", VENDOR, authorized=True, owned_org=True
            )
        self.assertFalse(plan["executed"])
        self.assertFalse(plan["launch_ready"])
        self.assertIn("OPENCTI_TOKEN", plan["missing_env_names"])
        self.assertEqual(plan["launch_command"][:2], ["docker", "compose"])

    def test_doctor_keeps_upstream_and_traceatlas_verification_separate(self):
        result = self.catalog.doctor(VENDOR)
        self.assertEqual(result["catalogued_connectors"], 308)
        self.assertEqual(result["vendor_packages_present"], 308)
        self.assertEqual(result["live_verified_by_traceatlas"], 0)
        self.assertEqual(result["license_counts"]["AGPL-3.0-only"], 4)
        self.assertEqual(result["license_counts"]["MIT"], 1)

    def test_checksum_verifier_detects_changes_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "vendor"
            root.mkdir()
            item = root / "connector.py"
            item.write_text("safe", encoding="utf-8")
            digest = hashlib.sha256(item.read_bytes()).hexdigest()
            sums = base / "SUMS"
            sums.write_text(f"{digest}  connector.py\n", encoding="utf-8")
            self.assertTrue(self.catalog.verify(root, sums)["valid"])
            item.write_text("changed", encoding="utf-8")
            self.assertFalse(self.catalog.verify(root, sums)["valid"])
            item.write_text("safe", encoding="utf-8")
            (root / "extra.py").write_text("unexpected", encoding="utf-8")
            result = self.catalog.verify(root, sums)
            self.assertFalse(result["valid"])
            self.assertIn({"path": "extra.py", "error": "unexpected-file"}, result["failures"])
            (root / "extra.py").unlink()
            sums.write_text(f"{digest}  ../escape\n", encoding="utf-8")
            with self.assertRaises(PolicyError):
                self.catalog.verify(root, sums)


if __name__ == "__main__":
    unittest.main()
