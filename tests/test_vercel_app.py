from __future__ import annotations

import json
import unittest
from pathlib import Path

from vercel_app_data import CATALOG, build_plan


ROOT = Path(__file__).resolve().parents[1]


class VercelAppTests(unittest.TestCase):
    def test_catalog_matches_integrated_platform(self):
        self.assertEqual(CATALOG["version"], "1.0.0")
        self.assertEqual(CATALOG["metrics"]["playbooks"], 40)
        self.assertEqual(CATALOG["metrics"]["openosint_tools"], 20)
        self.assertEqual(CATALOG["metrics"]["upstream_capability_engines"], 40)
        self.assertFalse(CATALOG["deployment_boundary"]["executes_scans"])
        self.assertTrue(CATALOG["deployment_boundary"]["target_processed_locally"])

    def test_plans_are_argv_templates_without_target_data(self):
        plan = build_plan({
            "target_type": "domain", "engine": "fusion", "authorized": True,
        })
        encoded = json.dumps(plan)
        self.assertIn("{target}", encoded)
        self.assertIn("integrations", encoded)
        self.assertIn("openosint", encoded)
        self.assertFalse(plan["target_received"])

    def test_api_rejects_targets_and_missing_authorization(self):
        with self.assertRaisesRegex(ValueError, "Do not send a target"):
            build_plan({
                "target": "sensitive@example.com", "target_type": "email",
                "engine": "fusion", "authorized": True,
            })
        with self.assertRaisesRegex(ValueError, "authorization"):
            build_plan({"target_type": "domain", "engine": "fusion"})

    def test_static_client_uses_safe_dom_and_omits_target_from_request(self):
        script = (ROOT / "public/app.js").read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", script)
        self.assertIn("textContent", script)
        self.assertIn("target_type: type", script)
        self.assertNotIn("target: target", script)
        self.assertIn("isPrivateIPv4", script)

    def test_vercel_security_headers_and_function_limit(self):
        config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
        headers = {item["key"]: item["value"] for item in config["headers"][0]["headers"]}
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(config["functions"]["api/*.py"]["maxDuration"], 10)

    def test_legacy_directory_is_bundled_and_routed(self):
        config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
        rewrites = {item["source"]: item["destination"] for item in config["rewrites"]}
        legacy = (ROOT / "public/legacy.html").read_text(encoding="utf-8")
        self.assertEqual(rewrites["/legacy"], "/public/legacy.html")
        self.assertIn("<title>TraceAtlas", legacy)
        self.assertIn("Built for ethical research", legacy)


if __name__ == "__main__":
    unittest.main()
