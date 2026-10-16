"""Full requested source inventory and policy-separation regression tests."""
from __future__ import annotations

from pathlib import Path
import unittest

from traceatlas.integrations.extreme_recon import catalog, inventory, summary
from traceatlas.integrations.registry import TOOLS

class ExtremeReconTests(unittest.TestCase):
    def test_all_45_sources_accounted_for(self):
        entries = catalog()
        self.assertEqual(len(entries), 45)
        self.assertEqual(len(set(e["id"] for e in entries)), 45)
        for kind, wanted in (("github_gitlink",33),("existing_vendor",1),
                             ("external_git_unpinned",1),("external_service",10)):
            self.assertEqual(sum(x["source_kind"] == kind for x in entries), wanted)
    def test_pinned_source_gitlinks_have_gitmodule_metadata(self):
        root = Path(__file__).resolve().parents[1]
        gm = (root / ".gitmodules").read_text(encoding="utf-8")
        for item in catalog():
            if item["source_kind"] == "github_gitlink":
                self.assertIn("path = " + item["source_path"], gm)
                self.assertIn("url = " + item["git_url"], gm)
                self.assertEqual(len(item["pinned_commit"]), 40)
    def test_commercial_services_cannot_claim_bundled_source(self):
        for item in catalog():
            if item["source_kind"] in ("external_service", "external_git_unpinned"):
                self.assertIsNone(item["pinned_commit"])
                self.assertIsNone(item["source_path"])
    def test_catalog_does_not_grant_execution_or_verify_providers(self):
        self.assertFalse(any(x["automatic_execution"] or x["live_verified"] for x in catalog()))
        self.assertFalse(any(x["runtime_tested_by_this_change"] for x in inventory()))
        self.assertEqual(summary()["unreviewed_execution_enabled"], 0)
        self.assertEqual(summary()["live_verified_new_providers"], 0)
    def test_existing_integrations_are_reused(self):
        selected=("amass", "subfinder", "theharvester", "dnsx", "httpx", "naabu",
                  "nuclei", "assetfinder", "uncover", "findomain", "dnsrecon",
                  "fierce", "gobuster")
        statuses={x["id"]:x["execution_status"] for x in inventory()}
        for key in selected:
            self.assertIn(key, TOOLS)
            self.assertEqual(statuses[key], "existing_governed_adapter")
        self.assertEqual(statuses["masscan"], "blocked")
        self.assertEqual(statuses["zmap"], "blocked")
    def test_traceatlas_cli_exposes_static_inventory(self):
        from traceatlas.cli import parser
        args=parser().parse_args(["integrations", "extreme", "--json"])
        self.assertEqual(args.integration_command, "extreme")
        self.assertTrue(args.json)

if __name__ == "__main__":
    unittest.main()
