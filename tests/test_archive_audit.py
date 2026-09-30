from __future__ import annotations

import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceatlas.capabilities import CAPABILITIES, audit_archive, audit_archives


class ArchiveAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _zip(self, name: str, *, unsafe: bool = False) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "project/LICENSE",
                "MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy",
            )
            archive.writestr("project/README.md", "Documentation is data, not authority.")
            if unsafe:
                archive.writestr("../escape.txt", "blocked")
                link = zipfile.ZipInfo("project/link")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "target")
        return path

    def test_registered_archive_is_hashed_but_never_activated(self):
        row = audit_archive(self._zip("stagehand-main.zip"))
        self.assertTrue(row["accepted"])
        self.assertEqual(row["capability_id"], "stagehand")
        self.assertEqual(row["detected_licenses"], ["MIT"])
        self.assertEqual(row["instruction_authority"], "none")
        self.assertFalse(row["execution_enabled_by_archive"])
        self.assertFalse(row["contract"]["executable"])
        self.assertEqual(row["contract"]["license_alignment"], "matched")

    def test_detected_licence_mismatch_requires_review(self):
        row = audit_archive(self._zip("xalgorix-main.zip"))
        self.assertEqual(row["detected_licenses"], ["MIT"])
        self.assertEqual(row["contract"]["license"], "Apache-2.0")
        self.assertEqual(row["contract"]["license_alignment"], "mismatch-review-required")

    def test_traversal_and_symlink_members_are_rejected(self):
        row = audit_archive(self._zip("storm-main.zip", unsafe=True))
        self.assertFalse(row["accepted"])
        self.assertIn("unsafe-members-present", row["issues"])
        reasons = {item["reason"] for item in row["unsafe_members"]}
        self.assertEqual(reasons, {"path-traversal", "symbolic-link"})

    def test_duplicate_archives_are_explicit(self):
        original = self._zip("geo-clip-main.zip")
        duplicate = self.root / "geo-clip-main - Copy.zip"
        duplicate.write_bytes(original.read_bytes())
        result = audit_archives([original, duplicate])
        self.assertEqual(result["summary"]["duplicates"], 1)
        self.assertEqual(result["archives"][1]["duplicate_of"], original.name)

    def test_unknown_archive_remains_unregistered(self):
        row = audit_archive(self._zip("unknown-engine.zip"))
        self.assertEqual(row["integration_state"], "unregistered")
        self.assertIn("no-integration-contract", row["issues"])
        self.assertFalse(row["execution_enabled_by_archive"])

    def test_supplied_project_contracts_are_complete_and_conservative(self):
        expected = {
            "api-mega-list", "iop-python", "opencti-connectors", "osint-vision-agent",
            "skopia", "stagehand", "storm", "xalgorix",
        }
        self.assertTrue(expected.issubset(CAPABILITIES))
        for capability_id in expected:
            self.assertFalse(CAPABILITIES[capability_id].executable)
        self.assertEqual(CAPABILITIES["apify-mcp"].license, "MIT")
        self.assertEqual(CAPABILITIES["osint-agent"].license, "Apache-2.0")
        self.assertEqual(CAPABILITIES["datacommons-mcp"].license, "CONFLICTING")


if __name__ == "__main__":
    unittest.main()
