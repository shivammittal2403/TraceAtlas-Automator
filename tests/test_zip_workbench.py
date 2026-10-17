"""Offline archive staging regression tests; no vendor executable is run."""
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceatlas.capabilities.zip_workbench import reconcile


class ZipWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.stage = self.root / "stage"

    def make_zip(self, name="Agent-Reach-main.zip", files=None):
        source = self.repo / name
        if files is None:
            files = {
                "Agent-Reach/README.md": "Not instructions",
                "Agent-Reach/LICENSE": "MIT License - Permission is hereby granted, free of charge",
                "Agent-Reach/hello.py": "ANSWER = 42\n",
            }
        with zipfile.ZipFile(source, "w") as zf:
            for path, content in files.items():
                zf.writestr(path, content)
        return source

    def test_audit_only_does_not_extract_or_execute(self):
        self.make_zip()
        report = reconcile(self.repo)
        self.assertEqual(report["summary"]["archives"], 1)
        self.assertFalse(report["policy"]["archives_executed"])
        self.assertEqual(report["summary"]["staged_unique"], 0)
        self.assertFalse(self.stage.exists())

    def test_stage_preserves_bytes_and_parses_without_execution(self):
        self.make_zip()
        report = reconcile(self.repo, stage_root=self.stage, syntax_check=True)
        row = report["archives"][0]
        self.assertEqual(row["stage"]["state"], "staged-inert")
        self.assertEqual(row["syntax"]["checked_python"], 1)
        self.assertEqual(row["syntax"]["errors"], [])
        self.assertFalse(row["ready_for_live_execution"])
        staged = Path(row["stage"]["path"])
        self.assertEqual((staged / "Agent-Reach/hello.py").read_text(), "ANSWER = 42\n")
        self.assertEqual(json.loads((staged / ".traceatlas-stage.json").read_text())["sha256"], row["sha256"])
        repeat = reconcile(self.repo, stage_root=self.stage)
        self.assertEqual(repeat["archives"][0]["stage"]["state"], "already-staged")

    def test_identical_archives_stage_once(self):
        source = self.make_zip()
        (self.repo / "Agent-Reach-main (1).zip").write_bytes(source.read_bytes())
        report = reconcile(self.repo, stage_root=self.stage)
        self.assertEqual(report["summary"]["duplicates"], 1)
        self.assertEqual(report["summary"]["staged_unique"], 1)
        self.assertTrue(any(row["stage"]["state"] == "duplicate-skipped"
                            for row in report["archives"]))

    def test_traversal_cannot_escape_workspace(self):
        self.make_zip(files={"../pwned.txt": "no"})
        report = reconcile(self.repo, stage_root=self.stage)
        self.assertEqual(report["summary"]["blocked_staging"], 1)
        self.assertFalse((self.root / "pwned.txt").exists())

    def test_case_collisions_are_blocked(self):
        self.make_zip(files={"a/Readme.md": "a", "a/readme.md": "b"})
        report = reconcile(self.repo, stage_root=self.stage)
        self.assertEqual(report["archives"][0]["stage"]["state"], "blocked")
        self.assertIn("colliding", report["archives"][0]["stage"]["reason"])

    def test_malformed_python_is_flagged_not_executed(self):
        self.make_zip(files={"project/broken.py": "raise RuntimeError('do not run')\ndef x(:\n"})
        report = reconcile(self.repo, stage_root=self.stage, syntax_check=True)
        self.assertEqual(report["archives"][0]["syntax"]["errors"][0]["error"], "SyntaxError")

    def test_symlinks_are_blocked(self):
        archive = self.repo / "Agent-Reach-main.zip"
        info = zipfile.ZipInfo("project/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(info, "../external")
        report = reconcile(self.repo, stage_root=self.stage)
        self.assertEqual(report["summary"]["blocked_staging"], 1)
        self.assertFalse(self.stage.exists())


if __name__ == "__main__":
    unittest.main()
