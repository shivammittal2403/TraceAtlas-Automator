from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "integrations" / "osint-tool-typescript"
MANIFEST = ROOT / "integrations" / "osint-tool-typescript.traceatlas-manifest.json"


class OsintToolTypescriptIntegrationTests(unittest.TestCase):
    def test_snapshot_is_preserved_under_integration_boundary(self):
        self.assertTrue(INTEGRATION.is_dir())
        self.assertTrue((INTEGRATION / "package.json").is_file())
        self.assertTrue((INTEGRATION / "pnpm-workspace.yaml").is_file())
        self.assertTrue((INTEGRATION / "packages" / "schemas" / "src" / "evidence.ts").is_file())
        self.assertFalse((ROOT / "services" / "core" / "src" / "routes" / "case.routes.ts").exists())

    def test_manifest_matches_files(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        files = sorted(path for path in INTEGRATION.rglob("*") if path.is_file())

        self.assertEqual(manifest["integration"], "osint-tool-typescript")
        self.assertEqual(manifest["source_archive"], "OSINT_Tool-main(2).zip")
        self.assertEqual(manifest["file_count"], len(files))
        self.assertEqual(manifest["total_bytes"], sum(path.stat().st_size for path in files))

        recorded = {item["path"]: item for item in manifest["files"]}
        self.assertEqual(len(recorded), len(files))
        for path in files:
            relative = path.relative_to(INTEGRATION).as_posix()
            self.assertEqual(recorded[relative]["size"], path.stat().st_size)
            self.assertEqual(recorded[relative]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
