"""Check that the directly tracked four source mirrors are byte-for-byte upstream."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import unittest

class DirectSourceMirrorTests(unittest.TestCase):
    def test_every_tracked_blob_matches_pinned_upstream(self):
        root=Path(__file__).resolve().parents[1]
        manifest=json.loads((root/"docs/integrations/EXTREME_RECON_VENDORED.json").read_text())
        self.assertEqual(len(manifest["projects"]),4)
        found=0
        for project in manifest["projects"]:
            prefix=root/"vendor_sources"/"extreme_recon"/project["key"]
            self.assertTrue((prefix/"LICENSE").is_file())
            expected={x["path"] for x in project["files"]}
            actual={p.relative_to(prefix).as_posix() for p in prefix.rglob("*") if p.is_file()}
            self.assertEqual(actual,expected)
            for item in project["files"]:
                data=(prefix/item["path"]).read_bytes()
                sha=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
                self.assertEqual(sha,item["sha"],(project["key"],item["path"]))
                self.assertEqual(len(data),item["size"])
                found+=1
        self.assertEqual(found,36)

if __name__ == "__main__":
    unittest.main()
