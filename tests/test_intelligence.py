from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.intelligence import IntelligenceAnalyzer, IntelligenceHub, MediaAnalyzer, SOURCES
from traceatlas.policy import PolicyError


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "cases.db")
        self.db.create_case("case-1", "Intelligence case", "Authorised defensive research")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_source_registry_has_requested_coverage(self):
        expected = {
            "linkedin", "instagram", "snapchat", "facebook", "tiktok", "youtube",
            "github", "discord", "shodan", "censys", "virustotal", "malwarebazaar",
            "business_registry", "employee_directory", "sanctions", "court_records",
        }
        self.assertEqual(expected, set(SOURCES))
        self.assertEqual(sum(item.live_connector for item in SOURCES.values()), 6)

    def test_personal_source_requires_consent_or_owned_org(self):
        source = self.root / "linkedin.json"
        source.write_text('[{"name":"Jane Example"}]', encoding="utf-8")
        with self.assertRaises(PolicyError):
            IntelligenceHub(self.db, self.root).ingest(
                "case-1", "linkedin", source, authorized=True
            )

    def test_ingest_redacts_contacts_and_secrets(self):
        source = self.root / "directory.json"
        source.write_text(json.dumps([{
            "name": "Jane Example", "job_title": "Analyst",
            "email": "jane@example.com", "phone": "+1 202 555 0100",
            "api_token": "must-not-survive", "home_address": "private",
            "latitude": 28.6139, "longitude": 77.2090,
        }]), encoding="utf-8")
        result = IntelligenceHub(self.db, self.root).ingest(
            "case-1", "employee_directory", source,
            authorized=True, owned_org=True,
        )
        events = self.db.spider_events(result["scan_id"])
        serialized = json.dumps(events)
        self.assertIn("Jane Example", serialized)
        self.assertIn("Analyst", serialized)
        self.assertNotIn("jane@example.com", serialized)
        self.assertNotIn("must-not-survive", serialized)
        self.assertNotIn('"private"', serialized)
        self.assertNotIn("28.6139", serialized)
        self.assertNotIn("77.209", serialized)
        self.assertGreaterEqual(result["stats"]["privacy"]["redacted"], 3)
        self.assertGreaterEqual(result["stats"]["privacy"]["removed"], 3)

    def test_public_record_requires_documented_basis(self):
        source = self.root / "court.json"
        source.write_text("[]", encoding="utf-8")
        with self.assertRaises(PolicyError):
            IntelligenceHub(self.db, self.root).ingest(
                "case-1", "court_records", source, authorized=True
            )

    def test_github_live_connector_normalizes_public_api_result(self):
        requested = {}

        def requester(url, headers, timeout):
            requested.update({"url": url, "headers": headers, "timeout": timeout})
            return 200, json.dumps({
                "login": "example", "name": "Example User", "email": "hidden@example.com",
                "bio": "Researcher", "public_repos": 12,
            }).encode()

        result = IntelligenceHub(self.db, self.root, requester=requester).collect(
            "case-1", "github", "username", "example",
            authorized=True, subject_consent=True,
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(requested["url"], "https://api.github.com/users/example")
        events = json.dumps(self.db.spider_events(result["scan_id"]))
        self.assertIn("CODE_PROFILE", events)
        self.assertNotIn("hidden@example.com", events)

    def test_internet_intelligence_rejects_private_ip(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test"}):
            with self.assertRaises(PolicyError):
                IntelligenceHub(self.db, self.root, requester=lambda *_: (200, b"{}" )).collect(
                    "case-1", "shodan", "ip", "127.0.0.1",
                    authorized=True, owned_asset=True,
                )

    def test_analysis_separates_facts_and_inferences(self):
        source = self.root / "business.json"
        source.write_text('[{"company":"Example Ltd","status":"active"}]', encoding="utf-8")
        result = IntelligenceHub(self.db, self.root).ingest(
            "case-1", "business_registry", source,
            authorized=True, public_record_basis=True,
        )
        summary = IntelligenceAnalyzer(self.db).analyze(result["scan_id"])
        self.assertEqual(summary["inferences"], [])
        self.assertEqual(len(summary["observed_facts"]), 1)
        self.assertFalse(summary["ai_analysis"]["enabled"])

    def test_ollama_must_use_loopback(self):
        source = self.root / "business.json"
        source.write_text('[{"company":"Example Ltd"}]', encoding="utf-8")
        result = IntelligenceHub(self.db, self.root).ingest(
            "case-1", "business_registry", source,
            authorized=True, public_record_basis=True,
        )
        analyzer = IntelligenceAnalyzer(self.db, requester=lambda *_: (200, b'{}'))
        with self.assertRaises(PolicyError):
            analyzer.analyze(result["scan_id"], use_ollama=True, base_url="https://example.com")

    def test_media_analysis_records_hash_without_tools(self):
        image = self.root / "evidence.png"
        image.write_bytes(b"\x89PNG\r\n\x1a\nminimal-test")
        with patch.object(MediaAnalyzer, "capabilities", return_value={
            "exiftool": False, "ffprobe": False, "tesseract": False, "whisper": False,
        }):
            result = MediaAnalyzer(self.db, self.root).analyze(
                "case-1", image, authorized=True, owned_asset=True
            )
        self.assertEqual(result["status"], "completed")
        events = self.db.spider_events(result["scan_id"])
        self.assertEqual(events[1]["event_type"], "MEDIA_METADATA")
        self.assertEqual(len(events[1]["data"]["sha256"]), 64)

    def test_media_analysis_requires_consent_or_ownership(self):
        image = self.root / "evidence.png"
        image.write_bytes(b"\x89PNG\r\n\x1a\nminimal-test")
        with self.assertRaises(PolicyError):
            MediaAnalyzer(self.db, self.root).analyze(
                "case-1", image, authorized=True
            )

    def test_media_perceptual_hashes_are_local_similarity_hints(self):
        if not MediaAnalyzer.capabilities().get("pillow"):
            self.skipTest("Pillow is optional")
        image = self.root / "pixel.png"
        image.write_bytes(base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
        ))
        hashes = MediaAnalyzer._perceptual_hashes(image)
        self.assertEqual(len(hashes["average_hash"]), 16)
        self.assertEqual(len(hashes["difference_hash"]), 16)
        self.assertIn("not proof", hashes["purpose"])


if __name__ == "__main__":
    unittest.main()
