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
        self.assertTrue(expected.issubset(SOURCES))
        self.assertTrue({"rdap", "dns", "wayback", "internetdb", "bluesky"}.issubset(SOURCES))
        self.assertTrue({"gitlab", "hackernews", "nvd"}.issubset(SOURCES))
        self.assertTrue({"mastodon", "stackexchange", "dockerhub", "npm", "crossref", "orcid"}.issubset(SOURCES))
        self.assertTrue({"ipwhois", "ipdata", "greynoise"}.issubset(SOURCES))
        self.assertIn("urlscan", SOURCES)
        self.assertEqual(sum(item.live_connector for item in SOURCES.values()), 34)

    def test_new_ip_context_connectors_enforce_scope_and_validate_contracts(self):
        fixtures = {
            "ipwhois": {"ip": "8.8.8.8", "success": True, "country_code": "US"},
            "ipdata": {"ip": "8.8.8.8", "asn": {"asn": "AS15169"}},
            "greynoise": {"ip": "8.8.8.8", "noise": False, "riot": True,
                          "classification": "benign", "message": "Success"},
        }
        for source, fixture in fixtures.items():
            with self.subTest(source=source), patch.dict("os.environ", {"IPDATA_API_KEY": "test-key"}):
                requested = {}
                def requester(url, headers, timeout):
                    requested.update({"url": url, "headers": headers, "timeout": timeout})
                    return 200, json.dumps(fixture).encode()
                result = IntelligenceHub(self.db, self.root, requester=requester).collect(
                    "case-1", source, "ip", "8.8.8.8", authorized=True, owned_asset=True,
                )
                self.assertEqual(result["status"], "completed")
                self.assertEqual(requested["timeout"], 30)
                self.assertTrue(requested["url"].startswith("https://"))
        for source in fixtures:
            with self.subTest(private_source=source), self.assertRaises(PolicyError):
                IntelligenceHub(self.db, self.root, requester=lambda *_: (200, b"{}")).collect(
                    "case-1", source, "ip", "127.0.0.1", authorized=True, owned_asset=True,
                )

    def test_new_ip_connectors_fail_closed_without_key_or_on_schema_drift(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaisesRegex(
            PolicyError, "IPDATA_API_KEY is required"
        ):
            IntelligenceHub(self.db, self.root).collect(
                "case-1", "ipdata", "ip", "8.8.8.8", authorized=True, owned_asset=True,
            )
        with self.assertRaisesRegex(Exception, "provider_schema_mismatch"):
            IntelligenceHub(self.db, self.root, requester=lambda *_: (200, b'{"ip":"8.8.8.8"}'),
                            sleeper=lambda _: None).collect(
                "case-1", "greynoise", "ip", "8.8.8.8", authorized=True, owned_asset=True,
            )
        with self.assertRaisesRegex(Exception, "provider_record_not_found"):
            IntelligenceHub(self.db, self.root, requester=lambda *_: (
                200, b'{"success":false,"message":"Reserved range"}'
            ), sleeper=lambda _: None).collect(
                "case-1", "ipwhois", "ip", "8.8.8.8", authorized=True, owned_asset=True,
            )

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
