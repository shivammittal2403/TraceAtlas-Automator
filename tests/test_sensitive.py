from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.policy import PolicyError
from traceatlas.report import build_report
from traceatlas.sensitive import SensitiveRunner


PURPOSE = "Authorized defensive exposure review"


class SensitiveWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "cases"
        self.db = CaseDB(self.workspace / "traceatlas.db")
        self.db.create_case("case-1", "Sensitive test", PURPOSE)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def runner(self, fake_http):
        return SensitiveRunner(self.db, self.workspace, http_get=fake_http)

    def test_two_step_consent_and_owner_attestation_are_required(self):
        runner = self.runner(lambda *_: (200, b""))
        with self.assertRaisesRegex(PolicyError, "both --authorized and --allow-sensitive"):
            runner.darkweb_monitor(
                "case-1", "example.com", lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=False, owned_domain=True,
                index_file=None, live_ahmia=True, authorized_feed=False,
                source_permission=True,
            )
        with self.assertRaisesRegex(PolicyError, "owned_domain"):
            runner.darkweb_monitor(
                "case-1", "example.com", lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=True, owned_domain=False,
                index_file=None, live_ahmia=True, authorized_feed=False,
                source_permission=True,
            )
        self.assertEqual(self.db.sensitive_audits("case-1"), [])

    def test_darkweb_uses_clearweb_index_and_redacts_onion_and_target(self):
        requested = []

        def fake_http(url, headers, timeout):
            requested.append(url)
            return 200, (
                b'<a href="http://abcdefghijklmnop.onion/post">'
                b'Example.com exposure at abcdefghijklmnop.onion</a>'
            )

        result = self.runner(fake_http).darkweb_monitor(
            "case-1", "example.com", lawful_purpose=PURPOSE,
            authorized=True, allow_sensitive=True, owned_domain=True,
            index_file=None, live_ahmia=True, authorized_feed=False,
            source_permission=True,
        )
        self.assertEqual(result["results"], 1)
        self.assertTrue(requested[0].startswith("https://ahmia.fi/search/"))
        events = self.db.spider_events(result["scan_id"])
        serialized = json.dumps(events).lower()
        self.assertNotIn("example.com", serialized)
        self.assertNotIn("abcdefghijklmnop.onion", serialized)
        self.assertNotIn("exposure at", serialized)
        self.assertTrue(events[1]["data"]["target_mentioned"])
        self.assertIn("title_sha256", events[1]["data"])
        self.assertIn("onion-not-fetched", serialized)
        repeated = self.runner(fake_http).darkweb_monitor(
            "case-1", "example.com", lawful_purpose=PURPOSE,
            authorized=True, allow_sensitive=True, owned_domain=True,
            index_file=None, live_ahmia=True, authorized_feed=False,
            source_permission=True,
        )
        self.assertTrue(result["changed"])
        self.assertFalse(repeated["changed"])

    def test_darkweb_can_parse_approved_export_without_network(self):
        export = self.root / "approved-index.html"
        export.write_text(
            '<a href="http://abcdefghijklmnop.onion/">Example.com alert</a>',
            encoding="utf-8",
        )

        def no_network(*_):
            self.fail("Offline index mode must not make a network request")

        result = self.runner(no_network).darkweb_monitor(
            "case-1", "example.com", lawful_purpose=PURPOSE,
            authorized=True, allow_sensitive=True, owned_domain=True,
            index_file=export, live_ahmia=False, authorized_feed=True,
            source_permission=False,
        )
        event = self.db.spider_events(result["scan_id"])[1]
        self.assertIn("approved-index-export", event["tags"])

    def test_account_breach_check_uses_email_k_anonymity(self):
        email = "analyst@example.com"
        digest = hashlib.sha1(email.encode()).hexdigest().upper()
        seen = []

        def fake_http(url, headers, timeout):
            seen.append((url, headers))
            body = [
                {"hashSuffix": "F" * 34, "websites": ["DiscardThisRangeResult"]},
                {"hashSuffix": digest[6:], "websites": ["ExampleBreach"]},
            ]
            return 200, json.dumps(body).encode()

        with patch.dict(os.environ, {"HIBP_API_KEY": "A" * 32}):
            result = self.runner(fake_http).breach_account(
                "case-1", email, lawful_purpose=f"Authorized check for {email}",
                authorized=True, allow_sensitive=True, subject_consent=True,
            )
        self.assertEqual(result["status"], "completed")
        self.assertIn(digest[:6], seen[0][0])
        self.assertNotIn(email, seen[0][0])
        events = self.db.spider_events(result["scan_id"])
        serialized = json.dumps(events)
        self.assertNotIn(email, serialized)
        self.assertIn("ExampleBreach", serialized)
        self.assertNotIn("DiscardThisRangeResult", serialized)
        report = build_report(self.db, "case-1")
        self.assertEqual(report["sensitive_audits"][0]["workflow"], "breach-account")
        self.assertNotIn(email, report["sensitive_audits"][0]["lawful_purpose"])

    def test_verified_domain_aliases_are_hashed_before_storage(self):
        domain = "example.com"
        runner = self.runner(lambda *_: (200, b'{"alice":["ExampleBreach"]}'))
        with self.assertRaisesRegex(PolicyError, "hibp_domain_verified"):
            runner.breach_domain(
                "case-1", domain, lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=True, owned_domain=True,
                hibp_domain_verified=False,
            )
        with patch.dict(os.environ, {"HIBP_API_KEY": "B" * 32}):
            result = runner.breach_domain(
                "case-1", domain, lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=True, owned_domain=True,
                hibp_domain_verified=True,
            )
        serialized = json.dumps(self.db.spider_events(result["scan_id"]))
        self.assertNotIn("alice", serialized)
        self.assertNotIn(domain, serialized)
        self.assertIn("alias_sha256", serialized)
        self.assertIn("ExampleBreach", serialized)

    def test_password_check_accepts_hash_only(self):
        runner = self.runner(lambda *_: (200, b""))
        with self.assertRaisesRegex(PolicyError, "never a plaintext password"):
            runner.password_hash_check(
                "case-1", "correct horse battery staple", lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=True, owned_account=True,
            )

        digest = "A" * 40
        suffix = digest[5:]
        def fake_http(url, headers, timeout):
            self.assertNotIn("AddPadding", url)
            self.assertEqual(headers["Add-Padding"], "true")
            return 200, f"{suffix}:42\n".encode()

        runner = self.runner(fake_http)
        result = runner.password_hash_check(
            "case-1", digest, lawful_purpose=PURPOSE,
            authorized=True, allow_sensitive=True, owned_account=True,
        )
        exposure = self.db.spider_events(result["scan_id"])[1]["data"]
        self.assertEqual(exposure["exposure_count"], 42)
        self.assertNotEqual(exposure["sha1_fingerprint"], digest)

    def test_person_profile_is_limited_to_public_professional_candidates(self):
        def fake_http(url, headers, timeout):
            self.assertIn("api.crossref.org/works", url)
            return 200, json.dumps({
                "message": {"items": [{
                    "DOI": "10.1000/example", "title": ["Research article"],
                    "published": {"date-parts": [[2025]]},
                }]}
            }).encode()

        with patch.dict(os.environ, {"ORCID_ACCESS_TOKEN": ""}):
            result = self.runner(fake_http).person_profile(
                "case-1", "Jane Example", lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=True, subject_consent=True,
            )
        events = self.db.spider_events(result["scan_id"])
        self.assertEqual(events[1]["event_type"], "PUBLICATION_CANDIDATE")
        self.assertIn("candidate-not-identity", events[1]["tags"])
        self.assertNotIn("Jane Example", json.dumps(events))

    def test_wifi_retains_coarse_location_and_hashed_bssid(self):
        bssid = "00:11:22:33:44:55"

        def fake_http(url, headers, timeout):
            self.assertIn("api.wigle.net", url)
            self.assertTrue(headers["Authorization"].startswith("Basic "))
            return 200, json.dumps({"results": [{
                "netid": bssid, "ssid": "Private network",
                "trilat": 28.6139, "trilong": 77.2090,
                "city": "Delhi", "region": "Delhi", "country": "IN",
                "lastupdt": "2026-01-01", "encryption": "WPA2",
            }]}).encode()

        with patch.dict(os.environ, {
            "WIGLE_API_NAME": "test-name", "WIGLE_API_TOKEN": "test-token",
        }):
            result = self.runner(fake_http).wifi_locate(
                "case-1", bssid, lawful_purpose=PURPOSE,
                authorized=True, allow_sensitive=True, owned_asset=True,
            )
        events = self.db.spider_events(result["scan_id"])
        location = events[1]["data"]
        self.assertEqual(location["latitude_coarse"], 28.61)
        self.assertEqual(location["longitude_coarse"], 77.21)
        self.assertNotIn("ssid", location)
        self.assertNotIn(bssid, json.dumps(events))

    def test_breach_artifact_never_copies_rows_or_column_names(self):
        source = self.root / "authorized.csv"
        source.write_text(
            "email,password,name\nsecret@example.com,do-not-store,Alice\n",
            encoding="utf-8",
        )
        result = self.runner(lambda *_: (500, b"")).breach_artifact(
            "case-1", source, lawful_purpose=PURPOSE,
            authorized=True, allow_sensitive=True, authorized_data=True,
        )
        event = self.db.spider_events(result["scan_id"])[1]
        self.assertEqual(event["data"]["rows_sampled"], 1)
        self.assertEqual(event["data"]["column_count"], 3)
        self.assertEqual(event["data"]["sensitive_column_count"], 2)
        self.assertNotIn("columns", event["data"])

        evidence_text = "\n".join(
            Path(item["path"]).read_text(encoding="utf-8")
            for item in self.db.evidence("case-1")
        )
        self.assertNotIn("secret@example.com", evidence_text)
        self.assertNotIn("do-not-store", evidence_text)
        self.assertNotIn("password", evidence_text)


if __name__ == "__main__":
    unittest.main()
