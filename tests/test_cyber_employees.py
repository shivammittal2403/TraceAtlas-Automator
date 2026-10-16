"""Adversarial regressions for the fourteen supplied-record cyber engines."""
import copy
import json
import unittest

from traceatlas.workforce.discipline_engines import invoke_employee
from traceatlas.workforce.discipline_engines.common import make_context


AS_OF = "2026-01-15T12:00:00+00:00"
EVIDENCE_IDS = ("evidence-cyber-fixture",)
SHA256 = "a" * 64


class CyberEmployeeTests(unittest.TestCase):
    def payload(self, label, rows, *, sources=None, parameters=None):
        records = []
        for index, entry in enumerate(rows, 1):
            source_id, data = entry if isinstance(entry, tuple) else ("S1", entry)
            records.append({
                "record_id": f"R{index}",
                "source_id": source_id,
                "data": copy.deepcopy(data),
            })
        if sources is None:
            sources = [
                {"source_id": source_id, "uri": f"urn:fixture:{source_id}"}
                for source_id in sorted({row["source_id"] for row in records})
            ]
        return {
            "case_id": "case-cyber-fixture",
            "task_id": "task-cyber-fixture",
            "discipline": label,
            "objective": "Review supplied synthetic cyber records",
            "as_of": AS_OF,
            "sources": copy.deepcopy(sources),
            "records": records,
            "parameters": copy.deepcopy(parameters or {}),
        }

    def assert_bound(self, result, payload):
        records = {row["record_id"]: row for row in payload["records"]}
        seen = set()
        for finding in result["findings"]:
            self.assertNotIn(finding["finding_id"], seen)
            seen.add(finding["finding_id"])
            refs = finding["record_ids"]
            self.assertTrue(refs)
            self.assertEqual(len(refs), len(set(refs)))
            self.assertTrue(set(refs).issubset(records))
            self.assertEqual(
                set(finding["source_ids"]),
                {records[ref]["source_id"] for ref in refs},
            )
            self.assertEqual(finding["canonical_evidence_ids"], list(EVIDENCE_IDS))
        for issue in result["issues"]:
            if issue["record_id"] is not None:
                self.assertIn(issue["record_id"], records)

    def analyze(self, label, rows, **kwargs):
        payload = self.payload(label, rows, **kwargs)
        result = invoke_employee(payload, evidence_ids=EVIDENCE_IDS)
        self.assert_bound(result, payload)
        return result

    def finding(self, result, kind, record_id=None):
        matches = [
            finding for finding in result["findings"]
            if finding["kind"] == kind
            and (record_id is None or record_id in finding["record_ids"])
        ]
        self.assertEqual(len(matches), 1, matches)
        return matches[0]

    def assert_rejected_record(self, result, record_id):
        self.assertFalse(any(
            record_id in finding["record_ids"] for finding in result["findings"]
        ))
        self.assertTrue(any(
            issue["record_id"] == record_id for issue in result["issues"]
        ))

    @staticmethod
    def failure(account="alice", ip="192.0.2.10"):
        return {
            "format": "structured",
            "event": {
                "timestamp": AS_OF,
                "event_type": "authentication",
                "account": account,
                "src_ip": ip,
                "outcome": "failure",
            },
        }

    @staticmethod
    def vulnerability(**changes):
        value = {
            "asset_id": "asset-1",
            "product": "Widget",
            "installed_version": "2.0",
            "cve_id": "CVE-2026-12345",
            "affected_product": "Widget",
            "affected_from": "2.0",
            "fixed_version": "3.0",
        }
        value.update(changes)
        return value

    def test_all_fourteen_handlers_are_deterministic_and_source_bound(self):
        fixtures = {
            "IOCINT": (
                [{"indicator_type": "domain", "value": "example.org"}],
                "indicator_correlation",
            ),
            "VULNINT": ([self.vulnerability()], "vulnerability_applicability"),
            "EXPLOITINT": (
                [{"cve_id": "CVE-2026-12345", "public_poc": True}],
                "exploit_report",
            ),
            "CYBINT": (
                [{
                    "asset_id": "asset-1", "internet_exposed": True,
                    "criticality": "high", "controls": {"mfa": False},
                }],
                "cyber_asset_posture",
            ),
            "CTI": (
                [{
                    "report_id": "report-1", "indicators": [],
                    "techniques": ["T1059.001"],
                }],
                "threat_report",
            ),
            "TTPINT": (
                [{
                    "technique_id": "T1059.001",
                    "procedure": "Supplied report describes PowerShell execution",
                    "attack_version": "16.1",
                }],
                "technique_procedure",
            ),
            "THREATACTORINT": (
                [{"provider": "Vendor A", "actor_label": "Crow", "aliases": []}],
                "actor_label_assertion",
            ),
            "CAMPAIGNINT": (
                [{
                    "campaign_id": "campaign-1",
                    "start_at": "2026-01-01T00:00:00+00:00",
                    "end_at": "2026-01-10T00:00:00+00:00",
                }],
                "campaign_window",
            ),
            "MALINT": (
                [{
                    "file_name": "fixture.bin", "file_size": 42,
                    "hashes": {"sha256": SHA256},
                    "imports": ["CreateRemoteThread"],
                }],
                "static_file_profile",
            ),
            "INCIDENTINT": (
                [{
                    "incident_id": "incident-1", "event_id": "event-1",
                    "event_type": "authentication", "timestamp": AS_OF,
                }],
                "incident_timeline",
            ),
            "LOGINT": (
                [self.failure(), self.failure(), self.failure()],
                "authentication_failure_cluster",
            ),
            "DFIRINT": (
                [{
                    "artifact_id": "artifact-1", "sha256": SHA256,
                    "timestamps": {"collected": AS_OF},
                }],
                "forensic_artifact_metadata",
            ),
            "HUNTINT": (
                [{
                    "record_type": "hypothesis", "hypothesis_id": "hunt-1",
                    "description": "Review supplied administrative events",
                    "selector": {"admin": True},
                }],
                "hunt_hypothesis",
            ),
            "DETECTIONINT": (
                [{
                    "record_type": "rule", "rule_id": "rule-1",
                    "selector": {"admin": True}, "enabled": True,
                }, {
                    "record_type": "test_event", "event_id": "event-1",
                    "fields": {"admin": True}, "expected_rule_ids": ["rule-1"],
                }],
                "detection_rule_evaluation",
            ),
        }
        self.assertEqual(len(fixtures), 14)
        for label, (rows, kind) in fixtures.items():
            with self.subTest(label=label):
                payload = self.payload(label, rows)
                original = copy.deepcopy(payload)
                first = invoke_employee(payload, evidence_ids=EVIDENCE_IDS)
                second = invoke_employee(payload, evidence_ids=EVIDENCE_IDS)
                self.assertEqual(payload, original)
                self.assertEqual(first, second)
                self.assert_bound(first, payload)
                self.assertTrue(any(f["kind"] == kind for f in first["findings"]))

    def test_ioc_defanging_merges_observable_without_hiding_verdict_conflict(self):
        result = self.analyze("IOCINT", [
            {"indicator_type": "domain", "value": "Example[.]ORG", "verdict": "malicious"},
            {"indicator_type": "domain", "value": "example.org", "verdict": "benign"},
            {"indicator_type": "url", "value": "hxxps://EXAMPLE[.]ORG/a"},
        ])
        indicators = result["artifacts"]["indicators"]
        domain = next(row for row in indicators if row["indicator_type"] == "domain")
        self.assertEqual(domain["value"], "example.org")
        self.assertEqual(set(domain["record_ids"]), {"R1", "R2"})
        self.assertEqual(set(domain["verdicts"]), {"malicious", "benign"})
        self.assertTrue(domain["conflicting_verdicts"])
        self.assertTrue(any(
            row["indicator_type"] == "url" and row["value"] == "https://example.org/a"
            for row in indicators
        ))

    def test_ioc_rejects_invalid_ipv4_and_credential_urls(self):
        result = self.analyze("IOCINT", [
            {"indicator_type": "ipv4", "value": "999.1.2.3"},
            {"indicator_type": "url", "value": "https://user:pass@example.org/a"},
        ])
        self.assert_rejected_record(result, "R1")
        self.assert_rejected_record(result, "R2")
        self.assertEqual(result["artifacts"]["indicators"], [])

    def test_ioc_rejects_invalid_unquoted_email_dot_placement(self):
        rows = [
            {"indicator_type": "email", "value": local + "@example.org"}
            for local in (".", ".alice", "alice.", "alice..bob")
        ]
        result = self.analyze("IOCINT", rows)
        for index in range(1, 5):
            self.assert_rejected_record(result, f"R{index}")
        self.assertEqual(result["artifacts"]["indicators"], [])

    def test_vulnerability_declared_range_boundaries_and_unknown_versions(self):
        cases = [
            ({"installed_version": "1.9"}, "outside_declared_range"),
            ({"installed_version": "2.0"}, "affected_by_declared_range"),
            ({"installed_version": "2.9"}, "affected_by_declared_range"),
            ({"installed_version": "3.0"}, "outside_declared_range"),
            ({"product": "Different Product"}, "product_mismatch"),
            ({"installed_version": "2.0rc1"}, "unknown"),
        ]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                result = self.analyze("VULNINT", [self.vulnerability(**changes)])
                finding = self.finding(result, "vulnerability_applicability", "R1")
                self.assertEqual(finding["data"]["applicability"], expected)
        missing = self.vulnerability()
        del missing["installed_version"]
        result = self.analyze("VULNINT", [missing])
        self.assertEqual(
            self.finding(result, "vulnerability_applicability")["data"]["applicability"],
            "unknown",
        )

    def test_public_exploit_report_does_not_establish_asset_exploitability(self):
        result = self.analyze("EXPLOITINT", [{
            "cve_id": "CVE-2026-12345", "public_poc": True,
            "exploitation_reported": True,
            "asset_product": "Different Product", "affected_product": "Widget",
            "installed_version": "2.0", "affected_from": "2.0", "fixed_version": "3.0",
        }])
        data = self.finding(result, "exploit_report")["data"]
        self.assertEqual(data["applicability"], "product_mismatch")
        self.assertEqual(data["exploitability"], "not_determined")

    def test_cyber_posture_distinguishes_failed_and_missing_controls(self):
        result = self.analyze("CYBINT", [{
            "asset_id": "asset-1", "internet_exposed": True, "criticality": "high",
            "controls": {"mfa": False, "logging": True},
        }])
        data = self.finding(result, "cyber_asset_posture")["data"]
        self.assertIn("mfa", data["failed_controls"])
        self.assertNotIn("logging", data["failed_controls"])
        self.assertIn("backups", data["missing_controls"])
        self.assertNotIn("mfa", data["missing_controls"])
        self.assertEqual(data["priority"], "review_high")

    def test_cyber_posture_rejects_truthy_non_booleans(self):
        for changes in ({"internet_exposed": 1}, {"controls": {"mfa": "false"}}):
            with self.subTest(changes=changes):
                record = {
                    "asset_id": "asset-1", "internet_exposed": True,
                    "criticality": "high", "controls": {"mfa": False},
                    **changes,
                }
                self.assert_rejected_record(self.analyze("CYBINT", [record]), "R1")

    def test_cti_expiration_and_future_publication_use_supplied_as_of(self):
        rows = [
            {"report_id": "current", "published_at": "2026-01-01T00:00:00+00:00",
             "valid_until": "2026-02-01T00:00:00+00:00", "indicators": [],
             "techniques": ["T1059.001"]},
            {"report_id": "expired", "published_at": "2026-01-01T00:00:00+00:00",
             "valid_until": "2026-01-10T00:00:00+00:00", "indicators": [],
             "techniques": ["T1059.001"]},
            {"report_id": "future", "published_at": "2026-02-01T00:00:00+00:00",
             "indicators": [], "techniques": ["T1059.001"]},
        ]
        result = self.analyze("CTI", rows)
        for index, expected in enumerate(("current", "expired", "future_dated"), 1):
            self.assertEqual(
                self.finding(result, "threat_report", f"R{index}")["data"]["temporal_status"],
                expected,
            )

    def test_cti_republication_does_not_inflate_declared_origin_count(self):
        sources = [
            {"source_id": "S1", "uri": "urn:fixture:one", "original_source_id": "origin-1"},
            {"source_id": "S2", "uri": "urn:fixture:two", "original_source_id": "origin-1"},
        ]
        rows = [
            ("S1", {"report_id": "one", "indicators": [{"type": "domain", "value": "Example[.]ORG"}],
                    "techniques": []}),
            ("S2", {"report_id": "two", "indicators": [{"type": "domain", "value": "example.org"}],
                    "techniques": []}),
        ]
        result = self.analyze("CTI", rows, sources=sources)
        support = result["artifacts"]["indicator_support"]
        self.assertEqual(len(support), 1)
        self.assertEqual(support[0]["declared_origin_count"], 1)
        self.assertIs(support[0]["independence_verified"], False)

    def test_ttp_mapping_stays_unverified_and_missing_version_is_visible(self):
        result = self.analyze("TTPINT", [{
            "technique_id": "T1059.001",
            "procedure": "Supplied description states PowerShell execution",
        }])
        self.assertIs(
            self.finding(result, "technique_procedure")["data"]["mapping_verified"], False
        )
        self.assertTrue(any(issue["code"] == "unversioned_mapping" for issue in result["issues"]))

    def test_actor_labels_are_provider_scoped_and_do_not_merge_by_name(self):
        result = self.analyze("THREATACTORINT", [
            {"provider": "Vendor A", "actor_label": "Crow", "aliases": ["Bird"]},
            {"provider": "Vendor B", "actor_label": "Crow", "aliases": ["Bird"]},
        ])
        assertions = [f for f in result["findings"] if f["kind"] == "actor_label_assertion"]
        self.assertEqual(len(assertions), 2)
        self.assertTrue(all(f["data"]["attribution_verified"] is False for f in assertions))
        self.assertEqual(result["artifacts"]["candidate_links"], [])

    def test_actor_shared_indicator_creates_only_a_candidate_link(self):
        result = self.analyze("THREATACTORINT", [
            {"provider": "Vendor A", "actor_label": "Crow",
             "indicators": [{"type": "domain", "value": "Example[.]ORG"}]},
            {"provider": "Vendor B", "actor_label": "Raven",
             "indicators": [{"type": "domain", "value": "example.org"}]},
        ])
        self.assertEqual(len(result["artifacts"]["candidate_links"]), 1)
        self.assertEqual(len([
            f for f in result["findings"] if f["kind"] == "actor_label_assertion"
        ]), 2)

    def test_campaign_shared_indicator_requires_overlapping_windows(self):
        base = {
            "indicators": [{"type": "domain", "value": "example.org"}],
            "techniques": [],
        }
        first = {**base, "campaign_id": "one",
                 "start_at": "2026-01-01T00:00:00+00:00",
                 "end_at": "2026-01-10T00:00:00+00:00"}
        overlap = {**base, "campaign_id": "two",
                   "start_at": "2026-01-05T00:00:00+00:00",
                   "end_at": "2026-01-15T00:00:00+00:00"}
        separate = {**base, "campaign_id": "three",
                    "start_at": "2026-02-01T00:00:00+00:00",
                    "end_at": "2026-02-10T00:00:00+00:00"}
        result = self.analyze("CAMPAIGNINT", [first, overlap])
        links = result["artifacts"]["candidate_links"]
        self.assertEqual(len(links), 1)
        self.assertIs(links[0]["candidate_only"], True)
        result = self.analyze("CAMPAIGNINT", [first, separate])
        self.assertEqual(result["artifacts"]["candidate_links"], [])

    def test_static_file_profile_does_not_verify_content_or_infer_malware(self):
        result = self.analyze("MALINT", [{
            "file_name": "fixture.exe", "file_size": 42, "hashes": {"sha256": SHA256},
            "imports": ["VirtualAlloc", "CreateRemoteThread"],
            "strings": ["fixture-only"], "signature": {"verified": True, "signer": "Fixture"},
        }])
        data = self.finding(result, "static_file_profile")["data"]
        self.assertIs(data["content_hash_verified"], False)
        self.assertEqual(data["malware_verdict"], "not_determined")
        self.assertTrue(data["capability_hints"])

    def test_incident_conflicting_event_ids_preserve_all_record_references(self):
        result = self.analyze("INCIDENTINT", [
            {"incident_id": "incident-1", "event_id": "event-1",
             "event_type": "authentication", "timestamp": "2026-01-15T10:00:00+00:00",
             "description": "First assertion"},
            {"incident_id": "incident-1", "event_id": "event-1",
             "event_type": "authentication", "timestamp": "2026-01-15T11:00:00+00:00",
             "description": "Conflicting assertion"},
        ])
        finding = self.finding(result, "incident_timeline")
        self.assertEqual(set(finding["record_ids"]), {"R1", "R2"})
        self.assertTrue(any(
            issue["code"] == "conflicting_event_id" for issue in result["issues"]
        ))

    def test_log_failure_threshold_groups_by_both_account_and_ip(self):
        rows = ([self.failure()] * 3
                + [self.failure(ip="192.0.2.11")] * 2
                + [self.failure(account="bob")] * 2)
        result = self.analyze("LOGINT", rows, parameters={"failure_threshold": 3})
        finding = self.finding(result, "authentication_failure_cluster")
        self.assertEqual(set(finding["record_ids"]), {"R1", "R2", "R3"})
        self.assertEqual(len(result["artifacts"]["events"]), 7)

    def test_log_json_duplicate_keys_are_rejected_without_losing_valid_events(self):
        valid = {
            "timestamp": AS_OF, "event_type": "authentication",
            "account": "alice", "src_ip": "192.0.2.10", "outcome": "failure",
        }
        duplicate = json.dumps(valid)[:-1] + ', "outcome": "success"}'
        result = self.analyze("LOGINT", [
            {"format": "json", "line": json.dumps(valid)},
            {"format": "json", "line": duplicate},
        ])
        self.assertEqual(len(result["artifacts"]["events"]), 1)
        self.assert_rejected_record(result, "R2")

    def test_log_json_escaped_unpaired_surrogate_is_rejected_per_record(self):
        valid = {
            "timestamp": AS_OF, "event_type": "authentication",
            "account": "alice", "src_ip": "192.0.2.10", "outcome": "failure",
        }
        invalid = {**valid, "account": "\ud800"}
        result = self.analyze("LOGINT", [
            {"format": "json", "line": json.dumps(valid)},
            {"format": "json", "line": json.dumps(invalid)},
        ])
        self.assertEqual(len(result["artifacts"]["events"]), 1)
        self.assertEqual(result["artifacts"]["events"][0]["record_id"], "R1")
        self.assert_rejected_record(result, "R2")

    def test_apache_log_is_parsed_as_supplied_metadata(self):
        result = self.analyze("LOGINT", [{
            "format": "apache",
            "line": ('192.0.2.10 - - [15/Jan/2026:12:00:00 +0000] '
                     '"POST /login HTTP/1.1" 401 123 "-" "fixture"'),
        }])
        self.assertEqual(len(result["artifacts"]["events"]), 1)

    def test_dfir_chronology_anomaly_is_a_review_flag_without_content_verification(self):
        result = self.analyze("DFIRINT", [{
            "artifact_id": "artifact-1", "sha256": SHA256,
            "path": "capture.bin", "size_bytes": 42,
            "timestamps": {
                "created": "2026-01-02T00:00:00+00:00",
                "modified": "2026-01-01T00:00:00+00:00",
                "collected": "2026-01-03T00:00:00+00:00",
            },
        }])
        data = self.finding(result, "forensic_artifact_metadata")["data"]
        self.assertIs(data["content_verified"], False)
        self.assertIn("modified_before_created", data["chronology_flags"])

    def test_hunt_statuses_distinguish_absent_support_and_counterevidence(self):
        hypothesis = {
            "record_type": "hypothesis", "hypothesis_id": "hunt-1",
            "description": "Review supplied administrative event assertions",
            "selector": {"admin": True}, "counter_selector": {"admin": False},
        }
        cases = [
            ([], "untested"),
            ([{"other": "value"}], "no_support_in_supplied_events"),
            ([{"admin": True}], "supported_in_sample"),
            ([{"admin": False}], "contradicted_in_sample"),
            ([{"admin": True}, {"admin": False}], "mixed"),
            ([{"admin": 1}], "no_support_in_supplied_events"),
        ]
        for events, expected in cases:
            with self.subTest(events=events):
                rows = [hypothesis] + [
                    {"record_type": "event", "event_id": f"event-{index}", "fields": fields}
                    for index, fields in enumerate(events, 1)
                ]
                result = self.analyze("HUNTINT", rows)
                self.assertEqual(
                    self.finding(result, "hunt_hypothesis")["data"]["status"], expected
                )

    def test_detection_confusion_matrix_covers_each_outcome(self):
        rows = [{
            "record_type": "rule", "rule_id": "rule-1", "enabled": True,
            "selector": {"event": "login", "success": False}, "techniques": ["T1110"],
        }]
        cases = [
            ({"event": "login", "success": False}, ["rule-1"]),
            ({"event": "login", "success": False}, []),
            ({"event": "login", "success": True}, ["rule-1"]),
            ({"event": "login", "success": True}, []),
        ]
        rows.extend(
            {"record_type": "test_event", "event_id": f"event-{index}",
             "fields": fields, "expected_rule_ids": expected}
            for index, (fields, expected) in enumerate(cases, 1)
        )
        result = self.analyze("DETECTIONINT", rows)
        data = self.finding(result, "detection_rule_evaluation")["data"]
        self.assertEqual(data["confusion"], {"tp": 1, "fp": 1, "fn": 1, "tn": 1})
        coverage = json.dumps(result["artifacts"]["coverage"])
        self.assertIn("T1110", coverage)
        self.assertNotIn("T1059", coverage)

    def test_detection_selectors_distinguish_boolean_true_from_integer_one(self):
        result = self.analyze("DETECTIONINT", [
            {"record_type": "rule", "rule_id": "rule-1", "enabled": True,
             "selector": {"admin": True}},
            {"record_type": "test_event", "event_id": "event-1",
             "fields": {"admin": 1}, "expected_rule_ids": ["rule-1"]},
            {"record_type": "test_event", "event_id": "event-2",
             "fields": {"admin": True}, "expected_rule_ids": ["rule-1"]},
        ])
        self.assertEqual(
            self.finding(result, "detection_rule_evaluation")["data"]["confusion"],
            {"tp": 1, "fp": 0, "fn": 1, "tn": 0},
        )

    def test_detection_ambiguous_rule_ids_are_excluded(self):
        result = self.analyze("DETECTIONINT", [
            {"record_type": "rule", "rule_id": "rule-1", "enabled": True,
             "selector": {"admin": True}},
            {"record_type": "rule", "rule_id": "rule-1", "enabled": True,
             "selector": {"admin": False}},
            {"record_type": "test_event", "event_id": "event-1",
             "fields": {"admin": True}, "expected_rule_ids": ["rule-1"]},
        ])
        self.assertTrue(result["issues"])
        self.assertFalse(any(
            finding["kind"] == "detection_rule_evaluation"
            for finding in result["findings"]
        ))

    def test_detection_unknown_expected_rule_id_is_visible(self):
        result = self.analyze("DETECTIONINT", [
            {"record_type": "rule", "rule_id": "rule-1", "enabled": True,
             "selector": {"admin": True}},
            {"record_type": "test_event", "event_id": "event-1",
             "fields": {"admin": True}, "expected_rule_ids": ["unknown-rule"]},
        ])
        self.assertTrue(result["issues"])

    def test_common_source_digest_requires_string_not_64_digit_integer(self):
        payload = self.payload("IOCINT", [
            {"indicator_type": "domain", "value": "example.org"},
        ])
        payload["sources"][0]["content_sha256"] = int("1" * 64)
        with self.assertRaises(ValueError):
            make_context(payload)


if __name__ == "__main__":
    unittest.main()
