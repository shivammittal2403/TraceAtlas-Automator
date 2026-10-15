"""Regression coverage for academic source integrity and input validation."""
import copy
import unittest

from traceatlas.addons.intelligence_v1.modules import accadmicint as academic


def fixture():
    return {
        "case_id": "CASE-SYNTHETIC",
        "task_id": "TASK-SYNTHETIC",
        "objective": "Review supplied synthetic academic records",
        "authorization": {
            "approved": True,
            "scope": "provided_records_only",
            "model_mode": "LOCAL_ONLY"
        },
        "sources": [
            {
                "source_id": "S1",
                "source_type": "official_publisher",
                "reliability": 0.88
            },
            {
                "source_id": "S2",
                "source_type": "institutional_repository",
                "reliability": 0.84
            }
        ],
        "publications": [
            {
                "publication_id": "P1",
                "doi": "10.9999/synthetic-one",
                "title": "Synthetic study one",
                "year": 2024,
                "authors": [
                    "Synthetic Author One"
                ],
                "source_ids": [
                    "S1"
                ],
                "evidence_ids": [
                    "E1"
                ]
            },
            {
                "publication_id": "P2",
                "doi": "10.9999/synthetic-two",
                "title": "Synthetic study two",
                "year": 2025,
                "authors": [
                    "Synthetic Author Two"
                ],
                "source_ids": [
                    "S2"
                ],
                "evidence_ids": [
                    "E2"
                ]
            }
        ]
    }


class AcademicInputIntegrityTests(unittest.TestCase):
    def test_approval_requires_literal_true(self):
        for value in ("true", "false", 1, [True], {"approved": True}, False, None):
            with self.subTest(value=value):
                payload = fixture()
                payload["authorization"]["approved"] = value
                result = academic.analyze_academicint_manifest(payload)
                self.assertEqual(result["status"], "BLOCKED_PERMISSION")
                self.assertEqual(result["publications"], [])

    def test_cloud_and_hybrid_require_explicit_cloud_approval(self):
        for mode in ("CLOUD", "HYBRID"):
            for approved in (False, "true", 1, None):
                with self.subTest(mode=mode, approved=approved):
                    payload = fixture()
                    payload["authorization"].update(model_mode=mode, cloud_approved=approved)
                    ok, reasons = academic.authorization_check(payload)
                    self.assertFalse(ok)
                    self.assertIn("CLOUD_PROCESSING_NOT_APPROVED", reasons)
            payload = fixture()
            payload["authorization"].update(model_mode=mode, cloud_approved=True)
            self.assertTrue(academic.authorization_check(payload)[0])

    def test_private_record_approval_requires_literal_true(self):
        payload = fixture()
        payload["private_lab_records"] = [{"record_id": "SYNTHETIC-PRIVATE"}]
        payload["authorization"]["private_research_approved"] = "true"
        self.assertIn("PRIVATE_RESEARCH_RECORDS_NOT_APPROVED", academic.authorization_check(payload)[1])
        payload["authorization"]["private_research_approved"] = True
        self.assertTrue(academic.authorization_check(payload)[0])

    def test_nonfinite_numbers_cannot_become_high_confidence(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(number=number):
                with self.assertRaises(ValueError):
                    academic.clamp(number)
                for collection, key in (("sources", "reliability"), ("publications", "confidence")):
                    payload = fixture()
                    payload[collection][0][key] = number
                    with self.assertRaises(ValueError):
                        academic.analyze_academicint_manifest(payload)
        self.assertEqual(academic.clamp(-2), 0.0)
        self.assertEqual(academic.clamp(2), 1.0)
        self.assertEqual(academic.clamp(0.75), 0.75)

    def test_malformed_containers_fail_before_analysis(self):
        malformed = [None, [], "manifest", {"authorization": []},
                     {"sources": "S1"}, {"sources": [None]},
                     {"publications": ["paper"]}, {"questions": "question"},
                     {"publications": [{"source_ids": "S1"}]},
                     {"publications": [{"authors": 42}]}]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    academic.analyze_academicint_manifest(payload)

    def test_duplicate_explicit_publication_id_is_rejected(self):
        payload = fixture()
        payload["publications"][1]["publication_id"] = "P1"
        with self.assertRaisesRegex(ValueError, "duplicate publication_id"):
            academic.analyze_academicint_manifest(payload)

    def test_duplicate_normalized_doi_is_rejected_across_different_ids(self):
        payload = fixture()
        payload["publications"][1]["doi"] = "https://doi.org/10.9999/SYNTHETIC-ONE"
        with self.assertRaisesRegex(ValueError, "duplicate DOI"):
            academic.analyze_academicint_manifest(payload)

    def test_duplicate_generated_id_is_rejected(self):
        payload = fixture()
        publication = {"title": "Synthetic repeated study", "year": 2024,
                       "authors": ["Synthetic Author"], "source_ids": ["S1"]}
        payload["publications"] = [publication, copy.deepcopy(publication)]
        with self.assertRaisesRegex(ValueError, "duplicate publication_id"):
            academic.analyze_academicint_manifest(payload)

    def test_distinct_records_keep_their_source_and_evidence_ids(self):
        payload = fixture()
        before = copy.deepcopy(payload)
        result = academic.analyze_academicint_manifest(payload)
        publications = {row["publication_id"]: row for row in result["publications"]}
        self.assertEqual(set(publications), {"P1", "P2"})
        self.assertEqual(publications["P1"]["source_ids"], ["S1"])
        self.assertEqual(publications["P2"]["source_ids"], ["S2"])
        self.assertEqual(publications["P1"]["evidence_ids"], ["E1"])
        self.assertEqual(publications["P2"]["evidence_ids"], ["E2"])
        self.assertEqual(result["claims"], [])
        self.assertEqual(result["citations"], [])
        self.assertEqual(payload, before)
        self.assertIn(result["status"], {"PARTIAL", "SUCCEEDED"})

    def test_report_keeps_limitations_for_blocked_permission(self):
        payload = fixture()
        payload["authorization"]["approved"] = False
        result = academic.analyze_academicint_manifest(payload)
        report = academic.generate_report(result)
        self.assertIn("## Limitations", report)
        self.assertIn("AUTHORIZATION_MISSING_OR_NOT_APPROVED", report)


if __name__ == "__main__":
    unittest.main()
