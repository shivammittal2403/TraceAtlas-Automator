"""Adversarial regressions for the fourteen supplied-record research engines."""
import copy
from decimal import Decimal
import unittest

from traceatlas.workforce.discipline_engines import invoke_employee


AS_OF = "2026-01-15T12:00:00+00:00"
EVIDENCE_IDS = ("evidence-research-fixture",)


FIXTURES = {
    "ACADEMICINT": [{"paper_id": "paper-1", "title": "Fixture paper",
                     "doi": "10.1000/fixture", "year": 2025, "authors": ["Ada"],
                     "references": [], "retracted": False}],
    "REGINT": [{"regulation_id": "reg-1", "jurisdiction": "IN", "subject": "Fixture subject",
                "effective_from": "2026-01-01T00:00:00+00:00",
                "effective_until": "2026-02-01T00:00:00+00:00", "status": "enacted"}],
    "LEGALINT": [{"decision_id": "decision-1", "court": "Fixture Court", "jurisdiction": "IN",
                  "decision_at": "2026-01-01T00:00:00+00:00", "outcome": "Supplied outcome",
                  "issue_tags": ["fixture"], "cites": []}],
    "SANCTIONSINT": [
        {"record_type": "entry", "list_entry_id": "entry-1", "list_name": "Fixture list",
         "jurisdiction": "IN", "program": "Fixture program", "subject_name": "Example Foundation",
         "identifiers": {"registration_id": "REG-1"},
         "effective_from": "2026-01-01T00:00:00+00:00",
         "effective_until": "2026-02-01T00:00:00+00:00",
         "snapshot_at": "2026-01-14T00:00:00+00:00"},
        {"record_type": "subject", "subject_id": "subject-1", "name": "Example Foundation",
         "identifiers": {"registration_id": "REG-1"}},
    ],
    "GOVINT": [{"agency": "Fixture Agency", "program_id": "program-1",
                "budget": 100, "spent": 120, "currency": "USD",
                "period_start": "2025-01-01T00:00:00+00:00",
                "period_end": "2026-01-01T00:00:00+00:00"}],
    "POLICYINT": [{"policy_id": "policy-1", "deadline": "2026-02-01T00:00:00+00:00",
                   "objectives": [{"objective_id": "O1", "text": "Improve the supplied measure"}],
                   "measures": [{"measure_id": "M1", "objective_ids": ["O1"]}],
                   "metrics": [{"metric_id": "MET1", "baseline": 0, "target": 100,
                                "direction": "increase", "current": 50,
                                "observed_at": "2026-01-10T00:00:00+00:00"}]}],
    "DIPLOINT": [{"event_id": "event-1", "timestamp": AS_OF, "actor": "State A",
                  "counterparty": "State B", "relation": "meeting"}],
    "NGOINT": [{"organization_id": "org-1", "name": "Fixture Foundation", "reporting_year": 2025,
                "income": 100, "program_expense": 30, "admin_expense": 10,
                "fundraising_expense": 10, "reported_total_expense": 50, "currency": "USD"}],
    "EDUINT": [{"institution_id": "institution-1", "program_id": "program-1",
                "accreditation_body": "Fixture Body", "accreditation_status": "accredited",
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_until": "2026-02-01T00:00:00+00:00", "qualification_level": "Bachelor"}],
    "PATENTINT": [{"publication_number": "PUB-1", "application_number": "APP-1",
                   "family_id": "FAMILY-1", "jurisdiction": "IN", "filing_date": "2025-01-01",
                   "priority_date": "2024-12-01", "publication_date": "2025-06-01",
                   "claims": ["A sensor system for measuring temperature"],
                   "inventors": ["Ada"], "legal_status": "Supplied pending assertion"}],
    "IPRINT": [
        {"record_type": "license", "license_id": "license-1", "asset_id": "asset-1",
         "permissions": [{"action": "publish", "territories": ["IN"]}],
         "prohibitions": [], "conditions": ["attribution"],
         "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2026-02-01T00:00:00+00:00"},
        {"record_type": "usage", "usage_id": "usage-1", "asset_id": "asset-1",
         "license_id": "license-1", "action": "publish", "territory": "IN",
         "conditions_satisfied": ["attribution"], "when": AS_OF},
    ],
    "STANDARDSINT": [
        {"record_type": "requirement", "standard_id": "STD-1", "version": "1.0",
         "requirement_id": "REQ-1", "text": "Log supplied events", "mandatory": True},
        {"record_type": "evidence", "artifact_id": "artifact-1",
         "description": "Supplied test log", "collected_at": "2026-01-10T00:00:00+00:00",
         "valid_until": "2026-02-01T00:00:00+00:00"},
        {"record_type": "control", "control_id": "control-1", "standard_id": "STD-1",
         "version": "1.0", "requirement_ids": ["REQ-1"], "evidence_record_ids": ["R2"],
         "implemented": True, "test_result": "pass"},
    ],
    "RNDINT": [{"project_id": "project-1", "hypothesis": "Supplied treatment may increase success",
                "experiments": [{"experiment_id": "experiment-1", "control_n": 10,
                                 "treatment_n": 10, "control_successes": 5,
                                 "treatment_successes": 8}], "minimum_effect": 0.1}],
    "INNOVATIONINT": [{"innovation_id": "innovation-1", "title": "Fixture innovation",
                       "readiness_level": 1, "readiness_evidence": [],
                       "milestones": [], "dependencies": []}],
}

KINDS = {
    "ACADEMICINT": "academic_record", "REGINT": "regulation_interval",
    "LEGALINT": "legal_decision", "SANCTIONSINT": "sanctions_candidate_review",
    "GOVINT": "public_program_spend", "POLICYINT": "policy_logic",
    "DIPLOINT": "bilateral_event_set", "NGOINT": "ngo_report_metrics",
    "EDUINT": "education_claim", "PATENTINT": "patent_record",
    "IPRINT": "license_usage_review", "STANDARDSINT": "standard_requirement_review",
    "RNDINT": "research_experiment_summary", "INNOVATIONINT": "innovation_readiness",
}


class ResearchEmployeeTests(unittest.TestCase):
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
            "case_id": "case-research-fixture",
            "task_id": "task-research-fixture",
            "discipline": label,
            "objective": "Review supplied synthetic research records",
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
    def record(label, index=0, **changes):
        record = copy.deepcopy(FIXTURES[label][index])
        record.update(changes)
        return record

    def test_all_fourteen_handlers_are_deterministic_and_source_bound(self):
        self.assertEqual(len(FIXTURES), 14)
        for label, rows in FIXTURES.items():
            with self.subTest(label=label):
                payload = self.payload(label, rows)
                original = copy.deepcopy(payload)
                first = invoke_employee(payload, evidence_ids=EVIDENCE_IDS)
                second = invoke_employee(payload, evidence_ids=EVIDENCE_IDS)
                self.assertEqual(payload, original)
                self.assertEqual(first, second)
                self.assert_bound(first, payload)
                self.assertTrue(any(f["kind"] == KINDS[label] for f in first["findings"]))

    def test_academic_doi_normalization_links_only_supplied_references(self):
        result = self.analyze("ACADEMICINT", [
            self.record("ACADEMICINT", paper_id="paper-a", doi="https://doi.org/10.1000/AbC"),
            self.record("ACADEMICINT", paper_id="paper-b", doi="10.1000/second",
                        references=["10.1000/ABC", "10.1000/not-supplied"]),
        ])
        self.assertEqual(self.finding(result, "academic_record", "R1")["data"]["doi"], "10.1000/abc")
        self.assertEqual(len(result["artifacts"]["citation_edges"]), 1)

    def test_academic_conflicting_duplicate_doi_preserves_retraction_assertion(self):
        result = self.analyze("ACADEMICINT", [
            self.record("ACADEMICINT", paper_id="paper-a", title="First supplied title"),
            self.record("ACADEMICINT", paper_id="paper-b", title="Different supplied title", retracted=True),
        ])
        self.assertEqual(len([f for f in result["findings"] if f["kind"] == "academic_record"]), 2)
        self.assertTrue(any(issue["code"] == "conflicting_doi" for issue in result["issues"]))
        second = self.finding(result, "academic_record", "R2")["data"]
        self.assertIs(second["retraction_asserted"], True)
        self.assertIs(second["source_truth_verified"], False)
        author_conflict = self.analyze("ACADEMICINT", [
            self.record("ACADEMICINT", paper_id="paper-a", authors=["Ada"]),
            self.record("ACADEMICINT", paper_id="paper-b", authors=["Grace"]),
        ])
        self.assertTrue(any(
            issue["code"] == "conflicting_doi" for issue in author_conflict["issues"]
        ))

    def test_regulation_temporal_status_uses_half_open_declared_interval(self):
        cases = [
            ({}, "active_declared"),
            ({"effective_from": "2026-02-01T00:00:00+00:00",
              "effective_until": "2026-03-01T00:00:00+00:00"}, "not_yet_effective"),
            ({"effective_until": AS_OF}, "expired"),
            ({"status": "proposed"}, "proposed"),
            ({"status": "repealed"}, "repealed"),
        ]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                result = self.analyze("REGINT", [self.record("REGINT", **changes)])
                self.assertEqual(self.finding(result, "regulation_interval")["data"]["temporal_status"],
                                 expected)

    def test_regulation_amendment_cycle_is_reported(self):
        result = self.analyze("REGINT", [
            self.record("REGINT", regulation_id="reg-a", amendment_of="reg-b"),
            self.record("REGINT", regulation_id="reg-b", amendment_of="reg-a"),
        ])
        self.assertTrue(result["artifacts"]["amendment_cycles"])

    def test_legal_future_citation_is_visible_without_inferred_precedence(self):
        result = self.analyze("LEGALINT", [
            self.record("LEGALINT", decision_id="decision-a", cites=["decision-b"]),
            self.record("LEGALINT", decision_id="decision-b",
                        decision_at="2026-01-10T00:00:00+00:00"),
        ])
        self.assertEqual(len(result["artifacts"]["citation_edges"]), 1)
        self.assertTrue(any(issue["code"] == "future_citation" for issue in result["issues"]))
        self.assertTrue(all(
            finding["data"]["precedent_authority_verified"] is False
            for finding in result["findings"] if finding["kind"] == "legal_decision"
        ))
        self.assertIs(result["artifacts"]["citation_edges"][0]["authority_verified"], False)

    def test_sanctions_exact_identifier_candidate_does_not_verify_clearance(self):
        result = self.analyze("SANCTIONSINT", [
            self.record("SANCTIONSINT"),
            self.record("SANCTIONSINT", 1, name="Different supplied name"),
        ])
        data = self.finding(result, "sanctions_candidate_review")["data"]
        self.assertEqual(data["candidate_count"], 1)
        self.assertIs(data["clearance_verified"], False)
        candidate = result["artifacts"]["candidate_matches"][0]
        self.assertEqual(candidate["basis"], "exact_identifier")
        self.assertIs(candidate["candidate_only"], True)

    def test_sanctions_normalized_name_and_no_match_both_remain_candidate_reviews(self):
        for name, count in ((" example FOUNDATION ", 1), ("Unrelated Company", 0)):
            with self.subTest(name=name):
                result = self.analyze("SANCTIONSINT", [
                    self.record("SANCTIONSINT", identifiers={}),
                    self.record("SANCTIONSINT", 1, name=name, identifiers={}),
                ])
                data = self.finding(result, "sanctions_candidate_review")["data"]
                self.assertEqual(data["candidate_count"], count)
                self.assertIs(data["clearance_verified"], False)
                if count:
                    self.assertEqual(result["artifacts"]["candidate_matches"][0]["basis"],
                                     "exact_normalized_name")

    def test_sanctions_expired_and_future_entries_do_not_become_active_candidates(self):
        cases = [
            {"effective_until": AS_OF},
            {"effective_from": "2026-02-01T00:00:00+00:00",
             "effective_until": "2026-03-01T00:00:00+00:00"},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                result = self.analyze("SANCTIONSINT", [
                    self.record("SANCTIONSINT", **changes), self.record("SANCTIONSINT", 1),
                ])
                self.assertEqual(self.finding(result, "sanctions_candidate_review")["data"]["candidate_count"], 0)
                self.assertEqual(result["artifacts"]["candidate_matches"], [])

    def test_government_spend_uses_decimal_arithmetic_and_separate_currency_totals(self):
        result = self.analyze("GOVINT", [
            self.record("GOVINT", budget=0.1, spent=0.3),
            self.record("GOVINT", program_id="program-2", budget=0.2, spent=0.2),
            self.record("GOVINT", program_id="program-3", currency="EUR", budget=10, spent=9),
        ])
        data = self.finding(result, "public_program_spend", "R1")["data"]
        self.assertIsInstance(data["variance"], str)
        self.assertEqual(Decimal(data["variance"]), Decimal("0.2"))
        self.assertIs(data["overspend_asserted"], True)
        self.assertIs(data["audit_verified"], False)
        totals = result["artifacts"]["totals_by_currency"]
        self.assertEqual(set(totals), {"USD", "EUR"})
        for currency, budget, spent, variance, count in (
                ("USD", "0.3", "0.5", "0.2", 2),
                ("EUR", "10", "9", "-1", 1)):
            for field, expected in (("budget", budget), ("spent", spent), ("variance", variance)):
                self.assertIsInstance(totals[currency][field], str)
                self.assertEqual(Decimal(totals[currency][field]), Decimal(expected))
            self.assertEqual(totals[currency]["report_count"], count)

    def test_government_spend_rejects_negative_and_boolean_amounts(self):
        for value in (-1, True):
            with self.subTest(value=value):
                result = self.analyze("GOVINT", [self.record("GOVINT", budget=value)])
                self.assert_rejected_record(result, "R1")

    def test_policy_uncovered_objectives_are_visible(self):
        row = self.record("POLICYINT")
        row["objectives"].append({"objective_id": "O2", "text": "Uncovered supplied objective"})
        result = self.analyze("POLICYINT", [row])
        data = self.finding(result, "policy_logic")["data"]
        self.assertEqual(data["uncovered_objective_ids"], ["O2"])
        self.assertIs(data["outcome_verified"], False)

    def test_policy_unknown_measure_objective_reference_invalidates_record(self):
        row = self.record("POLICYINT")
        row["measures"][0]["objective_ids"] = ["UNKNOWN"]
        self.assert_rejected_record(self.analyze("POLICYINT", [row]), "R1")

    def test_policy_progress_respects_increase_and_decrease_direction(self):
        row = self.record("POLICYINT")
        row["metrics"] = [
            {"metric_id": "increase", "baseline": 0, "target": 100, "current": 25,
             "direction": "increase", "observed_at": AS_OF},
            {"metric_id": "decrease", "baseline": 100, "target": 0, "current": 75,
             "direction": "decrease", "observed_at": AS_OF},
        ]
        result = self.analyze("POLICYINT", [row])
        data = self.finding(result, "policy_logic")["data"]
        metrics = {metric["metric_id"]: metric for metric in data["metrics"]}
        self.assertEqual(set(metrics), {"increase", "decrease"})
        for metric in metrics.values():
            self.assertAlmostEqual(metric["progress_fraction"], 0.25)
            self.assertIs(metric["target_met_in_supplied_observation"], False)
        self.assertIs(data["outcome_verified"], False)

    def test_policy_overdue_unmet_metrics_produce_review_gap(self):
        row = self.record("POLICYINT", deadline="2026-01-01T00:00:00+00:00")
        result = self.analyze("POLICYINT", [row])
        self.finding(result, "policy_logic")
        self.assertTrue(result["issues"])

    def test_diplomatic_pair_grouping_preserves_conflicting_event_ids(self):
        result = self.analyze("DIPLOINT", [
            self.record("DIPLOINT", event_id="event-1", relation="agreement"),
            self.record("DIPLOINT", event_id="event-1", actor="State B",
                        counterparty="State A", relation="dispute"),
        ])
        data = self.finding(result, "bilateral_event_set")["data"]
        self.assertEqual(data["event_count"], 2)
        self.assertEqual(data["relation_counts"], {"agreement": 1, "dispute": 1})
        self.assertIs(data["intent_verified"], False)
        self.assertTrue(any(issue["code"] == "conflicting_event_id" for issue in result["issues"]))

    def test_ngo_expense_discrepancy_is_visible_without_registration_verification(self):
        result = self.analyze("NGOINT", [self.record("NGOINT", reported_total_expense=49)])
        data = self.finding(result, "ngo_report_metrics")["data"]
        self.assertEqual(Decimal(data["total_expense"]), Decimal("50"))
        self.assertAlmostEqual(data["program_expense_ratio"], 0.6)
        self.assertIs(data["reported_total_agrees"], False)
        self.assertIs(data["registration_verified"], False)
        self.assertTrue(result["issues"])

    def test_ngo_zero_expense_ratio_is_unknown_instead_of_division_by_zero(self):
        row = self.record("NGOINT", program_expense=0, admin_expense=0,
                          fundraising_expense=0, reported_total_expense=0)
        result = self.analyze("NGOINT", [row])
        data = self.finding(result, "ngo_report_metrics")["data"]
        self.assertEqual(Decimal(data["total_expense"]), Decimal("0"))
        self.assertIsNone(data["program_expense_ratio"])
        self.assertIs(data["reported_total_agrees"], True)

    def test_education_accreditation_term_is_half_open_and_unverified(self):
        for until, active in (("2026-02-01T00:00:00+00:00", True), (AS_OF, False)):
            with self.subTest(until=until):
                result = self.analyze("EDUINT", [self.record("EDUINT", valid_until=until)])
                data = self.finding(result, "education_claim")["data"]
                self.assertIs(data["declared_active"], active)
                self.assertIs(data["accreditation_verified"], False)

    def test_education_overlapping_conflicting_claims_remain_separate(self):
        result = self.analyze("EDUINT", [
            self.record("EDUINT"),
            self.record("EDUINT", accreditation_status="withdrawn"),
        ])
        self.assertEqual(len([f for f in result["findings"] if f["kind"] == "education_claim"]), 2)
        self.assertTrue(any(
            issue["code"] == "conflicting_accreditation" for issue in result["issues"]
        ))

    def test_patent_lexical_overlap_and_declared_family_do_not_verify_validity(self):
        result = self.analyze("PATENTINT", [
            self.record("PATENTINT"),
            self.record("PATENTINT", publication_number="PUB-2", application_number="APP-2"),
        ], parameters={"similarity_threshold": 0.9})
        self.assertEqual(len(result["artifacts"]["lexical_overlap"]), 1)
        self.assertEqual(len(result["artifacts"]["families"]), 1)
        self.assertTrue(all(
            finding["data"]["validity_verified"] is False
            for finding in result["findings"] if finding["kind"] == "patent_record"
        ))

    def test_license_usage_statuses_and_declared_wildcard(self):
        cases = [
            ({}, {"license_id": "unknown"}, "unknown_license"),
            ({}, {"asset_id": "another-asset"}, "asset_mismatch"),
            ({}, {"when": "2026-02-01T00:00:00+00:00"}, "outside_declared_term"),
            ({"prohibitions": ["publish"]}, {}, "conflicting_terms"),
            ({"permissions": [], "prohibitions": ["publish"]}, {}, "prohibited"),
            ({"permissions": [{"action": "copy", "territories": ["IN"]}]}, {},
             "not_granted_in_supplied_license"),
            ({}, {"territory": "US"}, "territory_mismatch"),
            ({}, {"conditions_satisfied": []}, "conditions_unmet"),
            ({}, {}, "within_supplied_terms"),
            ({"permissions": [{"action": "publish", "territories": ["*"]}]},
             {"territory": "US"}, "within_supplied_terms"),
        ]
        for license_changes, usage_changes, expected in cases:
            with self.subTest(expected=expected, usage=usage_changes):
                result = self.analyze("IPRINT", [
                    self.record("IPRINT", **license_changes),
                    self.record("IPRINT", 1, **usage_changes),
                ])
                data = self.finding(result, "license_usage_review")["data"]
                self.assertEqual(data["status"], expected)
                self.assertIs(data["legal_clearance_verified"], False)

    def test_license_duplicate_id_is_excluded_as_ambiguous(self):
        result = self.analyze("IPRINT", [
            self.record("IPRINT"),
            self.record("IPRINT", asset_id="another-asset"),
            self.record("IPRINT", 1),
        ])
        data = self.finding(result, "license_usage_review")["data"]
        self.assertEqual(data["status"], "unknown_license")
        self.assertTrue(result["issues"])

    def test_standard_coverage_requires_exact_version_pass_implementation_and_current_evidence(self):
        cases = [
            ({}, {}, True),
            ({"version": "2.0"}, {}, False),
            ({"implemented": False}, {}, False),
            ({"test_result": "fail"}, {}, False),
            ({"test_result": "not_tested"}, {}, False),
            ({}, {"valid_until": AS_OF}, False),
        ]
        for control_changes, evidence_changes, covered in cases:
            with self.subTest(control=control_changes, evidence=evidence_changes):
                result = self.analyze("STANDARDSINT", [
                    self.record("STANDARDSINT"),
                    self.record("STANDARDSINT", 1, **evidence_changes),
                    self.record("STANDARDSINT", 2, **control_changes),
                ])
                data = self.finding(result, "standard_requirement_review")["data"]
                self.assertIs(data["covered_by_supplied_test"], covered)
                self.assertIs(data["compliance_verified"], False)

    def test_standard_unknown_evidence_reference_invalidates_control(self):
        result = self.analyze("STANDARDSINT", [
            self.record("STANDARDSINT"), self.record("STANDARDSINT", 1),
            self.record("STANDARDSINT", 2, evidence_record_ids=["UNKNOWN"]),
        ])
        self.assert_rejected_record(result, "R3")
        self.assertIs(self.finding(result, "standard_requirement_review")["data"]
                      ["covered_by_supplied_test"], False)

    def test_standard_duplicate_requirement_id_cannot_be_silently_covered(self):
        result = self.analyze("STANDARDSINT", [
            self.record("STANDARDSINT"),
            self.record("STANDARDSINT", text="Conflicting supplied requirement"),
            self.record("STANDARDSINT", 1),
            self.record("STANDARDSINT", 2, evidence_record_ids=["R3"]),
        ])
        self.assertTrue(result["issues"])
        self.assertFalse(any(
            finding["data"].get("covered_by_supplied_test") is True
            for finding in result["findings"] if finding["kind"] == "standard_requirement_review"
        ))

    def test_research_pools_counts_instead_of_averaging_rates_and_keeps_contradictions(self):
        result = self.analyze("RNDINT", [self.record("RNDINT", experiments=[
            {"experiment_id": "small", "control_n": 10, "treatment_n": 10,
             "control_successes": 10, "treatment_successes": 0},
            {"experiment_id": "large", "control_n": 90, "treatment_n": 90,
             "control_successes": 0, "treatment_successes": 90},
        ])])
        data = self.finding(result, "research_experiment_summary")["data"]
        self.assertAlmostEqual(data["pooled_control_rate"], 0.1)
        self.assertAlmostEqual(data["pooled_treatment_rate"], 0.9)
        self.assertAlmostEqual(data["absolute_effect"], 0.8)
        self.assertEqual(set(data["contradictory_experiment_ids"]), {"small", "large"})
        self.assertIs(data["causal_effect_verified"], False)

    def test_research_duplicate_experiment_id_invalidates_project_record(self):
        row = self.record("RNDINT")
        row["experiments"].append(copy.deepcopy(row["experiments"][0]))
        self.assert_rejected_record(self.analyze("RNDINT", [row]), "R1")

    def test_innovation_readiness_requires_contiguous_supported_levels(self):
        row = self.record("INNOVATIONINT", readiness_level=4, readiness_evidence=[
            {"level": 1, "description": "First supplied level", "record_ids": ["R1"]},
            {"level": 3, "description": "Third supplied level", "record_ids": ["R1"]},
            {"level": 4, "description": "Fourth supplied level", "record_ids": ["R1"]},
        ], milestones=[
            {"milestone_id": "overdue", "completed": False, "due_at": "2026-01-01T00:00:00+00:00"},
            {"milestone_id": "done", "completed": True, "due_at": "2026-01-01T00:00:00+00:00"},
        ], dependencies=["missing-innovation"])
        result = self.analyze("INNOVATIONINT", [row])
        data = self.finding(result, "innovation_readiness")["data"]
        self.assertEqual(data["declared_level"], 4)
        self.assertEqual(data["sequentially_supported_level"], 1)
        self.assertEqual(data["overdue_milestone_ids"], ["overdue"])
        self.assertIs(data["readiness_verified"], False)
        self.assertTrue(result["artifacts"]["missing_dependencies"])

    def test_innovation_cycles_survive_adjacent_unknown_evidence_reference(self):
        result = self.analyze("INNOVATIONINT", [
            self.record("INNOVATIONINT", innovation_id="innovation-a", dependencies=["innovation-b"]),
            self.record("INNOVATIONINT", innovation_id="innovation-b", dependencies=["innovation-a"]),
            self.record("INNOVATIONINT", innovation_id="innovation-invalid", readiness_evidence=[
                {"level": 1, "description": "Unknown supplied record", "record_ids": ["UNKNOWN"]},
            ]),
        ])
        self.assertTrue(result["artifacts"]["dependency_cycles"])
        self.assert_rejected_record(result, "R3")


if __name__ == "__main__":
    unittest.main()
