"""Semantic media/evidence tests using the production AnalysisContext."""
import hashlib
import math
import unittest

from traceatlas.workforce.discipline_engines.common import make_context
from traceatlas.workforce.discipline_engines.media import HANDLERS as MEDIA
from traceatlas.workforce.discipline_engines.evidence import HANDLERS as EVIDENCE

HANDLERS = {**MEDIA, **EVIDENCE}


class MediaEvidenceEmployeesTests(unittest.TestCase):
    @staticmethod
    def record(identifier, data, source="s1"):
        return {"record_id": identifier, "source_id": source, "data": data}

    def analyze(self, label, records, sources=None):
        payload = {"case_id": "case-test", "task_id": "task-test", "discipline": label,
                   "objective": "Analyze supplied records", "as_of": "2026-10-15T00:00:00Z",
                   "sources": sources or [
                       {"source_id": name, "uri": "urn:fixture:" + name}
                       for name in ("s1", "s2", "s3")],
                   "records": records, "parameters": {}}
        result = HANDLERS[label](make_context(payload))
        valid = {row["record_id"] for row in records}
        for finding in result["findings"]:
            self.assertTrue(set(finding["record_ids"]).issubset(valid))
        return result

    @staticmethod
    def claim(value, **extra):
        return {"subject": "asset-a", "predicate": "state", "value": value,
                "cardinality": "one", **extra}

    def test_measurement_units_uncertainty_and_reference_overlap(self):
        result = self.analyze("MASINT", [self.record("r1", {
            "value": 200, "unit": "cm", "uncertainty": 1,
            "reference": {"value": 2, "unit": "m", "uncertainty": 0.02}})])
        item = result["artifacts"]["measurements"][0]
        self.assertEqual(item["unit"], "m")
        self.assertEqual(item["value"], 2)
        self.assertAlmostEqual(item["uncertainty_interval"][0], 1.99)
        self.assertAlmostEqual(item["uncertainty_interval"][1], 2.01)
        self.assertEqual(item["reference_compatibility"], "INTERVALS_OVERLAP")

    def test_temperature_offset_does_not_shift_uncertainty(self):
        result = self.analyze("MASINT", [self.record("r1", {
            "value": 20, "unit": "C", "uncertainty": 0.5})])
        item = result["artifacts"]["measurements"][0]
        self.assertAlmostEqual(item["value"], 293.15)
        self.assertAlmostEqual(item["uncertainty_interval"][0], 292.65)
        self.assertAlmostEqual(item["uncertainty_interval"][1], 293.65)

    def test_unknown_uncertainty_is_not_zero_and_incompatible_units_reject(self):
        result = self.analyze("MASINT", [self.record("r1", {"value": 2, "unit": "m"}),
            self.record("r2", {"value": 2, "unit": "m", "reference": {"value": 2, "unit": "s"}})])
        self.assertEqual(result["metrics"]["measurements"], 1)
        self.assertIsNone(result["artifacts"]["measurements"][0]["uncertainty_interval"])
        codes = {row["code"] for row in result["issues"]}
        self.assertIn("measurement_uncertainty_unknown", codes)
        self.assertIn("invalid_measurement", codes)

    def test_geospatial_mercator_transform_and_uncertain_geofence(self):
        result = self.analyze("GEOINT", [self.record("r1", {
            "crs": "EPSG:3857", "x": 0, "y": 0, "uncertainty_m": 100,
            "geofence": {"center": {"latitude": 0, "longitude": 0}, "radius_m": 50}})])
        item = result["artifacts"]["points"][0]
        self.assertAlmostEqual(item["wgs84"]["latitude"], 0)
        self.assertAlmostEqual(item["wgs84"]["longitude"], 0)
        self.assertEqual(item["geofence"]["assessment"], "INTERSECTS_UNCERTAINTY")

    def test_geospatial_huge_uncertainty_isolated_from_valid_neighbor(self):
        result = self.analyze("GEOINT", [
            self.record("r1", {"latitude": 0, "longitude": 0, "uncertainty_m": 1e308,
                               "query_point": {"latitude": 0, "longitude": 0, "uncertainty_m": 1e308}}),
            self.record("r2", {"latitude": 0, "longitude": 0, "uncertainty_m": 5,
                               "geofence": {"center": {"latitude": 0, "longitude": 0}, "radius_m": 10}})])
        self.assertEqual(result["metrics"]["points"], 1)
        self.assertEqual(result["artifacts"]["points"][0]["record_id"], "r2")
        self.assertEqual(result["artifacts"]["points"][0]["geofence"]["assessment"], "INSIDE")
        self.assertIn("invalid_geospatial_record", {row["code"] for row in result["issues"]})

    def test_geospatial_antimeridian_distance_is_short_arc(self):
        result = self.analyze("GEOINT", [self.record("r1", {
            "latitude": 0, "longitude": 179.9,
            "query_point": {"latitude": 0, "longitude": -179.9}})])
        distance = result["artifacts"]["points"][0]["query_distance_m"]
        self.assertGreater(distance, 22000)
        self.assertLess(distance, 23000)

    def test_geospatial_malformed_point_and_out_of_range_latitude_are_issues(self):
        result = self.analyze("GEOINT", [
            self.record("r1", {"latitude": 91, "longitude": 0}),
            self.record("r2", {"latitude": 0, "longitude": 0, "query_point": "not-a-point"})])
        self.assertEqual(result["metrics"]["points"], 0)
        self.assertEqual(len(result["issues"]), 2)

    def test_image_orientation_normalizes_exact_pixel_identity(self):
        result = self.analyze("IMINT", [
            self.record("r1", {"pixels": [[0, 255], [50, 100]], "orientation": 6}),
            self.record("r2", {"pixels": [[50, 0], [100, 255]]}, "s2")])
        images = result["artifacts"]["images"]
        self.assertEqual(images[0]["pixel_sha256"], images[1]["pixel_sha256"])
        candidate = result["artifacts"]["similarity_candidates"][0]
        self.assertTrue(candidate["pixel_identical"])
        self.assertFalse(candidate["identity_or_authenticity_verified"])

    def test_image_uniform_hash_collision_does_not_claim_pixel_identity(self):
        result = self.analyze("IMINT", [
            self.record("r1", {"pixels": [[0, 0], [0, 0]]}),
            self.record("r2", {"pixels": [[255, 255], [255, 255]]}, "s2")])
        candidate = result["artifacts"]["similarity_candidates"][0]
        self.assertEqual(candidate["dhash_distance"], 0)
        self.assertFalse(candidate["pixel_identical"])

    def test_image_ragged_or_boolean_pixels_are_rejected(self):
        result = self.analyze("IMINT", [
            self.record("r1", {"pixels": [[0, 1], [2]]}),
            self.record("r2", {"pixels": [[True, 0]]})])
        self.assertEqual(result["metrics"]["images"], 0)

    def test_video_detects_scene_candidate_and_repeated_fingerprint(self):
        result = self.analyze("VIDINT", [self.record("r1", {
            "duration": 3, "fps": 1, "sampling": "complete", "frames": [
                {"timestamp": 0, "dhash": "0000000000000000"},
                {"timestamp": 1, "dhash": "0000000000000000"},
                {"timestamp": 2, "dhash": "ffffffffffffffff"}]})])
        item = result["artifacts"]["videos"][0]
        self.assertEqual(len(item["scene_change_candidates"]), 1)
        self.assertEqual(item["repeated_fingerprint_intervals"], [[0, 1]])
        self.assertEqual(item["gaps_in_declared_complete_sample"], [])

    def test_video_nonmonotonic_order_and_same_time_conflict_are_explicit(self):
        result = self.analyze("VIDINT", [self.record("r1", {"frames": [
            {"timestamp": 2, "dhash": "ffffffffffffffff"},
            {"timestamp": 1, "dhash": "0000000000000000"},
            {"timestamp": 1, "dhash": "ffffffffffffffff"}]})])
        codes = {row["code"] for row in result["issues"]}
        self.assertIn("nonmonotonic_frame_order", codes)
        self.assertIn("simultaneous_frame_conflict", codes)

    def test_audio_statistics_preserve_clipping_silence_and_duration(self):
        result = self.analyze("AUDINT", [self.record("r1", {
            "samples": [0, 1, -1, 0], "sample_rate": 4})])
        item = result["artifacts"]["audio"][0]
        self.assertEqual(item["duration_seconds"], 1)
        self.assertAlmostEqual(item["channels"][0]["rms"], math.sqrt(0.5))
        self.assertEqual(item["channels"][0]["clipped_samples"], 2)
        self.assertEqual(item["channels"][0]["zero_crossings"], 2)
        self.assertEqual(item["silence_intervals"], [
            {"start_seconds": 0, "end_seconds": 0.25},
            {"start_seconds": 0.75, "end_seconds": 1}])

    def test_audio_pcm16_and_incomplete_multichannel_frames(self):
        result = self.analyze("AUDINT", [
            self.record("r1", {"samples": [-32768, 32767], "sample_rate": 2, "sample_format": "pcm16"}),
            self.record("r2", {"samples": [0, 0, 0], "sample_rate": 2, "channels": 2})])
        self.assertEqual(result["metrics"]["audio_records"], 1)
        self.assertEqual(result["artifacts"]["audio"][0]["channels"][0]["clipped_samples"], 2)
        self.assertIn("invalid_audio_samples", {row["code"] for row in result["issues"]})

    def test_document_preserves_page_index_locators_and_table_width_gaps(self):
        result = self.analyze("DOCINT", [self.record("r1", {"pages": [
            {"page_number": 1, "text": "α 10.1234/example", "tables": [
                {"headers": ["id", "value"], "rows": [[1, 2], [3], [4, 5]]}]},
            {"page_number": 1, "text": "Second page"}]})])
        item = result["artifacts"]["documents"][0]
        self.assertEqual(item["page_count"], 2)
        self.assertEqual(item["references"][0]["start"], 2)
        self.assertEqual(item["references"][0]["text"], "10.1234/example")
        self.assertEqual(item["tables"][0]["valid_row_count"], 2)
        self.assertEqual(item["tables"][0]["invalid_row_count"], 1)
        self.assertIn("duplicate_page_number", {row["code"] for row in result["issues"]})

    def test_document_unhashable_table_header_becomes_issue(self):
        result = self.analyze("DOCINT", [self.record("r1", {"pages": [{
            "text": "Safe supplied content", "tables": [{"headers": [["bad"]], "rows": [[1]]}]}]})])
        self.assertEqual(result["artifacts"]["documents"][0]["tables"], [])
        self.assertIn("invalid_document_table", {row["code"] for row in result["issues"]})

    def test_metadata_reversed_chronology_and_hash_mismatch_are_not_authenticity(self):
        result = self.analyze("METADATAINT", [self.record("r1", {
            "metadata": {"CreationDate": "2026-10-14T12:00:00Z",
                         "ModifyDate": "2026-10-13T12:00:00Z", "Creator": "Example"},
            "content_text": "abc", "sha256": "f" * 64})])
        item = result["artifacts"]["metadata"][0]
        self.assertEqual(len(item["modification_before_creation"]), 1)
        self.assertFalse(item["declared_hash_matches"])
        self.assertFalse(item["authenticity_verified"])
        self.assertIn("metadata_hash_mismatch", {row["code"] for row in result["issues"]})

    def test_metadata_naive_timestamp_is_not_assigned_a_timezone(self):
        result = self.analyze("METADATAINT", [self.record("r1", {
            "metadata": {"CreationDate": "2026-10-14T12:00:00"}})])
        self.assertIn("ambiguous_metadata_time", {row["code"] for row in result["issues"]})
        self.assertNotIn("normalized_time", result["artifacts"]["metadata"][0]["fields"][0])

    def test_source_lineage_collapses_declared_origin_without_verifying_independence(self):
        sources = [
            {"source_id": "s1", "uri": "urn:fixture:s1", "original_source_id": "s2",
             "content_sha256": "a" * 64},
            {"source_id": "s2", "uri": "urn:fixture:s2", "original_source_id": "wire",
             "content_sha256": "a" * 64}]
        result = self.analyze("SOURCEINT", [
            self.record("r1", {}), self.record("r2", {}, "s2")], sources)
        rows = result["artifacts"]["source_lineage"]
        self.assertEqual(rows[0]["declared_origin_group"], rows[1]["declared_origin_group"])
        self.assertFalse(any(row["independence_verified"] for row in rows))
        self.assertEqual(result["metrics"]["shared_declared_hash_groups"], 1)

    def test_source_cycle_is_one_component_and_has_no_resolved_origin(self):
        sources = [
            {"source_id": "s1", "uri": "urn:fixture:s1", "original_source_id": "s2"},
            {"source_id": "s2", "uri": "urn:fixture:s2", "original_source_id": "s1"}]
        result = self.analyze("SOURCEINT", [
            self.record("r1", {}), self.record("r2", {}, "s2")], sources)
        self.assertEqual(result["metrics"]["lineage_cycles"], 1)
        self.assertTrue(all(row["declared_origin_group"] is None for row in result["artifacts"]["source_lineage"]))

    def test_provenance_computes_local_chain_and_parent_digest_consistency(self):
        digest = hashlib.sha256(b"abc").hexdigest()
        result = self.analyze("PROVENANCEINT", [
            self.record("r1", {"artifact_id": "a", "content_text": "abc", "sha256": digest}),
            self.record("r2", {"artifact_id": "b", "content_text": "derived",
                "transformation": "render", "parents": [{"artifact_id": "a", "sha256": digest}]})])
        artifacts = result["artifacts"]["artifacts"]
        self.assertTrue(all(row["chain_digest"] for row in artifacts))
        self.assertTrue(artifacts[0]["computed_from_supplied_text"])
        self.assertFalse(any(row["authenticity_verified"] for row in artifacts))

    def test_provenance_cycle_and_bad_content_hash_block_chain_digest(self):
        result = self.analyze("PROVENANCEINT", [
            self.record("r1", {"artifact_id": "a", "content_text": "abc", "sha256": "f" * 64,
                               "parents": ["b"]}),
            self.record("r2", {"artifact_id": "b", "content_text": "def", "parents": ["a"]})])
        self.assertEqual(result["metrics"]["lineage_cycles"], 1)
        self.assertTrue(all(row["chain_digest"] is None for row in result["artifacts"]["artifacts"]))
        self.assertIn("artifact_hash_mismatch", {row["code"] for row in result["issues"]})

    def test_provenance_duplicate_ids_do_not_silently_replace_manifests(self):
        result = self.analyze("PROVENANCEINT", [
            self.record("r1", {"artifact_id": "a", "content_text": "first"}),
            self.record("r2", {"artifact_id": "a", "content_text": "second"}),
            self.record("r3", {"artifact_id": "b", "content_text": "child", "parents": ["a"]})])
        self.assertEqual(result["metrics"]["artifact_manifests"], 3)
        self.assertEqual(result["metrics"]["ambiguous_artifact_ids"], 1)
        self.assertEqual(result["metrics"]["parent_gaps"], 1)
        self.assertTrue(all(row["chain_digest"] is None for row in result["artifacts"]["artifacts"]))

    def test_corroboration_copies_count_one_origin_and_refutation_stays_visible(self):
        sources = [
            {"source_id": "s1", "uri": "urn:fixture:s1", "original_source_id": "wire"},
            {"source_id": "s2", "uri": "urn:fixture:s2", "original_source_id": "wire"},
            {"source_id": "s3", "uri": "urn:fixture:s3", "original_source_id": "other"}]
        result = self.analyze("CORROBORATIONINT", [
            self.record("r1", {"claim_id": "c", "stance": "support"}),
            self.record("r2", {"claim_id": "c", "stance": "support"}, "s2"),
            self.record("r3", {"claim_id": "c", "stance": "refute"}, "s3")], sources)
        item = result["artifacts"]["corroboration"][0]
        self.assertEqual(len(item["declared_support_groups"]), 1)
        self.assertEqual(item["support_records"], 2)
        self.assertEqual(item["assessment"], "CONTESTED")
        self.assertFalse(item["factual_truth_verified"])

    def test_corroboration_unknown_origin_is_not_an_independent_group(self):
        result = self.analyze("CORROBORATIONINT", [
            self.record("r1", {"claim_id": "c", "stance": "support"}),
            self.record("r2", {"claim_id": "c", "stance": {}}, "s2")])
        item = result["artifacts"]["corroboration"][0]
        self.assertEqual(item["declared_support_groups"], [])
        self.assertEqual(item["unknown_origin_sources"], ["s1"])
        self.assertIn("invalid_corroboration_record", {row["code"] for row in result["issues"]})

    def test_contradiction_normalizes_units_and_retains_uncertainty(self):
        result = self.analyze("CONTRADICTIONINT", [
            self.record("r1", self.claim(500, unit="m", uncertainty=1)),
            self.record("r2", self.claim(0.5, unit="km", uncertainty=0.001), "s2")])
        self.assertEqual(result["metrics"]["conflicting_pairs"], 0)
        self.assertEqual(result["metrics"]["compatible_pairs"], 1)

    def test_contradiction_requires_exclusivity_and_temporal_overlap(self):
        result = self.analyze("CONTRADICTIONINT", [
            self.record("r1", self.claim("red", valid_from="2020-01-01", valid_to="2020-12-31")),
            self.record("r2", self.claim("blue", valid_from="2021-01-01", valid_to="2021-12-31"), "s2"),
            self.record("r3", self.claim("green", cardinality="many"), "s3")])
        self.assertEqual(result["metrics"]["conflicting_pairs"], 0)
        self.assertGreater(result["metrics"]["unassessed_pairs"], 0)

    def test_contradiction_boolean_is_not_numeric_one(self):
        result = self.analyze("CONTRADICTIONINT", [
            self.record("r1", self.claim(True)), self.record("r2", self.claim(1), "s2")])
        self.assertEqual(result["metrics"]["conflicting_pairs"], 1)

    def test_verification_checks_entailment_and_keeps_cited_refutation(self):
        result = self.analyze("VERIFICATIONINT", [
            self.record("r1", {"claim": self.claim("active"),
                               "support_record_ids": ["r2"], "refute_record_ids": ["r3"]}),
            self.record("r2", {"claims": [self.claim("active")]}, "s2"),
            self.record("r3", {"claims": [self.claim("closed")]}, "s3")])
        item = result["artifacts"]["verification"][0]
        self.assertEqual(item["assessment"], "CONTESTED_SUPPLIED_ASSERTIONS")
        self.assertEqual(item["support_record_ids"], ["r2"])
        self.assertEqual(item["refute_record_ids"], ["r3"])
        self.assertFalse(item["factual_truth_verified"])
        self.assertEqual(result["findings"][0]["record_ids"], ["r1", "r2", "r3"])

    def test_verification_future_target_is_not_supported_by_current_same_assertion(self):
        result = self.analyze("VERIFICATIONINT", [
            self.record("r1", {"claim": self.claim("active", valid_from="2027-01-01"),
                               "support_record_ids": ["r2"]}),
            self.record("r2", {"claims": [self.claim("active")]}, "s2")])
        self.assertEqual(result["metrics"]["claim_assessments"], 0)
        self.assertIn("verification_target_outside_as_of", {row["code"] for row in result["issues"]})

    def test_provenance_artifact_bounds_preserve_total_gap_count(self):
        records = [self.record("r" + str(index), {
            "artifact_id": "a" + str(index), "content_text": "record-" + str(index),
            "parents": ["missing-" + str(index) + "-" + str(parent) for parent in range(250)]})
            for index in range(3)]
        result = self.analyze("PROVENANCEINT", records)
        self.assertEqual(result["metrics"]["parent_gaps"], 750)
        self.assertEqual(len(result["artifacts"]["parent_gaps"]), 200)
        self.assertTrue(result["artifacts"]["lineage_artifacts_truncated"]["parent_gaps"])
        self.assertTrue(all(row["parent_count"] == 250 and row["parents_truncated"]
                            for row in result["artifacts"]["artifacts"]))

    def test_verification_unrelated_citation_cannot_support_claim(self):
        result = self.analyze("VERIFICATIONINT", [
            self.record("r1", {"claim": self.claim("active"), "support_record_ids": ["r2"]}),
            self.record("r2", {"claims": [self.claim("active", subject="other-asset"), "bad-row"]}, "s2")])
        item = result["artifacts"]["verification"][0]
        self.assertEqual(item["assessment"], "INSUFFICIENT_CITED_ASSERTIONS")
        self.assertEqual(item["support_record_ids"], [])
        self.assertIn("citation_does_not_entail_claim", {row["code"] for row in result["issues"]})
        self.assertIn("malformed_cited_assertion", {row["code"] for row in result["issues"]})

    def test_verification_bad_local_hash_prevents_citation_support(self):
        result = self.analyze("VERIFICATIONINT", [
            self.record("r1", {"claim": self.claim("active"), "support_record_ids": ["r2"]}),
            self.record("r2", {"claims": [self.claim("active")], "content_text": "abc",
                               "sha256": "f" * 64}, "s2")])
        self.assertEqual(result["artifacts"]["verification"][0]["support_record_ids"], [])
        self.assertIn("cited_content_hash_mismatch", {row["code"] for row in result["issues"]})

    def test_hypotheses_do_not_multiply_weight_for_copied_origin(self):
        sources = [
            {"source_id": "s1", "uri": "urn:fixture:s1"},
            {"source_id": "s2", "uri": "urn:fixture:s2", "original_source_id": "wire"},
            {"source_id": "s3", "uri": "urn:fixture:s3", "original_source_id": "wire"}]
        result = self.analyze("HYPOTHESISINT", [
            self.record("r1", {"hypotheses": [{"id": "h1", "statement": "First"},
                                             {"id": "h2", "statement": "Second"}],
                "evidence": [{"record_id": "r2", "assessments": {"h1": "supports"}},
                             {"record_id": "r3", "assessments": {"h1": "supports"}}]}),
            self.record("r2", {"observation": "original"}, "s2"),
            self.record("r3", {"observation": "copy"}, "s3")], sources)
        item = result["artifacts"]["hypotheses"][0]
        self.assertEqual(item["ranking"][0]["support_weight"], 1)
        self.assertFalse(item["probabilities_calibrated"])
        self.assertEqual(item["ranking"][1]["unknown_assessments"], 2)
        self.assertEqual(result["issues"], [])

    def test_hypothesis_tied_rankings_are_sensitive_and_duplicate_ids_reject(self):
        result = self.analyze("HYPOTHESISINT", [
            self.record("r1", {"hypotheses": [{"id": "h1", "statement": "One"},
                                             {"id": "h2", "statement": "Two"}],
                "evidence": [{"record_id": "r2", "weight": 0.5,
                              "assessments": {"h1": "supports", "h2": "supports"}}]}),
            self.record("r2", {"observation": "ambiguous"})])
        self.assertTrue(result["artifacts"]["hypotheses"][0]["ranking_sensitive"])
        bad = self.analyze("HYPOTHESISINT", [self.record("r1", {
            "hypotheses": [{"id": "same", "statement": "One"}, {"id": "same", "statement": "Two"}],
            "evidence": []})])
        self.assertEqual(bad["metrics"]["hypothesis_matrices"], 0)

    def test_hypothesis_malformed_record_identifier_and_stance_are_issues(self):
        result = self.analyze("HYPOTHESISINT", [
            self.record("r1", {"hypotheses": [{"id": "h", "statement": "One"}],
                "evidence": [{"record_id": {}}, {"record_id": "r2", "assessments": {"h": {}}}]}),
            self.record("r2", {"value": 1})])
        codes = {row["code"] for row in result["issues"]}
        self.assertIn("unknown_hypothesis_evidence", codes)
        self.assertIn("invalid_hypothesis_stance", codes)

    def test_falsification_finds_cited_counterexample_without_proving_hypothesis(self):
        result = self.analyze("FALSIFICATIONINT", [
            self.record("r1", {"hypothesis_id": "all-cool", "tests": [{
                "test_id": "temperature-bound", "field": "temperature", "operator": "lte",
                "expected_value": 10, "record_ids": ["r2", "r3"]}]}),
            self.record("r2", {"temperature": 9}), self.record("r3", {"temperature": 12})])
        item = result["artifacts"]["falsification"][0]
        self.assertEqual(item["tests"][0]["state"], "COUNTEREXAMPLE_IN_SUPPLIED_RECORDS")
        self.assertEqual(item["tests"][0]["counterexample_record_ids"], ["r3"])
        self.assertFalse(item["hypothesis_proven_true"])
        self.assertEqual(result["issues"], [])

    def test_falsification_missing_field_is_unknown_not_null_or_counterexample(self):
        result = self.analyze("FALSIFICATIONINT", [
            self.record("r1", {"hypothesis_id": "nullable", "tests": [{
                "test_id": "null-test", "field": "value", "operator": "eq",
                "expected_value": None, "record_ids": ["r2", "r3"]}]}),
            self.record("r2", {"value": None}), self.record("r3", {})])
        test = result["artifacts"]["falsification"][0]["tests"][0]
        self.assertEqual(test["state"], "INCONCLUSIVE")
        self.assertEqual(test["passing_record_ids"], ["r2"])
        self.assertEqual(test["unknown_record_ids"], ["r3"])

    def test_falsification_absence_without_complete_scope_does_not_refute_existence(self):
        result = self.analyze("FALSIFICATIONINT", [
            self.record("r1", {"hypothesis_id": "some-cool", "tests": [{
                "test_id": "exists", "claim_kind": "existential", "field": "temperature",
                "operator": "lt", "expected_value": 10, "record_ids": ["r2"]}]}),
            self.record("r2", {"temperature": 12})])
        self.assertEqual(result["artifacts"]["falsification"][0]["tests"][0]["state"], "INCONCLUSIVE")

    def test_falsification_unhashable_operator_is_rejected_without_execution(self):
        result = self.analyze("FALSIFICATIONINT", [self.record("r1", {
            "hypothesis_id": "h", "tests": [{"test_id": "bad", "field": "x",
                "operator": {}, "expected_value": 1, "record_ids": []}]})])
        self.assertIn("unsupported_falsification_test", {row["code"] for row in result["issues"]})

    def test_trust_calibration_has_small_sample_uncertainty_and_excludes_unresolved(self):
        result = self.analyze("TRUSTINT", [self.record("r1", {
            "context": "weather", "assessments": [
                {"prediction_id": "p1", "prediction": 0.9, "outcome": True},
                {"prediction_id": "p2", "prediction": 0.1, "outcome": False},
                {"prediction_id": "p3", "prediction": 0.2, "outcome": None}]})])
        item = result["artifacts"]["calibration"][0]
        self.assertEqual(item["resolved_samples"], 2)
        self.assertAlmostEqual(item["brier_score"], 0.01)
        self.assertEqual(item["threshold_accuracy"], 1)
        self.assertLess(item["accuracy_wilson_95"][0], 0.5)
        self.assertFalse(item["global_source_trust_verified"])
        self.assertEqual(result["metrics"]["unresolved_outcomes"], 1)

    def test_trust_duplicate_prediction_outcomes_are_not_first_wins(self):
        result = self.analyze("TRUSTINT", [self.record("r1", {
            "context": "weather", "assessments": [
                {"prediction_id": "same", "prediction": 0.9, "outcome": True},
                {"prediction_id": "same", "prediction": 0.9, "outcome": False}]})])
        self.assertEqual(result["metrics"]["calibration_contexts"], 0)
        self.assertEqual(result["metrics"]["ambiguous_prediction_groups"], 1)
        self.assertIn("duplicate_trust_prediction", {row["code"] for row in result["issues"]})

    def test_trust_future_outcome_is_unresolved_and_string_true_is_invalid(self):
        result = self.analyze("TRUSTINT", [self.record("r1", {
            "context": "weather", "assessments": [
                {"prediction": 0.9, "outcome": True, "resolved_at": "2027-01-01T00:00:00Z"},
                {"prediction": 0.9, "outcome": "true"}]})])
        self.assertEqual(result["metrics"]["calibration_contexts"], 0)
        self.assertEqual(result["metrics"]["unresolved_outcomes"], 1)
        self.assertIn("invalid_trust_outcome", {row["code"] for row in result["issues"]})


if __name__ == "__main__":
    unittest.main()
