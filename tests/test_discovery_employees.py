"""Semantic discovery tests through the production context."""
import unittest

from traceatlas.workforce.discipline_engines.common import make_context
from traceatlas.workforce.discipline_engines.discovery import HANDLERS, parse_query


class DiscoveryEmployeesTests(unittest.TestCase):
    def run_employee(self, label, records, sources=None):
        payload = {
            "case_id": "case-test", "task_id": "task-test",
            "discipline": label, "objective": "Analyze supplied records",
            "as_of": "2026-10-15T00:00:00Z",
            "sources": sources or [
                {"source_id": "s1", "uri": "urn:fixture:s1"},
                {"source_id": "s2", "uri": "urn:fixture:s2"},
                {"source_id": "s3", "uri": "urn:fixture:s3"},
            ],
            "records": records, "parameters": {},
        }
        return HANDLERS[label](make_context(payload))

    @staticmethod
    def record(identifier, data, source="s1", observed=None):
        result = {"record_id": identifier, "source_id": source, "data": data}
        if observed is not None:
            result["observed_at"] = observed
        return result

    def test_osint_copied_sources_do_not_become_independent_origins(self):
        sources = [
            {"source_id": name, "uri": "urn:fixture:" + name,
             "original_source_id": "wire-origin"}
            for name in ("s1", "s2", "s3")
        ]
        records = [self.record("r" + str(i), {
            "claims": [{"subject": "org-a", "predicate": "staff", "value": 10}],
        }, source) for i, source in enumerate(("s1", "s2", "s3"), 1)]
        result = self.run_employee("OSINT", records, sources)
        self.assertEqual(result["metrics"]["declared_origin_groups"], 1)
        self.assertEqual(result["metrics"]["source_count"], 3)
        self.assertFalse(result["artifacts"]["assertion_matrix"][0]["independence_verified"])

    def test_osint_conflicts_preserve_both_assertions(self):
        result = self.run_employee("OSINT", [
            self.record("r1", {"claims": [{"subject": "org", "predicate": "status", "value": "active"}]}),
            self.record("r2", {"claims": [{"subject": "org", "predicate": "status", "value": "closed"}]}, "s2"),
        ])
        self.assertEqual(result["metrics"]["conflicting_groups"], 1)
        variants = result["artifacts"]["assertion_matrix"][0]["variants"]
        self.assertEqual({row["value"] for row in variants}, {"active", "closed"})
        self.assertEqual(set(result["findings"][0]["record_ids"]), {"r1", "r2"})

    def test_osint_equivalent_numbers_agree_but_boolean_is_distinct(self):
        result = self.run_employee("OSINT", [
            self.record("r1", {"claims": [{"subject": "x", "predicate": "count", "value": 1}]}),
            self.record("r2", {"claims": [{"subject": "x", "predicate": "count", "value": 1.0}]}, "s2"),
        ])
        self.assertEqual(result["metrics"]["conflicting_groups"], 0)
        result = self.run_employee("OSINT", [
            self.record("r1", {"claims": [{"subject": "x", "predicate": "count", "value": 1}]}),
            self.record("r2", {"claims": [{"subject": "x", "predicate": "count", "value": True}]}, "s2"),
        ])
        self.assertEqual(result["metrics"]["conflicting_groups"], 1)

    def test_osint_future_validity_does_not_enter_current_snapshot(self):
        result = self.run_employee("OSINT", [self.record("r1", {"claims": [{
            "subject": "org", "predicate": "status", "value": "closed",
            "valid_from": "2027-01-01",
        }]})])
        self.assertEqual(result["metrics"]["accepted_assertions"], 0)
        self.assertIn("outside_as_of", {row["code"] for row in result["issues"]})

    def test_web_extracts_visible_text_canonical_links_and_unicode(self):
        result = self.run_employee("WEBINT", [self.record("r1", {
            "url": "https://EXAMPLE.com:443/start#fragment",
            "html": '<head><title>अभिलेख</title><link rel="canonical" href="/report"></head>'
                    '<body><h1>Report</h1><script>privateScriptValue</script>'
                    '<style>hiddenCSS</style><p>Visible evidence</p>'
                    '<a href="/source#top">Source</a><a href="javascript:alert(1)">Bad</a></body>',
        })])
        capture = result["artifacts"]["captures"][0]
        self.assertEqual(capture["title"], "अभिलेख")
        self.assertEqual(capture["canonical_url"], "https://example.com/report")
        self.assertNotIn("privateScriptValue", capture["visible_text"])
        self.assertNotIn("hiddenCSS", capture["visible_text"])
        self.assertEqual(capture["links"], ["https://example.com/source"])
        self.assertEqual(capture["heading_counts"], {"h1": 1})

    def test_web_change_requires_orderable_capture_times(self):
        records = [
            self.record("r1", {"url": "https://example.com", "text": "one two"},
                        observed="2026-10-13T12:00:00Z"),
            self.record("r2", {"url": "https://example.com", "text": "one three four"},
                        observed="2026-10-14T12:00:00Z"),
        ]
        result = self.run_employee("WEBINT", records)
        self.assertEqual(result["metrics"]["content_changes"], 1)
        change = result["artifacts"]["changes"][0]
        self.assertEqual(change["added_word_count"], 2)
        self.assertEqual(change["removed_word_count"], 1)
        self.assertEqual(change["similarity_basis"], "token_multiset_jaccard")
        self.assertAlmostEqual(change["text_similarity"], 1 / 4)

    def test_web_large_repeated_content_uses_linear_token_similarity(self):
        repeated = "a " * 120000
        result = self.run_employee("WEBINT", [
            self.record("r1", {"url": "https://example.com", "text": repeated + "x"},
                        observed="2026-10-13T12:00:00Z"),
            self.record("r2", {"url": "https://example.com", "text": repeated + "y"},
                        observed="2026-10-14T12:00:00Z"),
        ])
        change = result["artifacts"]["changes"][0]
        self.assertEqual(change["similarity_basis"], "token_multiset_jaccard")
        self.assertAlmostEqual(change["text_similarity"], 120000 / 120002)
        self.assertEqual(change["added_word_count"], 1)
        self.assertEqual(change["removed_word_count"], 1)

    def test_web_same_time_conflict_is_not_ordered(self):
        result = self.run_employee("WEBINT", [
            self.record("r1", {"url": "https://example.com", "text": "first"},
                        observed="2026-10-14T12:00:00Z"),
            self.record("r2", {"url": "https://example.com", "text": "second"},
                        observed="2026-10-14T12:00:00Z"),
        ])
        self.assertEqual(result["metrics"]["content_changes"], 0)
        self.assertIn("simultaneous_capture_conflict", {row["code"] for row in result["issues"]})

    def test_search_rank_fusion_deduplicates_same_engine_votes(self):
        result = self.run_employee("SEARCHINT", [
            self.record("r1", {"query": "public report", "engine": "alpha", "results": [
                {"url": "https://example.com/a#one", "rank": 1},
                {"url": "https://example.com/a#two", "rank": 9},
            ]}),
            self.record("r2", {"query": "public report", "engine": "beta", "results": [
                {"url": "https://example.com/a", "rank": 2},
            ]}, "s2"),
        ])
        self.assertEqual(result["metrics"]["supplied_results"], 3)
        self.assertEqual(result["metrics"]["unique_query_urls"], 1)
        item = result["artifacts"]["ranked_results"][0]
        self.assertAlmostEqual(item["reciprocal_rank_score"], 1 / 61 + 1 / 62)
        self.assertFalse(item["content_verified"])

    def test_search_zero_rank_is_rejected(self):
        result = self.run_employee("SEARCHINT", [self.record("r1", {
            "query": "report", "results": [{"url": "https://example.com", "rank": 0}],
        })])
        self.assertEqual(result["metrics"]["unique_query_urls"], 0)
        self.assertIn("invalid_rank", {row["code"] for row in result["issues"]})

    def test_dork_parses_quoted_operators_and_checks_captured_results(self):
        result = self.run_employee("DORKINT", [self.record("r1", {
            "query": 'site:example.com filetype:pdf intitle:"Annual Report"',
            "provider": "brave",
            "results": [
                {"url": "https://docs.example.com/report.pdf", "title": "Annual Report 2026"},
                {"url": "https://elsewhere.example/report.pdf", "title": "Annual Report 2026"},
            ],
        })])
        self.assertEqual(result["metrics"]["valid_queries"], 1)
        self.assertEqual(result["metrics"]["constraint_mismatches"], 1)
        operation = result["artifacts"]["source_operations"][0]
        self.assertEqual(operation["tool_id"], "search.execute")
        self.assertEqual(operation["source_id"], "brave")
        self.assertEqual(operation["dispatch_state"], "NOT_DISPATCHED")
        self.assertEqual(operation["arguments"]["query_kind"], "typed-public-query")

    def test_dork_unknown_operator_blocks_operation_without_silent_rewrite(self):
        result = self.run_employee("DORKINT", [self.record("r1", {
            "query": "cache:example.com report",
        })])
        self.assertEqual(result["metrics"]["source_operations"], 0)
        self.assertIn("unsupported_operator", {row["code"] for row in result["issues"]})

    def test_dork_untrusted_executed_flag_does_not_claim_dispatch(self):
        result = self.run_employee("DORKINT", [self.record("r1", {
            "query": 'site:example.com "report"', "query_executed": True,
        })])
        self.assertEqual(
            result["artifacts"]["source_operations"][0]["dispatch_state"],
            "NOT_DISPATCHED",
        )

    def test_dork_bad_quotes_and_unsupported_boolean_syntax_fail(self):
        for query in ('intitle:"unterminated', "report OR records"):
            with self.subTest(query=query), self.assertRaises(ValueError):
                parse_query(query)

    def test_archive_reads_cdx_and_separates_http_failures_from_content_changes(self):
        result = self.run_employee("ARCHIVEINT", [self.record("r1", {
            "cdx": [
                ["timestamp", "original", "statuscode", "digest"],
                ["20261012000000", "https://example.com/", "200", "A"],
                ["20261013000000", "https://example.com/", "404", "ERROR"],
                ["20261014000000", "https://example.com/", "200", "B"],
            ],
        })])
        self.assertEqual(result["metrics"]["accepted_captures"], 3)
        self.assertEqual(result["metrics"]["digest_changes"], 1)
        history = result["artifacts"]["histories"][0]
        self.assertEqual(history["successful_captures"], 2)
        self.assertEqual(history["known_content_digests"], 2)
        self.assertEqual(history["largest_observed_gap_seconds"], 86400)

    def test_archive_unhashable_header_is_reported_as_input_issue(self):
        for malformed in ([["timestamp"], "original"], [{"timestamp": "bad"}, "original"]):
            result = self.run_employee("ARCHIVEINT", [self.record("r1", {
                "cdx": [malformed, ["20261014000000", "https://example.com/"]],
            })])
            self.assertEqual(result["metrics"]["accepted_captures"], 0)
            self.assertIn("invalid_cdx_header", {row["code"] for row in result["issues"]})

    def test_archive_duplicate_capture_and_missing_digest_are_explicit(self):
        capture = {"url": "https://example.com", "timestamp": "20261014000000", "status": 200}
        result = self.run_employee("ARCHIVEINT", [self.record("r1", {
            "captures": [capture, dict(capture)],
        })])
        self.assertEqual(result["metrics"]["duplicate_capture_rows"], 1)
        self.assertEqual(result["metrics"]["digest_changes"], 0)
        self.assertEqual(result["artifacts"]["histories"][0]["unknown_digest_captures"], 1)

    def test_archive_future_capture_is_rejected(self):
        result = self.run_employee("ARCHIVEINT", [self.record("r1", {
            "captures": [{"url": "https://example.com", "timestamp": "20271014000000",
                          "status": 200, "digest": "A"}],
        })])
        self.assertEqual(result["metrics"]["accepted_captures"], 0)

    def test_news_identical_reprints_form_one_content_cluster(self):
        body = "A supplied article with the same complete body across published copies."
        result = self.run_employee("NEWSINT", [
            self.record("r1", {"url": "https://one.example/a", "title": "First", "body": body}),
            self.record("r2", {"url": "https://two.example/b", "title": "Changed headline",
                               "body": body}, "s2"),
        ])
        self.assertEqual(result["metrics"]["content_clusters"], 1)
        self.assertEqual(result["metrics"]["candidate_republished_articles"], 1)
        self.assertFalse(result["artifacts"]["clusters"][0]["independence_verified"])
        self.assertEqual(result["artifacts"]["clusters"][0]["copy_links"][0]["method"], "exact_body")

    def test_news_matching_headlines_alone_do_not_prove_republication(self):
        result = self.run_employee("NEWSINT", [
            self.record("r1", {"url": "https://one.example/a", "title": "Election result"}),
            self.record("r2", {"url": "https://two.example/b", "title": "Election result"}, "s2"),
        ])
        self.assertEqual(result["metrics"]["content_clusters"], 2)

    def test_dataset_missing_null_zero_and_boolean_remain_distinct(self):
        result = self.run_employee("DATASETINT", [self.record("r1", {
            "rows": [{"x": None}, {"x": 0}, {}, {"x": False}],
            "schema": {"x": "number"},
        })])
        profile = result["artifacts"]["profiles"][0]
        self.assertEqual(profile["columns"]["x"]["type_counts"],
                         {"null": 1, "integer": 1, "missing": 1, "boolean": 1})
        self.assertEqual(profile["columns"]["x"]["numeric"]["mean"], 0)
        self.assertEqual(profile["schema_violation_count"], 1)

    def test_dataset_composite_duplicate_keys_preserve_row_positions(self):
        result = self.run_employee("DATASETINT", [self.record("r1", {
            "key_fields": ["country", "id"],
            "rows": [{"country": "IN", "id": 1}, {"country": "IN", "id": 1},
                     {"country": "US", "id": 1}, {"country": "IN"}],
        })])
        profile = result["artifacts"]["profiles"][0]
        self.assertEqual(profile["duplicate_key_row_groups"], [[0, 1]])
        self.assertEqual(profile["incomplete_key_rows"], [3])

    def test_dataset_schema_drift_requires_ordered_snapshots(self):
        result = self.run_employee("DATASETINT", [
            self.record("r1", {"dataset_id": "d", "rows": [{"id": 1, "value": 2}]},
                        observed="2026-10-13T00:00:00Z"),
            self.record("r2", {"dataset_id": "d", "rows": [{"id": "1", "new": 2}]},
                        observed="2026-10-14T00:00:00Z"),
        ])
        drift = result["artifacts"]["schema_drifts"][0]
        self.assertEqual(drift["added_columns"], ["new"])
        self.assertEqual(drift["removed_columns"], ["value"])
        self.assertEqual(drift["changed_type_columns"], ["id"])

    def test_events_same_location_different_times_are_separate(self):
        result = self.run_employee("EVENTINT", [
            self.record("r1", {"event_type": "meeting", "start": "2026-10-14T01:00:00Z",
                               "end": "2026-10-14T02:00:00Z", "place_id": "hall"}),
            self.record("r2", {"event_type": "meeting", "start": "2026-10-14T01:30:00Z",
                               "end": "2026-10-14T02:30:00Z", "place_id": "hall"}, "s2"),
            self.record("r3", {"event_type": "meeting", "start": "2026-10-14T12:00:00Z",
                               "end": "2026-10-14T13:00:00Z", "place_id": "hall"}, "s3"),
        ])
        self.assertEqual(result["metrics"]["candidate_clusters"], 2)
        self.assertTrue(all(row["candidate_only"] for row in result["artifacts"]["event_clusters"]))

    def test_event_spatial_chain_does_not_merge_incompatible_endpoints(self):
        records = [self.record("r" + str(i), {
            "event_type": "observation", "start": "2026-10-14T01:00:00Z",
            "latitude": 0, "longitude": longitude,
        }) for i, longitude in enumerate((0, 0.0008, 0.0016), 1)]
        result = self.run_employee("EVENTINT", records)
        self.assertEqual(result["metrics"]["candidate_clusters"], 2)

    def test_event_invalid_coordinate_does_not_become_a_location(self):
        result = self.run_employee("EVENTINT", [self.record("r1", {
            "event_type": "meeting", "start": "2026-10-14", "latitude": 91, "longitude": 0,
        })])
        self.assertEqual(result["metrics"]["events"], 0)
        self.assertIn("invalid_event", {row["code"] for row in result["issues"]})

    def test_timeline_date_precision_prevents_false_order(self):
        result = self.run_employee("TIMELINEINT", [
            self.record("r1", {"event_id": "day", "time": "2026-10-14"}),
            self.record("r2", {"event_id": "midday", "time": "2026-10-14T12:00:00Z"}),
            self.record("r3", {"event_id": "next", "time": "2026-10-15T00:00:00Z"}),
        ])
        self.assertIn(["r1", "r2"], result["artifacts"]["overlapping_pairs"])
        self.assertNotIn(["r1", "r2"], result["artifacts"]["certain_pairs"])
        self.assertIn(["r1", "r3"], result["artifacts"]["certain_pairs"])
        self.assertEqual(result["artifacts"]["intervals"][0]["precision"], "day")

    def test_timeline_detects_exact_cycle_without_marking_downstream_node_cyclic(self):
        result = self.run_employee("TIMELINEINT", [
            self.record("r1", {"event_id": "a", "time": "2026-10-14T01:00:00Z", "before": ["b"]}),
            self.record("r2", {"event_id": "b", "time": "2026-10-14T02:00:00Z", "before": ["a", "c"]}),
            self.record("r3", {"event_id": "c", "time": "2026-10-14T03:00:00Z"}),
        ])
        self.assertEqual(result["artifacts"]["cycles"], [["r1", "r2"]])
        self.assertEqual(result["metrics"]["time_order_conflicts"], 1)

    def test_timeline_naive_timestamp_and_ambiguous_identifier_do_not_silently_merge(self):
        result = self.run_employee("TIMELINEINT", [
            self.record("r1", {"event_id": "duplicate", "time": "2026-10-14T01:00:00Z"}),
            self.record("r2", {"event_id": "duplicate", "time": "2026-10-14T02:00:00Z"}),
            self.record("r3", {"event_id": "third", "time": "2026-10-14T03:00:00Z",
                               "after": ["duplicate"]}),
            self.record("r4", {"event_id": "naive", "time": "2026-10-14T04:00:00"}),
        ])
        self.assertEqual(result["metrics"]["events"], 3)
        self.assertEqual(result["metrics"]["declared_precedence_edges"], 0)
        codes = {row["code"] for row in result["issues"]}
        self.assertTrue({"ambiguous_event_identifier", "unresolved_precedence_target",
                         "invalid_timeline_time"}.issubset(codes))


if __name__ == "__main__":
    unittest.main()
