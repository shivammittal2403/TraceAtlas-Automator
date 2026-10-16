"""Nonempty semantic/adversarial tests for all sixteen network employees."""
import copy
import unittest
from unittest.mock import patch

from traceatlas.workforce.discipline_engines import invoke_employee
from traceatlas.workforce.discipline_engines.network import HANDLERS


def record(identifier, data, source="s1"):
    return {"record_id": identifier, "source_id": source, "data": data}


def payload(label, records):
    return {"case_id": "case-network", "task_id": "task-network",
            "discipline": label, "objective": "Review supplied synthetic observations",
            "as_of": "2026-10-15T00:00:00Z",
            "sources": [{"source_id": "s1", "uri": "urn:fixture:s1"},
                        {"source_id": "s2", "uri": "urn:fixture:s2"}],
            "records": records}


class NetworkEmployeesTests(unittest.TestCase):
    def analyze(self, label, records):
        value = payload(label, records)
        before = copy.deepcopy(value)
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("subprocess.run", side_effect=AssertionError("process forbidden")):
            result = invoke_employee(value, evidence_ids=("evidence-fixture",))
        self.assertEqual(value, before)
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["model_calls"], 0)
        self.assertFalse(result["source_authenticity_verified"])
        for finding in result["findings"]:
            refs = {row["record_id"]: row for row in records}
            self.assertTrue(set(finding["record_ids"]) <= set(refs))
            self.assertEqual(set(finding["source_ids"]), {refs[key]["source_id"] for key in finding["record_ids"]})
            self.assertEqual(finding["canonical_evidence_ids"], ["evidence-fixture"])
        return result

    def test_domain_idna_expiry_and_conflicting_active_owners(self):
        result = self.analyze("DOMAININT", [
            record("r1", {"domain": "BÜCHER.example.", "registrant_id": "owner-a", "expires_at": "2027-01-01"}),
            record("r2", {"domain": "xn--bcher-kva.example", "registrant_id": "owner-b"}, "s2"),
            record("r3", {"domain": "old.example", "expires_at": "2025-01-01"}),
        ])
        self.assertEqual(result["metrics"]["owner_conflicts"], 1)
        rows = result["artifacts"]["registrations"]
        self.assertEqual(rows[0]["domain"], "xn--bcher-kva.example")
        self.assertTrue(rows[2]["expired_at_snapshot"])
        self.assertEqual(set(result["findings"][0]["record_ids"]), {"r1", "r2"})

    def test_domain_reversed_lifetime_is_invalid(self):
        result = self.analyze("DOMAININT", [record("r1", {
            "domain": "example.org", "created_at": "2026-01-01", "expires_at": "2025-01-01"})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_dns_cycle_and_exclusivity_keep_references(self):
        result = self.analyze("DNSINT", [
            record("r1", {"name": "a.example", "type": "CNAME", "value": "b.example", "ttl": 60}),
            record("r2", {"name": "b.example", "type": "CNAME", "value": "a.example"}, "s2"),
            record("r3", {"name": "a.example", "type": "A", "value": "192.0.2.1"}),
        ])
        self.assertEqual(result["metrics"]["cname_cycles"], 1)
        self.assertEqual(result["metrics"]["cname_conflicts"], 1)
        cycle = next(row for row in result["findings"] if row["kind"] == "dns_cname_cycle")
        self.assertEqual(set(cycle["record_ids"]), {"r1", "r2"})

    def test_dns_wrong_address_family_and_boolean_ttl_rejected(self):
        result = self.analyze("DNSINT", [
            record("r1", {"name": "a.example", "type": "AAAA", "value": "192.0.2.1"}),
            record("r2", {"name": "a.example", "type": "A", "value": "192.0.2.1", "ttl": True}),
        ])
        self.assertEqual(result["metrics"]["accepted_records"], 0)

    def test_ip_prefix_membership_and_mapped_ipv4(self):
        result = self.analyze("IPINT", [
            record("r1", {"ip": "2001:0db8::1", "prefixes": ["2001:db8::/32", "192.0.2.0/24"], "ports": [443, 443]}),
            record("r2", {"ip": "::ffff:192.0.2.1"}),
        ])
        rows = result["artifacts"]["addresses"]
        self.assertEqual(rows[0]["ip"], "2001:db8::1")
        self.assertEqual(rows[0]["matching_prefixes"], ["2001:db8::/32"])
        self.assertEqual(rows[0]["observed_ports"], [443])
        self.assertEqual(rows[1]["mapped_ipv4"], "192.0.2.1")

    def test_ip_hostname_and_scope_are_rejected(self):
        result = self.analyze("IPINT", [record("r1", {"ip": "example.org"}),
                                       record("r2", {"ip": "fe80::1%eth0"})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_asn_private_ranges_and_owner_conflict(self):
        result = self.analyze("ASNINT", [
            record("r1", {"asn": "AS64512", "prefixes": ["192.0.2.0/24"], "organization_id": "org-a"}),
            record("r2", {"asn": 64512, "prefixes": [], "organization_id": "org-b"}, "s2"),
        ])
        self.assertTrue(result["artifacts"]["systems"][0]["private_use"])
        self.assertEqual(result["metrics"]["organization_conflicts"], 1)

    def test_asn_uint_overflow_and_noncanonical_prefix_rejected(self):
        result = self.analyze("ASNINT", [record("r1", {"asn": 4294967296, "prefixes": []}),
                                        record("r2", {"asn": 123, "prefixes": ["192.0.2.1/24"]})])
        self.assertEqual(result["metrics"]["accepted_records"], 0)

    def test_bgp_valid_if_any_covering_vrp_matches_and_prepends_are_not_loops(self):
        result = self.analyze("BGPINT", [record("r1", {
            "prefix": "192.0.2.0/24", "origin_asn": 64496, "as_path": [64497, 64497, 64496],
            "roas": [{"prefix": "192.0.0.0/16", "asn": 64498, "max_length": 24},
                     {"prefix": "192.0.2.0/24", "asn": 64496}],
        })])
        route = result["artifacts"]["routes"][0]
        self.assertEqual(route["origin_validation"], "VALID")
        self.assertEqual(route["covering_vrps"], 2)
        self.assertFalse(route["nonconsecutive_as_loop"])

    def test_bgp_invalid_notfound_as0_and_path_loops_distinct(self):
        result = self.analyze("BGPINT", [
            record("r1", {"prefix": "192.0.2.0/25", "origin_asn": 64496,
                          "roas": [{"prefix": "192.0.2.0/24", "asn": 64496, "max_length": 24}],
                          "as_path": [64496, 64497, 64496]}),
            record("r2", {"prefix": "198.51.100.0/24", "origin_asn": 64496, "roas": []}),
            record("r3", {"prefix": "203.0.113.0/24", "origin_asn": 0,
                          "roas": [{"prefix": "203.0.113.0/24", "asn": 0}]}),
        ])
        rows = result["artifacts"]["routes"]
        self.assertEqual([row["origin_validation"] for row in rows], ["INVALID", "NOT_FOUND", "INVALID"])
        self.assertTrue(rows[0]["nonconsecutive_as_loop"])

    def test_net_components_bridges_and_isolation(self):
        result = self.analyze("NETINT", [record("r1", {
            "nodes": ["a", "b", "c", "d", "e"],
            "links": [["a", "b"], ["b", "c"], ["c", "a"], ["c", "d"]],
        })])
        graph = result["artifacts"]["topologies"][0]
        self.assertEqual(graph["connected_components"], [["a", "b", "c", "d"], ["e"]])
        self.assertEqual(graph["bridges"], [["c", "d"]])
        self.assertEqual(graph["isolated_nodes"], ["e"])

    def test_net_undeclared_endpoint_rejected(self):
        result = self.analyze("NETINT", [record("r1", {"nodes": ["a"], "links": [["a", "foreign"]]})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_infra_shared_hosting_does_not_infer_common_control(self):
        result = self.analyze("INFRAINT", [
            record("r1", {"asset_id": "one", "ips": ["192.0.2.1"], "domains": ["one.example"], "services": ["web"]}),
            record("r2", {"asset_id": "two", "ips": ["192.0.2.1"], "domains": ["two.example"]}, "s2"),
        ])
        self.assertEqual(result["metrics"]["shared_address_groups"], 1)
        self.assertFalse(result["artifacts"]["shared_addresses"][0]["ownership_inferred"])

    def test_infra_hostname_in_address_field_rejected(self):
        result = self.analyze("INFRAINT", [record("r1", {"asset_id": "one", "ips": ["one.example"]})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_cert_single_label_wildcard_and_validity(self):
        base = {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
                "dns_names": ["*.example.org"], "sha256": "ab" * 32}
        result = self.analyze("CERTINT", [record("r1", {**base, "target": "a.example.org"}),
                                         record("r2", {**base, "target": "b.a.example.org"})])
        rows = result["artifacts"]["certificates"]
        self.assertTrue(rows[0]["target_name_covered"])
        self.assertFalse(rows[1]["target_name_covered"])
        self.assertTrue(rows[0]["time_valid_at_snapshot"])
        self.assertFalse(rows[0]["chain_verified"])

    def test_cert_naive_time_and_invalid_fingerprint_rejected(self):
        result = self.analyze("CERTINT", [record("r1", {
            "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00Z",
            "dns_names": ["a.example"], "sha256": "broken"})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_tls_version_and_cipher_flags(self):
        result = self.analyze("TLSINT", [
            record("r1", {"version": "TLSv1.1", "cipher": "ECDHE-RSA-RC4-SHA"}),
            record("r2", {"version": "TLS1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                          "server_name": "a.example.org", "certificate_dns_names": ["*.example.org"]}),
        ])
        rows = result["artifacts"]["handshakes"]
        self.assertTrue(rows[0]["obsolete_protocol"])
        self.assertEqual(rows[0]["weak_cipher_tokens"], ["RC4"])
        self.assertFalse(rows[1]["obsolete_protocol"])
        self.assertTrue(rows[1]["certificate_name_covered"])

    def test_tls_unknown_version_not_silently_secure(self):
        result = self.analyze("TLSINT", [record("r1", {"version": "TLS9", "cipher": "new"})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_cloud_explicit_flags_and_wildcards_are_candidates(self):
        result = self.analyze("CLOUDINT", [record("r1", {
            "resource_id": "bucket-fixture", "public_access": True, "encrypted": False,
            "statements": [{"effect": "Allow", "actions": ["storage:*"], "resources": ["*"]},
                           {"effect": "Deny", "actions": ["*"], "resources": ["*"]}],
        })])
        item = result["artifacts"]["resources"][0]
        self.assertEqual(len(item["allow_wildcards"]), 1)
        self.assertEqual(item["review_flags"], ["declared_public_access", "declared_unencrypted"])
        self.assertIsNone(item["logging_enabled"])
        self.assertFalse(item["effective_permissions_computed"])

    def test_cloud_string_boolean_rejected(self):
        result = self.analyze("CLOUDINT", [record("r1", {"resource_id": "x", "public_access": "false"})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_host_baseline_and_support_end(self):
        result = self.analyze("HOSTINT", [record("r1", {
            "host_id": "host-1", "ports": [22, 443], "approved_ports": [443], "support_ends": "2026-10-01"})])
        item = result["artifacts"]["hosts"][0]
        self.assertEqual(item["ports_outside_baseline"], [22])
        self.assertTrue(item["support_ended_at_snapshot"])

    def test_host_absent_baseline_is_unknown_and_bad_port_rejected(self):
        result = self.analyze("HOSTINT", [record("r1", {"host_id": "h", "ports": [443]}),
                                         record("r2", {"host_id": "h2", "ports": [65536]})])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIsNone(result["artifacts"]["hosts"][0]["ports_outside_baseline"])

    def test_route_longest_prefix_then_distance_metric_and_ecmp(self):
        result = self.analyze("ROUTEINT", [record("r1", {
            "destination": "192.0.2.77", "routes": [
                {"prefix": "0.0.0.0/0", "next_hop": "198.51.100.1", "distance": 1, "metric": 1},
                {"prefix": "192.0.2.0/24", "next_hop": "198.51.100.2", "distance": 10, "metric": 5},
                {"prefix": "192.0.2.0/24", "next_hop": "198.51.100.3", "distance": 10, "metric": 5},
                {"prefix": "192.0.2.0/24", "next_hop": "198.51.100.4", "distance": 20, "metric": 0},
            ]})])
        decision = result["artifacts"]["decisions"][0]
        self.assertEqual(decision["selection_state"], "ECMP_CANDIDATE")
        self.assertEqual({row["next_hop"] for row in decision["selected_routes"]},
                         {"198.51.100.2", "198.51.100.3"})

    def test_route_no_match_distinct_from_invalid_family(self):
        result = self.analyze("ROUTEINT", [
            record("r1", {"destination": "192.0.2.1", "routes": []}),
            record("r2", {"destination": "192.0.2.1", "routes": [
                {"prefix": "192.0.2.0/24", "next_hop": "2001:db8::1"}]}),
        ])
        self.assertEqual(result["artifacts"]["decisions"][0]["selection_state"], "NO_ROUTE")
        self.assertEqual(result["status"], "PARTIAL")

    def test_cdn_shared_age_and_cookie_review_flag(self):
        result = self.analyze("CDNINT", [record("r1", {
            "url": "https://example.org/a", "headers": {
                "Cache-Control": "public, max-age=30, s-maxage=60", "Age": "40",
                "Vary": "Accept-Encoding", "Set-Cookie": "fixture=1"}})])
        item = result["artifacts"]["cache_observations"][0]
        self.assertTrue(item["fresh_under_supplied_age"])
        self.assertEqual(item["declared_shared_lifetime_seconds"], 60)
        self.assertEqual(item["review_flags"], ["public_response_with_set_cookie"])
        self.assertFalse(item["provider_attribution_verified"])

    def test_cdn_negative_age_rejected(self):
        result = self.analyze("CDNINT", [record("r1", {"url": "https://example.org", "headers": {"age": "-1"}})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_mail_static_spf_budget_null_mx_and_dmarc(self):
        result = self.analyze("MAILINT", [record("r1", {
            "domain": "example.org", "mx": [{"preference": 0, "exchange": "."}],
            "spf": "v=spf1 " + " ".join("include:s" + str(i) + ".example" for i in range(11)) + " +all",
            "dmarc": "v=DMARC1; p=reject; pct=50",
            "dkim": [{"selector": "retired", "record": "v=DKIM1; k=rsa; p="}],
        })])
        item = result["artifacts"]["mail_domains"][0]
        self.assertTrue(item["null_mx"])
        self.assertTrue(item["spf_direct_lookup_budget_exceeded"])
        self.assertTrue(item["spf_permissive_all"])
        self.assertTrue(item["dkim_selectors"][0]["revoked"])
        self.assertEqual(item["dmarc"]["p"], "reject")
        self.assertEqual(item["spf_evaluation_state"], "STATIC_ONLY")

    def test_mail_duplicate_dmarc_tags_and_mixed_null_mx_rejected(self):
        result = self.analyze("MAILINT", [
            record("r1", {"domain": "example.org", "dmarc": "v=DMARC1; p=none; p=reject"}),
            record("r2", {"domain": "example.org", "mx": [{"preference": 0, "exchange": "."},
                                                       {"preference": 10, "exchange": "mx.example.org"}]}),
        ])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_sigint_rms_occupancy_and_nyquist(self):
        result = self.analyze("SIGINT", [record("r1", {
            "center_frequency_hz": 1000, "bandwidth_hz": 100, "sample_rate_hz": 150,
            "samples": [0, 2, -2, 0], "occupancy_threshold": 1})])
        item = result["artifacts"]["signals"][0]
        self.assertAlmostEqual(item["rms"], 2 ** 0.5)
        self.assertEqual(item["mean"], 0)
        self.assertEqual(item["threshold_occupancy_fraction"], 0.5)
        self.assertFalse(item["real_sample_nyquist_sufficient"])

    def test_sigint_empty_samples_not_successful(self):
        result = self.analyze("SIGINT", [record("r1", {
            "center_frequency_hz": 1000, "bandwidth_hz": 100, "sample_rate_hz": 1000, "samples": []})])
        self.assertEqual(result["status"], "INVALID_DATA")

    def test_elint_constant_pri_duty_cycle_and_jitter(self):
        result = self.analyze("ELINT", [record("r1", {
            "frequency_hz": 1e9, "pulse_width_us": 10, "pulse_arrivals_us": [0, 100, 200, 300]})])
        item = result["artifacts"]["pulse_trains"][0]
        self.assertEqual(item["mean_pri_us"], 100)
        self.assertEqual(item["prf_hz"], 10000)
        self.assertEqual(item["duty_cycle_fraction"], 0.1)
        self.assertEqual(item["normalized_pri_jitter"], 0)
        self.assertFalse(item["emitter_identified"])

    def test_elint_nonmonotonic_and_overlapping_pulses_rejected(self):
        result = self.analyze("ELINT", [
            record("r1", {"frequency_hz": 1000, "pulse_width_us": 10, "pulse_arrivals_us": [0, 100, 50]}),
            record("r2", {"frequency_hz": 1000, "pulse_width_us": 110, "pulse_arrivals_us": [0, 100, 200]}),
        ])
        self.assertEqual(result["status"], "INVALID_DATA")


if __name__ == "__main__":
    unittest.main()
