"""Offline adversarial integration tests; loopback fixtures are not live providers."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch, Mock
from urllib.parse import urlsplit, parse_qs

from traceatlas.db import CaseDB
from traceatlas.intelligence.provider import ProviderError
from traceatlas.intelligence.rdap import bootstrap_url, registry_url
from traceatlas.intelligence.transport import request, request_loopback_search
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.live_sources import readiness, select_sources, search_base
from traceatlas.workforce.pipeline import InvestigationPipeline, _live_facts
from traceatlas.workforce.service import WorkforceService
from traceatlas.workforce.registry import EmployeeRegistry

BOOTSTRAP = {"version": "1.0", "services": [[["org"], ["https://rdap.publicinterestregistry.org/rdap/"]]]}
STAMP = "2025-01-01T00:00:00+00:00"


class LiveSourceTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"TRACEATLAS_SEARCH_PROVIDER": "", "BRAVE_SEARCH_API_KEY": "",
                              "SEARXNG_URL": "", "IPDATA_API_KEY": "", "GREYNOISE_API_KEY": "",
                              "URLSCAN_API_KEY": "", "TRACEATLAS_WORKFORCE_KILL_SWITCH": ""})
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "case.db")
        self.db.create_case("live-case", "Synthetic source qualification", "Controlled fixture tests")
        self.service = WorkforceService(self.db, enabled=True)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()
        self.env.stop()

    def task(self, kind="domain", target="example.org", sources=None, tools=None, prices=None):
        stamp = datetime.now(timezone.utc)
        context = AuthorizationContext("1.0", "auth-live", "live-case", "analyst", "Synthetic fixture qualification",
            (kind + ":" + target,), ("request_collection", "propose_observation", "propose_claim"),
            tools or ("dns.lookup", "rdap.lookup", "archive.lookup", "ip.lookup", "search.execute", "evidence.retrieve"),
            "IN", "test-only", stamp.isoformat(), (stamp + timedelta(hours=1)).isoformat(), "b" * 64)
        self.service.register_authorization(context)
        plan = self.service.create_investigation_task(context.context_id, kind, target, "Qualify synthetic live sources", sources=sources, source_prices=prices)
        self.service.approve(plan["task"]["task_id"], actor_id="analyst", rationale="Reviewed the exact synthetic source plan",
                             envelope_digest=plan["envelope_digest"], authorized=True)
        return plan["task"]["task_id"]

    def test_full_live_capture_graph_report_and_offline_replay(self):
        os.environ["BRAVE_SEARCH_API_KEY"] = "fixture-key-not-a-real-credential"
        task = self.task(sources=("dns", "rdap", "urlscan", "wayback", "brave"), prices={"brave": 0})
        calls = []
        payloads = {
            "dns.google": {"Status": 0, "Question": [{"name": "example.org."}],
                           "Answer": [{"name": "example.org.", "type": 1, "data": "8.8.8.8"}]},
            "data.iana.org": BOOTSTRAP,
            "rdap.publicinterestregistry.org": {"objectClassName": "domain", "ldhName": "example.org", "handle": "TEST"},
            "urlscan.io": {"results": [{"page": {"domain": "example.org", "url": "https://example.org/", "ip": "8.8.8.8"},
                                         "task": {"time": "2024-01-01T00:00:00Z"}}]},
            "web.archive.org": [["timestamp", "original"], ["20240101000000", "https://example.org/old"]],
            "api.search.brave.com": {"query": {"original": '"example.org"'}, "web": {"results": [{"url": "https://example.org/about"}]}},
        }
        def requester(url, headers, timeout):
            calls.append(url)
            self.assertGreater(timeout, 0)
            if urlsplit(url).hostname == "api.search.brave.com":
                self.assertEqual(headers["X-Subscription-Token"], os.environ["BRAVE_SEARCH_API_KEY"])
            return 200, json.dumps(payloads[urlsplit(url).hostname]).encode()
        pipeline = InvestigationPipeline(self.service, self.root, requester=requester)
        product = pipeline.run(task, live=True, authorized=True)
        self.assertEqual(product["network_attempts"], 6)
        outcomes = product["replay_manifest"]["source_outcomes"]
        self.assertEqual(sum(row["attempts"] for row in outcomes), 6)
        self.assertTrue(all(row["status"] == "captured" for row in outcomes))
        self.assertEqual(len(product["replay_manifest"]["evidence"]), 6)
        self.assertEqual(product["plan"]["query_intents"][0]["state"], "executed")
        self.assertIn("search_listing_not_content_verification", product["analysis"]["information_gaps"])
        self.assertNotIn("no-captured-web-search", product["analysis"]["information_gaps"])
        self.assertIn("## Source collection", product["report_markdown"])
        self.assertNotIn(os.environ["BRAVE_SEARCH_API_KEY"], json.dumps(product))
        self.assertTrue(any(edge["edge_type"] == "search_result_url" for edge in product["analysis"]["graph"]["edges"]))
        calls.clear()
        self.assertTrue(pipeline.replay(task)["verified"])
        self.assertFalse(calls)

    def test_ip_providers_share_one_tool_without_duplicate_contract_values(self):
        task = self.task("ip", "8.8.8.8", ("ipwhois", "internetdb"))
        def requester(url, *_):
            payload = ({"ip": "8.8.8.8", "success": True, "country_code": "US", "connection": {"asn": 15169, "isp": "Example ISP"}}
                       if "ipwho.is" in url else {"ip": "8.8.8.8", "ports": [53]})
            return 200, json.dumps(payload).encode()
        product = InvestigationPipeline(self.service, self.root, requester=requester).run(task, live=True, authorized=True)
        self.assertEqual(product["result"]["tool_calls"], ["ip.lookup"])
        self.assertEqual(product["network_attempts"], 2)
        self.assertIn("ip_geolocation_not_person_location", product["analysis"]["information_gaps"])

    def test_new_environment_does_not_expand_an_approved_plan(self):
        task = self.task(sources=("dns",))
        os.environ["TRACEATLAS_SEARCH_PROVIDER"] = "brave"
        calls = []
        def requester(url, *_):
            calls.append(url)
            return 200, b'{"Status":0,"Question":[{"name":"example.org"}]}'
        product = InvestigationPipeline(self.service, self.root, requester=requester).run(task, live=True, authorized=True)
        self.assertEqual(product["plan"]["sources"], ["dns"])
        self.assertEqual(len(calls), 1)

    def test_source_tool_permission_is_required_before_task_creation(self):
        with self.assertRaisesRegex(ValueError, "authorization does not permit"):
            self.task(sources=("brave",), tools=("evidence.retrieve", "dns.lookup"))

    def test_employee_source_permission_is_required_before_task_creation(self):
        employee = self.service.registry.get("webint-infra-specialist")
        self.service.registry = EmployeeRegistry((replace(employee, allowed_sources=("dns",)),))
        with self.assertRaisesRegex(ValueError, "employee does not permit"):
            self.task(sources=("rdap",))

    def test_missing_key_is_visible_without_network_or_circuit_poisoning(self):
        task = self.task(sources=("brave",))
        pipeline = InvestigationPipeline(self.service, self.root, requester=lambda *_: self.fail("no credential means no request"))
        product = pipeline.run(task, live=True, authorized=True)
        self.assertEqual(product["network_attempts"], 0)
        self.assertEqual(product["replay_manifest"]["source_outcomes"][0]["reason"], "not_configured")
        self.assertEqual(product["plan"]["query_intents"][0]["state"], "skipped")
        self.assertFalse(self.db.connector_health())
        self.assertTrue(pipeline.replay(task)["verified"])

    def test_rate_limit_does_not_spend_remaining_attempts_retrying(self):
        task = self.task(sources=("dns",))
        calls = []
        def requester(url, *_):
            calls.append(url)
            return 429, b""
        product = InvestigationPipeline(self.service, self.root, requester=requester).run(task, live=True, authorized=True)
        self.assertEqual(len(calls), 1)
        self.assertIn("source-dns-provider_rate_limited", product["analysis"]["information_gaps"])

    def test_bootstrap_is_preserved_when_registry_is_not_approved(self):
        task = self.task(sources=("rdap",))
        calls = []
        def requester(url, *_):
            calls.append(url)
            return 200, json.dumps({"version": "1.0", "services": [[["org"], ["https://127.0.0.1/"]]]}).encode()
        pipeline = InvestigationPipeline(self.service, self.root, requester=requester)
        product = pipeline.run(task, live=True, authorized=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(product["replay_manifest"]["evidence"][0]["source_id"], "rdap_bootstrap")
        self.assertIn("source-rdap-provider_registry_not_approved", product["analysis"]["information_gaps"])
        self.assertFalse(product["analysis"]["observations"])
        self.assertTrue(pipeline.replay(task)["verified"])

    def test_kill_switch_between_bootstrap_and_registry_stops_second_request(self):
        task = self.task(sources=("rdap",))
        calls = []
        def requester(url, *_):
            calls.append(url)
            os.environ["TRACEATLAS_WORKFORCE_KILL_SWITCH"] = "1"
            return 200, json.dumps(BOOTSTRAP).encode()
        with self.assertRaises(ValueError):
            InvestigationPipeline(self.service, self.root, requester=requester).run(task, live=True, authorized=True)
        self.assertEqual(len(calls), 1)

    def test_ipv6_defaults_and_explicit_incompatible_sources(self):
        self.assertNotIn("internetdb", select_sources("ip", "2606:4700:4700::1111"))
        for source in ("internetdb", "greynoise"):
            with self.assertRaises(ValueError):
                select_sources("ip", "2606:4700:4700::1111", (source,))
        with self.assertRaises(ValueError):
            select_sources("domain", "example.org", ("ipdata",))
        with self.assertRaises(ValueError):
            select_sources("domain", "example.org", ("dns", "dns"))

    def test_readiness_only_contains_environment_names(self):
        os.environ["BRAVE_SEARCH_API_KEY"] = "fixture-secret-never-display"
        value = json.dumps(readiness())
        self.assertIn("BRAVE_SEARCH_API_KEY", value)
        self.assertNotIn("fixture-secret-never-display", value)

    def test_wrong_target_and_query_responses_are_not_assertions(self):
        payloads = {
            "ipwhois": {"ip": "1.1.1.1", "success": True},
            "ipdata": {"ip": "1.1.1.1"},
            "greynoise": {"ip": "1.1.1.1", "classification": "benign", "noise": False, "riot": True},
            "brave": {"query": {"original": '"different.org"'}},
            "searxng": {"query": '"different.org"', "results": []},
            "urlscan": {"results": [{"page": {"ip": "1.1.1.1"}, "task": {}}]},
        }
        for source, data in payloads.items():
            with self.subTest(source=source), self.assertRaisesRegex(ProviderError, "target_mismatch"):
                _live_facts(source, "ip:8.8.8.8", data, STAMP)

    def test_search_results_are_leads_and_unsafe_urls_are_filtered(self):
        data = {"query": '"example.org"', "results": [{"url": url} for url in
            ["javascript:alert(1)", "http://127.0.0.1/", "https://user:secret@example.org/", "https://example.org/about"]]}
        facts = _live_facts("searxng", "domain:example.org", data, STAMP)
        self.assertEqual([fact.value for fact in facts], ["https://example.org/about"])

    def test_urlscan_historical_time_and_missing_fields(self):
        data = {"results": [{"page": {"domain": "example.org", "url": "https://example.org/", "ip": "8.8.8.8"},
                             "task": {"time": "2020-01-01T00:00:00Z"}}, {}]}
        facts = _live_facts("urlscan", "domain:example.org", data, STAMP)
        self.assertTrue(all(f.valid_from == "2020-01-01T00:00:00+00:00" for f in facts))
        data["results"][0]["task"]["time"] = "2020-01-01T00:00:00"
        with self.assertRaisesRegex(ProviderError, "schema_mismatch"):
            _live_facts("urlscan", "domain:example.org", data, STAMP)

    def test_searxng_real_loopback_transport_capture_and_replay(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                query = parse_qs(urlsplit(self.path).query)["q"][0]
                raw = json.dumps({"query": query, "results": [{"url": "https://example.org/about"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            os.environ["SEARXNG_URL"] = f"http://127.0.0.1:{server.server_port}"
            task = self.task(sources=("searxng",))
            pipeline = InvestigationPipeline(self.service, self.root, requester=lambda *_: self.fail("no public dispatch"))
            product = pipeline.run(task, live=True, authorized=True)
            self.assertEqual(product["network_attempts"], 1)
            self.assertEqual(product["plan"]["query_intents"][0]["result_count"], 1)
            self.assertEqual(product["replay_manifest"]["evidence"][0]["source_uri"], "urn:traceatlas:provider:searxng:search")
            self.assertTrue(pipeline.replay(task)["verified"])
            self.assertEqual(len(requests), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_search_configuration_and_transports_cannot_escape_loopback(self):
        for value in ["http://localhost:8080", "https://127.0.0.1:8080", "http://169.254.169.254:80",
                      "http://127.0.0.1:8080/?key=x", "http://user:secret@127.0.0.1:8080", "http://127.0.0.1:8080/admin"]:
            os.environ["SEARXNG_URL"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                search_base()
        for url in ["http://example.org:80/search", "http://127.0.0.1:80/admin", "http://user@127.0.0.1:80/search"]:
            with patch("http.client.HTTPConnection") as connect, self.assertRaises(ProviderError):
                request_loopback_search(url, {}, 1)
            connect.assert_not_called()
        with self.assertRaises(ProviderError):
            request("https://127.0.0.1:8080/search", {}, 1)

    def test_loopback_transport_rejects_redirect_compression_and_oversize(self):
        for status, headers, raw, error in [
            (302, {"Location": "https://evil.example/"}, b"", "redirect_rejected"),
            (200, {"Content-Encoding": "gzip"}, b"{}", "encoding_rejected"),
            (200, {"Content-Type": "text/html"}, b"{}", "content_type_rejected"),
            (200, {}, b"x" * (400 * 1024 + 1), "response_too_large")]:
            response = Mock(status=status)
            metadata = {"Content-Type": "application/json", **headers}
            response.getheader.side_effect = lambda key, default=None: metadata.get(key, default)
            response.read.return_value = raw
            with patch("http.client.HTTPConnection") as connection, self.assertRaisesRegex(ProviderError, error):
                connection.return_value.getresponse.return_value = response
                request_loopback_search("http://127.0.0.1:8080/search?q=example&format=json", {}, 1)
            connection.return_value.request.assert_called_once()


class BootstrapRoutingTests(unittest.TestCase):
    def test_exact_registry_base_and_longest_matching_allocation(self):
        data = {"version": "1.0", "services": [
            [["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]],
            [["8.8.0.0/16"], ["https://rdap.db.ripe.net/"]]]}
        self.assertEqual(registry_url("ip", "8.8.8.8", data), "https://rdap.db.ripe.net/ip/8.8.8.8")
        self.assertEqual(bootstrap_url("ip", "2606:4700:4700::1111"), "https://data.iana.org/rdap/ipv6.json")
        data["services"][1][1] = ["https://evil.example/"]
        with self.assertRaisesRegex(ProviderError, "registry_not_approved"):
            registry_url("ip", "8.8.8.8", data)

    def test_arbitrary_base_paths_credentials_and_private_targets_fail_closed(self):
        for base in ["http://rdap.publicinterestregistry.org/rdap/", "https://rdap.publicinterestregistry.org/evil/",
                     "https://user@rdap.publicinterestregistry.org/rdap/", "https://rdap.publicinterestregistry.org/rdap/?token=x"]:
            with self.subTest(base=base), self.assertRaisesRegex(ProviderError, "registry_not_approved"):
                registry_url("domain", "example.org", {"version": "1.0", "services": [[["org"], [base]]]})
        with self.assertRaises(ProviderError):
            bootstrap_url("ip", "127.0.0.1")
        with self.assertRaisesRegex(ProviderError, "bootstrap_invalid"):
            registry_url("domain", "example.org", {"version": "1.0", "services": [{"malformed": True}]})


if __name__ == "__main__":
    unittest.main()
