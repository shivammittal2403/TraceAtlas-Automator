from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from traceatlas.capabilities import (
    CAPABILITIES, CapabilityHub, MCPClient, ResearchWorkflow, ServiceClient, TrainingStore,
)
from traceatlas.db import CaseDB
from traceatlas.policy import PolicyError


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = CaseDB(self.root / "traceatlas.db")
        self.db.create_case("case-1", "Capability", "Authorized fixture test")
        self.hub = CapabilityHub(self.db, self.root)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_all_analyzed_repositories_are_registered(self):
        self.assertEqual(len(CAPABILITIES), 19)
        for name in ("agent-reach", "crawl4ai", "firecrawl-mcp", "mcp-maigret",
                     "osint-mcp-server", "openosint", "browser-use"):
            self.assertIn(name, CAPABILITIES)

    def test_licence_boundaries_are_machine_enforced(self):
        self.assertFalse(CAPABILITIES["iop-mvp"].executable)
        self.assertEqual(CAPABILITIES["firecrawl"].integration, "service")
        self.assertFalse(CAPABILITIES["gpt-researcher"].executable)
        self.assertIn("not vendored", CAPABILITIES["firecrawl"].restriction)

    def test_doctor_is_secret_safe(self):
        encoded = json.dumps(self.hub.doctor())
        self.assertNotIn("API_KEY=", encoded)
        self.assertEqual(self.hub.doctor()["upstream_engines"], 19)

    def test_ingest_requires_authorization_and_consent(self):
        export = self.root / "agent.json"
        export.write_text('{"username":"alice"}', encoding="utf-8")
        with self.assertRaises(PolicyError):
            self.hub.ingest("case-1", "agent-reach", export, authorized=False)
        with self.assertRaisesRegex(PolicyError, "subject-consent"):
            self.hub.ingest("case-1", "agent-reach", export, authorized=True)

    def test_ingest_redacts_secrets_and_separates_inferences(self):
        export = self.root / "exa.jsonl"
        export.write_text(
            '{"title":"public result","api_key":"never-store","home_address":"private"}\n',
            encoding="utf-8",
        )
        result = self.hub.ingest(
            "case-1", "exa-mcp", export, authorized=True, subject_consent=True
        )
        data = json.loads(Path(result["output"]).read_text(encoding="utf-8"))
        self.assertEqual(data["facts"][0]["api_key"], "[REDACTED]")
        self.assertEqual(data["facts"][0]["home_address"], "[REMOVED]")
        self.assertEqual(data["inferences"], [])
        self.assertEqual(len(self.db.evidence("case-1")), 1)

    def test_mcp_policy_blocks_secrets_private_targets_and_unlisted_tools(self):
        with self.assertRaisesRegex(PolicyError, "Credentials"):
            self.hub._validate_arguments({"api_key": "not-accepted"})
        with self.assertRaisesRegex(PolicyError, "Private"):
            self.hub._validate_arguments({"target": "http://127.0.0.1/admin"})
        client = MCPClient(CAPABILITIES["osint-mcp-server"], "/tmp/osint-mcp-server")
        self.assertTrue(client.tool_allowed("dns_lookup"))
        self.assertFalse(client.tool_allowed("delete_all"))
        self.assertFalse(client.tool_allowed("run_actor"))

    def test_real_stdio_mcp_handshake_filters_server_tools(self):
        server = self.root / "osint-mcp-server"
        server.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "for line in sys.stdin:\n"
            " m=json.loads(line)\n"
            " if 'id' not in m: continue\n"
            " if m['method']=='initialize': r={'protocolVersion':'2024-11-05','capabilities':{},'serverInfo':{'name':'fixture','version':'1'}}\n"
            " elif m['method']=='tools/list': r={'tools':[{'name':'dns_lookup'},{'name':'delete_all'}]}\n"
            " else: r={'content':[{'type':'text','text':'fixture observation'}]}\n"
            " print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':r}),flush=True)\n",
            encoding="utf-8",
        )
        server.chmod(0o755)
        client = MCPClient(CAPABILITIES["osint-mcp-server"], str(server), timeout=5)
        self.assertEqual([tool["name"] for tool in client.list_tools()], ["dns_lookup"])
        result = client.call_tool("dns_lookup", {"domain": "example.com"})
        self.assertEqual(result["content"][0]["text"], "fixture observation")

    def test_research_dag_requires_authority_and_person_consent(self):
        with self.assertRaises(PolicyError):
            ResearchWorkflow.plan("Review public footprint", "person", "Approved research purpose")
        plan = ResearchWorkflow.plan(
            "Review owned organisation exposure", "organisation",
            "Authorised by the organisation security owner",
        )
        self.assertEqual(plan["stages"][1]["depends_on"], ["T01"])
        self.assertIn("authority_statement", plan)

    def test_research_brief_deduplicates_and_keeps_inferences_separate(self):
        rows = [
            {"observation": "DNS record observed", "source": "dns", "confidence": 80},
            {"observation": "DNS record observed", "source": "dns", "confidence": 80},
            {"observation": "May use provider X", "source": "analysis", "type": "inference"},
        ]
        result = ResearchWorkflow.brief(rows)
        self.assertEqual(len(result["facts"]), 1)
        self.assertEqual(len(result["inferences"]), 1)
        self.assertEqual(result["deduplicated"], 1)

    def test_crawl_worker_rejects_remote_control_and_code_hooks(self):
        with self.assertRaisesRegex(PolicyError, "Local worker"):
            ServiceClient._loopback_base("https://worker.example.com")
        with self.assertRaisesRegex(PolicyError, "Unsafe"):
            ServiceClient.crawl4ai("https://example.com", {"hooks": "malicious"})
        with self.assertRaisesRegex(PolicyError, "Private"):
            ServiceClient.crawl4ai("http://10.0.0.8/internal", {})

    def test_training_module_validation_and_progress(self):
        module = self.root / "module.json"
        module.write_text(json.dumps({
            "id": "osint-101", "title": "OSINT Basics", "level": "beginner",
            "lessons": [{"id": "l1", "title": "Sources", "exercises": [
                {"type": "mcq", "question": "Which source?"}
            ]}],
        }), encoding="utf-8")
        result = TrainingStore.validate_module(module)
        self.assertTrue(result["valid"])
        self.assertEqual(result["exercises"], 1)
        progress = TrainingStore(self.root).record("osint-101", "l1", 85)
        self.assertTrue(progress["completed"])


if __name__ == "__main__":
    unittest.main()
