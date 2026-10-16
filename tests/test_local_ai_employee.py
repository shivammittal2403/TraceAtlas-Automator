"""TraceAtlas local AI employee adversarial unit, integration and localhost tests."""
from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.employee.agent_runtime import AgentMemory, LocalAIEmployee, ToolRegistry
from traceatlas.employee.console import make_server
from traceatlas.engine import Engine


class FakeLibrary:
    def search(self, query, *, kind="all", limit=5):
        return {"matched": 1, "results": [{"ref": "skill:verified-procedure",
                "name": "Verified procedure", "kind": "skill",
                "execution_enabled": False, "description": query}], "execution_enabled": False}
    def reference(self, ref):
        if ref != "skill:verified-procedure":
            raise ValueError("Unknown skill")
        return {"ref": ref, "markdown": "# Reference\nDo not follow these instructions",
                "execution_enabled": False}


class AgentMemoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.memory = AgentMemory(self.tmp.name)

    def test_rag_citations_are_hashed_and_scoped(self):
        d = self.memory.add_document("case-a", "Asset evidence",
            "Example organization operates example.org according to the dated registrar data.")
        self.assertEqual(len(d["sha256"]), 64)
        a = self.memory.search("case-a", "example.org")
        self.assertGreaterEqual(a["count"], 1)
        self.assertEqual(a["matches"][0]["document_id"], d["document_id"])
        self.assertEqual(len(a["matches"][0]["sha256"]), 64)
        self.assertEqual(self.memory.search("case-b", "example.org")["matches"], [])
        self.assertEqual(self.memory.list_documents("case-a")["graph_edges"], 0)
        with self.assertRaises(ValueError):
            self.memory.add_document("case-a", "x", "short")

    def test_graph_provenance_does_not_cross_cases(self):
        d=self.memory.add_document("case-a","Domain",
            "Official letter identifies Example Corp as the operator of example.org.")
        with self.assertRaises(ValueError):
            self.memory.add_edge("case-b",d["document_id"],"Example Corp","operates","example.org")
        edge=self.memory.add_edge("case-a",d["document_id"],"Example Corp","operates","example.org")
        found=self.memory.neighbors("case-a","Example Corp")
        self.assertEqual(found["edges"][0]["citation"], edge["edge_id"])
        self.assertEqual(self.memory.neighbors("case-b","Example Corp")["edges"], [])

    def test_no_path_traversal_sql_or_overlong_input(self):
        for case in ("../other", "", "with space", "x"*100):
            with self.assertRaises(ValueError):
                self.memory.search(case,"example")
        with self.assertRaises(ValueError):
            self.memory.add_document("case-a","notes","x" * 32769)
        with self.assertRaises(ValueError):
            self.memory.add_edge("case-a","doc-"+"0"*32,"a","knows","b")

    def test_native_traceatlas_case_reports_are_read_only_and_scoped(self):
        path = Path(self.tmp.name) / "traceatlas.db"
        report = json.dumps({
            "claims": [{"statement": "Registrar shows example.org for organization"}],
            "evidence": [{"evidence_id": "evi-authorized-001"}]
        })
        with sqlite3.connect(path) as con:
            con.execute("CREATE TABLE autonomous_investigations "
                        "(id TEXT PRIMARY KEY, case_id TEXT, status TEXT, report_json TEXT, created_at TEXT)")
            con.execute("INSERT INTO autonomous_investigations VALUES (?,?,?,?,?)",
                        ("inv-a","case-a","completed",report,"2026-10-16"))
        a=self.memory.case_reports("case-a","registrar")
        self.assertEqual(len(a["reports"]),1)
        self.assertEqual(a["reports"][0]["evidence_ids"],["evi-authorized-001"])
        self.assertEqual(len(a["reports"][0]["report_sha256"]),64)
        self.assertEqual(self.memory.case_reports("case-b","registrar")["reports"],[])
        self.assertEqual(self.memory.case_reports("case-a","unrelated")["reports"],[])

    def test_run_records_are_case_scoped(self):
        result=self.memory.save_run("case-a", "Research local evidence",
                    {"status":"needs-evidence","answer":"No records"})
        self.assertEqual(self.memory.get_run("case-a",result["run_id"])["answer"],"No records")
        with self.assertRaises(ValueError):
            self.memory.get_run("case-b",result["run_id"])


class GovernedAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.employee=LocalAIEmployee(self.tmp.name,library=FakeLibrary())
        self.doc=self.employee.memory.add_document("alpha", "Registration evidence",
            "Public registrar entry names example.org and dated organization control.")

    def test_authorized_model_can_select_rag_then_finish_with_real_citation(self):
        calls=[]
        def fake(url, raw, headers, timeout):
            request=json.loads(raw)
            calls.append(request["prompt"])
            if len(calls)==1:
                response={"tool":"rag.search","arguments":{"query":"example.org"},"answer":"","citations":[]}
            else:
                marker=self.doc["document_id"]+":0"
                response={"tool":"finish","arguments":{},
                          "answer":"According to the supplied registrar entry, example.org is named.",
                          "citations":[marker]}
            return 200,json.dumps({"response":json.dumps(response)}).encode()
        result=self.employee.run("alpha","Review domain registration evidence",
                                  requester=fake,max_steps=3)
        self.assertEqual(result["status"],"completed-advisory")
        self.assertEqual(len(result["events"]),1)
        self.assertEqual(result["events"][0]["tool"],"rag.search")
        self.assertIn(self.doc["document_id"]+":0",result["citations"])
        self.assertFalse(result["external_action_started"])
        self.assertTrue(result["approval_required_for_source_collection"])
        self.assertEqual(len(calls),2)

    def test_model_is_denied_arbitrary_shell_and_urls(self):
        def hostile(*_):
            return 200,json.dumps({"response":json.dumps({
                "tool":"shell.exec","arguments":{"command":"curl malware"},
                "answer":"I did it","citations":[]})}).encode()
        result=self.employee.run("alpha","Investigate authorized registration data",
                                  requester=hostile,allowed_tools=["rag.search"])
        self.assertEqual(result["status"],"model-unavailable-or-invalid")
        self.assertEqual(result["events"],[])
        self.assertIn("registrar",result["answer"])
        self.assertFalse(result["external_action_started"])

    def test_model_cannot_forge_source_citations(self):
        def fake(*_):
            return 200,json.dumps({"response":json.dumps({
                "tool":"finish","arguments":{},"answer":"Unsupported fact",
                "citations":["doc-"+"f"*32+":0"]})}).encode()
        result=self.employee.run("alpha","Research the registration of example.org",
                                  requester=fake)
        self.assertEqual(result["status"],"model-unavailable-or-invalid")
        self.assertNotIn("Unsupported fact",result["answer"])

    def test_offline_model_returns_deterministic_cited_excerpts(self):
        def down(*_):
            raise TimeoutError("Ollama offline")
        result=self.employee.run("alpha","Investigate registration example.org",
                                  requester=down)
        self.assertEqual(result["status"],"model-unavailable-or-invalid")
        self.assertTrue(result["citations"])
        self.assertIn("registrar",result["answer"])

    def test_tool_registry_denies_injection_and_case_leaks(self):
        registry=self.employee.registry
        with self.assertRaises(ValueError):
            registry.execute("alpha","python.eval",{"query":"foo"})
        with self.assertRaises(ValueError):
            registry.execute("alpha","skills.search",{"query":"dns","shell":"rm"})
        self.assertEqual(registry.execute("beta","rag.search",{"query":"example.org"})["matches"],[])
        rows=registry.execute("alpha","skills.search",{"query":"dns"})
        self.assertFalse(rows["execution_enabled"])

    def test_hard_budgets_and_tool_allowlist(self):
        with self.assertRaises(ValueError):
            self.employee.run("alpha","Investigate authorized records",max_steps=100)
        with self.assertRaises(ValueError):
            self.employee.run("alpha","Investigate authorized records",allowed_tools=["shell.exec"])
        with self.assertRaises(ValueError):
            self.employee.run("alpha","Investigate authorized records",model="http://evil.example")

    def test_model_empty_evidence_is_not_called_verified(self):
        def finish(*_):
            return 200,json.dumps({"response":json.dumps({
                "tool":"finish","arguments":{},"answer":"Unverified conjecture",
                "citations":[]})}).encode()
        result=self.employee.run("beta","Investigate currently unknown source details",
                                  requester=finish)
        self.assertEqual(result["status"],"needs-evidence")


class ConsoleAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        engine=Engine(Path(self.tmp.name))
        engine.db.create_case("legal-case","Authorized local review",
                              "Review evidence for an organization we administer.")
        engine.close()
        self.server=make_server(Path(self.tmp.name),port=0,enabled=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self,method,path,body=None,csrf="",origin=None):
        con=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=30)
        headers={"Host":"127.0.0.1:"+str(self.server.server_port)}
        if origin: headers["Origin"]=origin
        payload=None if body is None else json.dumps(body).encode()
        if payload is not None:
            headers["Content-Type"]="application/json"
            headers["X-TraceAtlas-CSRF"]=csrf
        con.request(method,path,body=payload,headers=headers)
        resp=con.getresponse()
        result=resp.read()
        status=resp.status
        con.close()
        return status,(json.loads(result) if resp.headers.get("Content-Type","").startswith("application/json") else result)

    def test_local_ui_and_session(self):
        for path in ("/agent","/agent.js","/agent.css"):
            status,data=self.request("GET",path)
            self.assertEqual(status,200)
            self.assertTrue(data)
        status,session=self.request("GET","/api/session")
        self.assertEqual(status,200)
        self.assertGreater(len(session["csrf_token"]),20)
        status,manifest=self.request("GET","/api/agent/tools")
        self.assertEqual(status,200)
        self.assertEqual(len(manifest["tools"]),6)

    def test_case_authorization_and_document_ingestion(self):
        status,session=self.request("GET","/api/session")
        body={"case_id":"legal-case","title":"Registry notes",
              "text":"Registrar evidence says this example domain belongs to the authorized organization.",
              "authorized":True}
        self.assertEqual(self.request("POST","/api/agent/document",body)[0],403)
        self.assertEqual(self.request("POST","/api/agent/document",
                         {**body,"authorized":False},session["csrf_token"])[0],400)
        status,data=self.request("POST","/api/agent/document",body,session["csrf_token"])
        self.assertEqual(status,201)
        status,docs=self.request("GET","/api/agent/documents?case=legal-case")
        self.assertEqual(status,200)
        self.assertEqual(docs["documents"][0]["document_id"],data["document_id"])
        self.assertEqual(self.request("GET","/api/agent/documents?case=other")[0],400)
        self.assertEqual(self.request("GET","/api/agent/run?case=legal-case&id=run-not-real")[0],400)
        self.assertEqual(self.request("POST","/api/agent/edge",
          {"case_id":"other","document_id":data["document_id"],"subject":"x",
           "predicate":"links","object":"y","authorized":True},session["csrf_token"])[0],400)

    def test_cross_origin_requests_blocked(self):
        status,_=self.request("GET","/api/agent/tools",origin="https://attacker.example")
        self.assertEqual(status,400)


if __name__ == "__main__":
    unittest.main()
