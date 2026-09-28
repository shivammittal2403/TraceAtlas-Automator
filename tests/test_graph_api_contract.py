"""The hosted graph keeps evidence links and tells the UI when a read is capped."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("traceatlas_graph_api", ROOT / "api/graph.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CASE_ID = "11111111-1111-4111-8111-111111111111"


class GraphApiContractTests(unittest.TestCase):
    def test_evidence_links_and_explicit_caps(self):
        class Gateway:
            def select(self, table, params):
                if table == "graph_entities":
                    self_case.assertIn("evidence_id", params["select"])
                    return [{"id": str(i), "evidence_id": "e1"} for i in range(501)]
                if table == "graph_edges":
                    self_case.assertIn("evidence_id", params["select"])
                    return [{"id": "edge", "evidence_id": None}]
                return [{"id": "e1", "source": "dns"}]

        self_case = self
        request = MODULE.handler.__new__(MODULE.handler)
        request.path = f"/api/graph?case_id={CASE_ID}"
        sent = []
        with patch.object(MODULE, "authenticated_gateway", return_value=(Gateway(), None)), \
                patch.object(MODULE, "send_json", side_effect=lambda _req, code, body: sent.append((code, body))):
            request.do_GET()
        code, body = sent[0]
        self.assertEqual(code, 200)
        self.assertEqual(body["case_id"], CASE_ID)
        self.assertEqual(body["truncated"], {"entities": True, "edges": False, "evidence": False})
        self.assertEqual(len(body["entities"]), 500)
        self.assertEqual(body["entities"][0]["evidence_ids"], ["e1"])
        self.assertNotIn("evidence_id", body["entities"][0])
        self.assertEqual(body["edges"][0]["evidence_ids"], [])


if __name__ == "__main__":
    unittest.main()
