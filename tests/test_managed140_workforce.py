"""Deterministic case routing tests."""
import unittest
from traceatlas.skills.managed140.workforce import plan_case, run_case, verify_case

class Workforce140Tests(unittest.TestCase):
    def test_explicit_bounded_case(self):
        data = {"records":[{"source_id":"fixture","data":{"domain":"example.org"}}]}
        report = run_case(data, case_id="case-001", domains=["DOMAININT"])
        self.assertTrue(verify_case(report))
        self.assertEqual(report["summary"]["executed"],1)
        self.assertEqual(report["plan"]["team_leads"]["infra_cyber"],["DOMAININT"])
        report["summary"]["executed"] = 50
        self.assertFalse(verify_case(report))
    def test_sensitive_cannot_self_authorize(self):
        data = {"records":[{"source_id":"fixture","data":{"frequency_hz":123}}]}
        plan = plan_case(data, goal="signals")
        self.assertNotIn("SIGINT",plan["domains"])
        blocked = run_case(data, case_id="case-002", domains=["SIGINT"], authorized=False)
        self.assertEqual(blocked["reports"]["SIGINT"]["status"],"blocked")
    def test_domain_budget_rejected(self):
        data = {"records":[]}
        with self.assertRaises(ValueError):
            plan_case(data,domains=["DOMAININT"]*13,limit=0)
    def test_unsupported_domain_rejected(self):
        with self.assertRaises(KeyError):
            plan_case({"records":[]},domains=["FAKEINT"])
if __name__ == "__main__":
    unittest.main()
