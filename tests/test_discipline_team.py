"""Coordinator tests use actual nonempty network and software processors."""
import copy
import unittest
from traceatlas.workforce.discipline_team import run_team


def fixture():
    return {"case_id": "case-team", "task_id": "team-test",
        "objective": "Review supplied infrastructure and software evidence", "as_of": "2026-10-15T00:00:00Z",
        "sources": [{"source_id": "s", "uri": "urn:fixture:team"}],
        "assignments": [
            {"discipline": "DNSINT", "records": [{"record_id": "dns-r", "source_id": "s", "data": {
                "name": "example.org", "type": "A", "value": "192.0.2.1"}}]},
            {"discipline": "CODEINT", "records": [{"record_id": "code-r", "source_id": "s", "data": {
                "path": "fixture.py", "content": "answer = 42\n"}}]},
            {"discipline": "IPINT", "records": [{"record_id": "ip-r", "source_id": "s", "data": {
                "ip": "192.0.2.1", "prefixes": ["192.0.2.0/24"]}}]}]}


class TeamTests(unittest.TestCase):
    def test_distinct_handlers_receive_bound_child_tasks_and_preserve_input(self):
        data, before = fixture(), fixture()
        result = run_team(data)
        self.assertEqual(data, before)
        self.assertEqual(result["employees_executed"], 3)
        self.assertEqual(result["unique_supplied_records"], 3)
        self.assertEqual(result["status"], "ANALYSIS_COMPLETE")
        dns, code, ip = result["drafts"]
        self.assertEqual(dns["artifacts"]["records"][0]["value"], "192.0.2.1")
        self.assertEqual(code["metrics"]["parsed_files"], 1)
        self.assertEqual(ip["artifacts"]["addresses"][0]["matching_prefixes"], ["192.0.2.0/24"])
        self.assertEqual(len({draft["task_id"] for draft in result["drafts"]}), 3)
        self.assertTrue(all(draft["case_id"] == data["case_id"] for draft in result["drafts"]))
        self.assertEqual(run_team(copy.deepcopy(data)), result)

    def test_empty_assignment_stays_an_explicit_gap(self):
        data = fixture()
        data["assignments"][1]["records"] = []
        result = run_team(data)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["information_gaps"], [{"discipline": "CODEINT",
            "status": "INSUFFICIENT_DATA", "issues": 0}])

    def test_duplicate_discipline_and_conflicting_record_identity_rejected(self):
        for mutate in (
            lambda d: d["assignments"].append(copy.deepcopy(d["assignments"][0])),
            lambda d: d["assignments"][1]["records"][0].update(record_id="dns-r"),
            lambda d: d["assignments"][1]["records"][0].update(source_id="foreign")):
            data = fixture()
            mutate(data)
            with self.assertRaises(ValueError):
                run_team(data)

    def test_consistent_cross_discipline_record_can_be_reused(self):
        data = fixture()
        record = data["assignments"][0]["records"][0]
        record["data"]["ip"] = "192.0.2.1"
        data["assignments"][2]["records"] = [copy.deepcopy(record)]
        result = run_team(data)
        self.assertEqual(result["unique_supplied_records"], 2)
        self.assertEqual(result["employees_executed"], 3)


if __name__ == "__main__":
    unittest.main()
