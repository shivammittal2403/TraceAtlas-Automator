"""Nonempty and negative regressions for repaired engine behavior."""
import importlib
import unittest

from fixture_inputs import fixture
from traceatlas.addons.intelligence_v1.registry import contract
from traceatlas.workforce.intelligence import run_offline


class RepairedAnalysisTests(unittest.TestCase):
    def test_linguistic_duplicates_and_negation_are_preserved(self):
        data = fixture(contract("lingint"))
        data["authorization"].update(lawful_basis="SYNTHETIC_TEST_INPUT", purpose="OFFLINE_VERIFICATION")
        text = "The sample report does not confirm an outage. It may reflect a reporting delay."
        data.update(sources=[{"source_id": "S-1", "source_type": "PUBLIC_REPORT", "publisher": "Synthetic fixture publisher"}],
                    texts=[{"text_id": "T-1", "original_text": text, "source_id": "S-1"},
                           {"text_id": "T-2", "original_text": text, "source_id": "S-1"}])
        _, result = run_offline("lingint", data)
        self.assertEqual(len(result["text_artifacts"]), 2)
        self.assertEqual(len(result["exact_duplicates"]), 1)
        self.assertIn("does not confirm", result["text_artifacts"][0]["original_excerpt"])
        self.assertGreater(result["negations"][0]["negation_count"], 0)
        self.assertFalse(result["source_authenticity_verified"])

    def test_linguistic_sensitive_trait_inference_is_refused(self):
        data = fixture(contract("lingint"))
        data["scope"]["infer_ethnicity"] = True
        _, result = run_offline("lingint", data)
        self.assertIn(result["status"], {"BLOCKED_POLICY", "POLICY_BLOCKED"})

    def test_ttp_dedup_keeps_conflicting_same_id_records(self):
        module = importlib.import_module("traceatlas.addons.intelligence_v1.modules.ttpint")
        parsed = module.empty_parsed()
        first = {"procedure_id": "P-1", "statement": "Submitted observation A"}
        conflict = {"procedure_id": "P-1", "statement": "Conflicting submitted observation B"}
        parsed["procedures"] = [first, dict(first), conflict]
        result = module.finalize_parsed(parsed)
        self.assertEqual(result["procedures"], [first, conflict])
        self.assertEqual(len(parsed["procedures"]), 3)

    def test_content_fingerprints_do_not_crash_and_ignore_token_order(self):
        for name in ("corpint", "finint", "tradeint"):
            module = importlib.import_module("traceatlas.addons.intelligence_v1.modules." + name)
            with self.subTest(name=name):
                self.assertEqual(module.content_fingerprint("SUPPLIED record 42"),
                                 module.content_fingerprint("42 supplied RECORD"))
                self.assertNotEqual(module.content_fingerprint("supplied record 42"),
                                    module.content_fingerprint("supplied record 99"))
                self.assertEqual(module.content_fingerprint(""), "")

    def test_ioc_mutex_pattern_matches_namespaces_without_crashing(self):
        module = importlib.import_module("traceatlas.addons.intelligence_v1.modules.iocint")
        for value in ("Global\\fixture_mutex", "Local\\fixture_mutex", "Sessions\\1\\BaseNamedObjects\\fixture_mutex"):
            self.assertIsNotNone(module.MUTEX_RE.fullmatch(value))
        self.assertIsNone(module.MUTEX_RE.fullmatch("ordinary words"))

    def test_unknown_enum_and_unconfigured_paths_do_not_fabricate_results(self):
        for name in ("healthint", "researchint", "sbomint"):
            item = contract(name)
            _, result = run_offline(name, fixture(item))
            with self.subTest(name=name):
                self.assertEqual(result["status"], "BLOCKED_CONFIGURATION")
                self.assertEqual(result.get("source_ids", []), [])


if __name__ == "__main__":
    unittest.main()
