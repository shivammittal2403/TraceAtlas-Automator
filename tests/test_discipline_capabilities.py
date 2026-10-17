"""Native capability mapping validates actual source semantics without executing collectors."""
import ast
import copy
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.addons.intelligence_v1.registry import catalog as legacy_catalog
from traceatlas.workforce import discipline_capabilities as capabilities
from traceatlas.workforce.discipline_engines import registered_handlers

ROOT = Path(__file__).resolve().parents[1]


class NativeCapabilityCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = capabilities.capability_catalog(
            repository_root=ROOT, require_repository_assets=True)
        cls.rows = {row["discipline"]: row for row in cls.catalog["employees"]}

    def test_authoritative_groups_and_registered_dispatch_cover_same_disciplines(self):
        groups = capabilities.domain_groups()
        labels = [label for group in groups for label in group["disciplines"]]
        self.assertEqual(set(labels), set(registered_handlers()))
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual([row["group_id"] for row in groups], list(range(1, 11)))
        self.assertEqual(capabilities.discipline_group("  dnsint "), {
            "group_id": 4, "group_name": "NETWORK / INFRASTRUCTURE"})
        self.assertEqual(capabilities.discipline_group("NETWORKINT")["group_id"], 2)
        self.assertEqual(self.rows["OSINT"]["classification"], "umbrella")
        self.assertTrue(all(row["classification"] == "discipline"
                            for label, row in self.rows.items() if label != "OSINT"))
        self.assertEqual(self.catalog["discipline_count"], 139)
        for label in (None, "../../dnsint", "NOT_A_DISCIPLINE"):
            with self.subTest(label=label), self.assertRaises(ValueError):
                capabilities.discipline_group(label)

    def test_representative_output_contracts_preserve_all_eleven_native_families(self):
        expected = {
            "DNSINT": ("network", "cname_cycles", "records", "dns_cname_cycle"),
            "APIINT": ("software", "operations", "operation_contracts", "API_AUTH_NOT_REQUIRED_BY_SPEC"),
            "WEBINT": ("discovery", "captures", "captures", "web_capture"),
            "FININT": ("economic", "accepted_records", "statements", "financial_statement_checks"),
            "NETWORKINT": ("social", "nodes", "node_statistics", "SUPPLIED_GRAPH_ARTICULATION_NODE"),
            "IOCINT": ("cyber", "unique_indicators", "indicators", "indicator_correlation"),
            "GEOINT": ("media", "points", "points", "geospatial_measurement"),
            "HYPOTHESISINT": ("evidence", "hypothesis_matrices", "hypotheses", "competing_hypotheses_matrix"),
            "PAYMENTINT": ("fraud", "invoice_ids", "invoice_reconciliation", "SUPPLIED_INVOICE_OVERPAYMENT"),
            "ACADEMICINT": ("research", "papers", "citation_edges", "academic_record"),
            "RAILINT": ("supply", "rail_trips", "trips", "rail_service_day_timetable"),
        }
        for label, (family, metric, artifact, finding) in expected.items():
            with self.subTest(label=label):
                row = self.rows[label]
                self.assertEqual(row["native_handler"]["implementation_family"], family)
                self.assertIn(metric, row["static_output_contract"]["metrics"])
                self.assertIn(artifact, row["static_output_contract"]["artifacts"])
                self.assertIn(finding, row["static_output_contract"]["findings"])
                self.assertFalse(row["static_output_contract"]["exhaustive"])
                self.assertFalse(row["static_output_contract"]["code_executed_for_extraction"])

    def test_native_net_and_social_network_are_distinct_and_legacy_modes_do_not_replace_native(self):
        net, social, dns = (self.rows[name] for name in ("NETINT", "NETWORKINT", "DNSINT"))
        self.assertEqual(net["native_handler"]["module"], "traceatlas.workforce.discipline_engines.network")
        self.assertEqual(social["native_handler"]["module"], "traceatlas.workforce.discipline_engines.social")
        self.assertNotEqual(net["static_output_contract"]["artifacts"], social["static_output_contract"]["artifacts"])
        self.assertEqual(dns["native_execution"]["mode"], "SUPPLIED_RECORD_ANALYSIS")
        self.assertEqual(dns["legacy_route"]["execution_mode"], "PLANNING_ONLY")
        self.assertEqual(self.rows["CODEINT"]["legacy_route"]["execution_mode"], "UNCONFIGURED_SCOPE_CHECK")
        self.assertEqual(self.rows["CODEINT"]["native_execution"]["implementation_status"], "CALLABLE_REGISTERED")
        self.assertEqual(self.catalog["legacy_module_count"], 135)
        self.assertEqual(self.catalog["legacy_module_modes"], {
            "SUPPLIED_RECORD_ANALYSIS": 68, "PLANNING_ONLY": 53, "UNCONFIGURED_SCOPE_CHECK": 14})
        self.assertEqual(self.catalog["legacy_label_route_modes"], {
            "SUPPLIED_RECORD_ANALYSIS": 53, "PLANNING_ONLY": 72, "UNCONFIGURED_SCOPE_CHECK": 15})

    def test_hypothesis_and_falsification_describe_coded_scope_without_truth_or_live_promotion(self):
        hypothesis, falsification = (self.rows[name]["hypothesis_review"]
                                     for name in ("HYPOTHESISINT", "FALSIFICATIONINT"))
        self.assertTrue(hypothesis["typed_hypothesis_projection_coded"])
        self.assertTrue(falsification["canonical_sidecar_coded"])
        self.assertFalse(falsification["typed_hypothesis_projection_coded"])
        self.assertFalse(falsification["standalone_falsification_invents_proposition"])
        self.assertFalse(self.rows["DNSINT"]["hypothesis_review"]["canonical_sidecar_coded"])
        for row in self.rows.values():
            self.assertIsNone(row["native_execution"]["execution_receipt"])
            self.assertIsNone(row["semantic_tests"]["execution_receipt"])
            self.assertFalse(row["live_collection"]["live_verified"])
            self.assertFalse(row["live_collection"]["automatically_dispatched"])
            self.assertEqual(row["live_collection"]["status"], "NOT_IMPLEMENTED_BY_NATIVE_HANDLER")
            self.assertEqual(row["external_requirements"], {
                "specification_status": "UNREAD", "minimum_requirements_met": None})

    def test_hashes_native_recipes_skills_and_wrapper_dispatch_match_actual_assets(self):
        for label, row in self.rows.items():
            with self.subTest(label=label):
                handler = row["native_handler"]
                self.assertEqual(handler["function"], label.lower())
                self.assertEqual(handler["registry_dispatch"], "registered_handlers()[discipline]")
                self.assertEqual(handler["source_sha256"], sha256((ROOT / handler["source_path"]).read_bytes()).hexdigest())
                self.assertGreater(handler["source_line"], 0)
                recipe = row["native_recipe"]
                self.assertTrue(recipe["available"])
                self.assertTrue(recipe["synthetic"])
                self.assertEqual(recipe["sha256"], sha256((ROOT / recipe["path"]).read_bytes()).hexdigest())
                self.assertTrue(row["skill"]["metadata_validated"])
                self.assertFalse(row["skill"]["grants_source_authority"])
                self.assertRegex(row["skill"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(self.rows["FININT"]["native_handler"]["registered_wrapper"])
        self.assertFalse(self.rows["DNSINT"]["native_handler"]["registered_wrapper"])

    def test_dynamic_and_explicit_semantic_references_are_source_presence_not_execution(self):
        software = self.rows["APIINT"]["semantic_tests"]
        self.assertIn("SoftwareEmployeeTests.test_apiint_positive", software["selectors"])
        self.assertIn("CASES.adversarial.APIINT", software["structured_case_references"])
        economic = self.rows["FININT"]["semantic_tests"]
        self.assertIn("EconomicEmployeeTests.test_finint_semantics", economic["selectors"])
        self.assertIn("EconomicEmployeeTests.test_finint_malformed", economic["selectors"])
        dns = self.rows["DNSINT"]["semantic_tests"]
        self.assertTrue(any(selector.endswith("test_dns_cycle_and_exclusivity_keep_references")
                            for selector in dns["selectors"]))
        for row in self.rows.values():
            self.assertTrue(row["semantic_tests"]["source_available"])
            self.assertEqual(row["semantic_tests"]["definition_status"], "SOURCE_REFERENCED")
            self.assertIsNone(row["semantic_tests"]["execution_receipt"])

    def test_ast_extraction_keeps_literal_outputs_and_never_runs_source(self):
        tree = ast.parse(
            'def helper(ctx, kind, extra):\n'
            '    metrics = {"fixed_count": 1}\n'
            '    metrics.update(extra)\n'
            '    ctx.finding(kind, "Submitted result", ["r"])\n'
            '    return ctx.output(metrics=metrics, artifacts={"rows": []})\n'
            'def analyzer(ctx):\n'
            '    raise AssertionError("Source must never execute")\n'
            '    ctx.issue(None, "literal_issue", "Input issue")\n'
            '    return helper(ctx, "literal_finding", {"literal_count": 2})\n')
        result = capabilities._static_outputs(tree, "analyzer")
        self.assertEqual(result["metrics"], ["fixed_count", "literal_count"])
        self.assertEqual(result["artifacts"], ["rows"])
        self.assertEqual(result["findings"], ["literal_finding"])
        self.assertEqual(result["issues"], ["literal_issue"])
        with self.assertRaises(ValueError):
            capabilities._static_outputs(tree, "missing")

    def test_dynamic_test_selector_requires_source_definition_and_restricted_name_expression(self):
        tree = ast.parse('"test_" + label.lower() + "_" + category', mode="eval")
        self.assertEqual(capabilities._test_selector(tree.body, "DNSINT", "positive"),
                         "test_dnsint_positive")
        unsafe = ast.parse('__import__("os").system("unexpected")', mode="eval")
        self.assertIsNone(capabilities._test_selector(unsafe.body, "DNSINT", "positive"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "tests/test_discipline_software.py"
            path.parent.mkdir(parents=True)
            path.write_text(
                'import json\nCASES = json.loads(\'{"positive":{"APIINT":{}}}\')\n'
                'class SoftwareEmployeeTests:\n    pass\n', encoding="utf-8")
            reference = capabilities._test_references(root, "software", "APIINT")
            self.assertEqual(reference["selectors"], [])
            self.assertEqual(reference["definition_status"], "NOT_ESTABLISHED")

    def test_missing_handler_invalid_legacy_route_and_duplicate_group_fail_closed(self):
        handlers = registered_handlers()
        handlers.pop("DNSINT")
        with patch.object(capabilities, "registered_handlers", return_value=handlers):
            with self.assertRaisesRegex(ValueError, "every taxonomy handler"):
                capabilities.capability_catalog()
        manifest = copy.deepcopy(legacy_catalog())
        manifest["modules"] = [row for row in manifest["modules"] if row["id"] != "dnsint"]
        with patch.object(capabilities, "legacy_catalog", return_value=manifest):
            with self.assertRaises(ValueError):
                capabilities.capability_catalog()
        terms = dict(capabilities.GROUP_TERMS)
        terms[1] += " DNSINT"
        with patch.object(capabilities, "GROUP_TERMS", terms):
            with self.assertRaisesRegex(ValueError, "duplicate disciplines"):
                capabilities.domain_groups()

    def test_missing_and_malformed_recipe_fail_when_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "recipe is missing"):
                capabilities.capability_catalog(repository_root=root, require_repository_assets=True)
            path = root / "examples/employees/recipes/DNSINT.json"
            path.parent.mkdir(parents=True)
            path.write_text('{"discipline":"NETINT","records":[{}]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "identity"):
                capabilities._recipe(root, "DNSINT", True)

    def test_installation_without_repository_assets_reports_absence_honestly(self):
        with patch.object(capabilities, "_repository_root", return_value=None):
            installed = capabilities.capability_catalog()
        for row in installed["employees"]:
            self.assertFalse(row["native_recipe"]["available"])
            self.assertIsNone(row["native_recipe"]["sha256"])
            self.assertFalse(row["semantic_tests"]["source_available"])
            self.assertEqual(row["semantic_tests"]["definition_status"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
