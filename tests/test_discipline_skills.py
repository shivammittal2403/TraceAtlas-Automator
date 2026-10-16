"""Package and authority regression for all 139 requested + OSINT skills."""
import unittest

from traceatlas.workforce.discipline_skills import (
    get_skill_guide, parse_guide, skill_inventory)
from traceatlas.workforce.discipline_registry import supported_disciplines


class MarkdownDisciplineTests(unittest.TestCase):
    def test_all_registered_processors_have_skills(self):
        self.assertEqual(len(supported_disciplines()), 140)
        self.assertEqual(len(set(supported_disciplines()) - {"OSINT"}), 139)
        self.assertEqual(skill_inventory()["guides_available"], 140)
        for label in supported_disciplines():
            with self.subTest(label=label):
                guide = get_skill_guide(label)
                self.assertEqual(guide["discipline"], label)
                self.assertEqual(guide["employee"], "discipline-" + label.lower())
                self.assertFalse(guide["live_verified"])
                self.assertIn("## Hypothesis and Falsification", guide["markdown"])

    def test_specificity_and_distinct_network_semantics(self):
        self.assertIn("CNAME", get_skill_guide("DNSINT")["markdown"])
        self.assertIn("not IP network infrastructure", get_skill_guide("NETWORKINT")["markdown"])
        self.assertIn("not relationships among people", get_skill_guide("NETINT")["markdown"])

    def test_metadata_tampering_and_traversal(self):
        markdown = get_skill_guide("DNSINT")["markdown"]
        for altered in (markdown.replace("live_verified: false", "live_verified: true"),
                        markdown.replace("allowed_tool: discipline.analyze", "allowed_tool: shell"),
                        markdown.replace("discipline: DNSINT", "discipline: SIGINT"),
                        markdown.replace("## Procedure", "## UNKNOWN"),
                        markdown.replace("id: dnsint", "id: dnsint\nid: dnsint")):
            with self.subTest(altered=altered[:45]), self.assertRaises(ValueError):
                parse_guide(altered, "DNSINT")
        with self.assertRaises(ValueError):
            get_skill_guide("../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
