"""Installed coordination guides are complete, scoped and inert."""
import unittest

from traceatlas.workforce.coordination_registry import build_coordination_definitions
from traceatlas.workforce.coordination_skills import (
    _validate, coordination_skill_inventory, get_coordination_skill,
)


class CoordinationSkillTests(unittest.TestCase):
    def test_installed_guides_match_every_opt_in_role_and_taxonomy_scope(self):
        inventory = coordination_skill_inventory()
        self.assertEqual(inventory["count"], 11)
        self.assertEqual(inventory["validated"], 11)
        self.assertFalse(inventory["grants_authority"])
        guides = {item["employee_id"]: item for item in inventory["guides"]}
        self.assertEqual(set(guides), {item.employee_id for item in build_coordination_definitions()})
        from traceatlas.workforce.discipline_capabilities import domain_groups
        for group in domain_groups():
            guide = get_coordination_skill("coordination-lead-" + str(group["group_id"]))
            self.assertEqual(guide["metadata"]["domain_group"], str(group["group_id"]))
            self.assertEqual(guide["metadata"]["role"], "team_lead")
            self.assertFalse(guide["live_verified"])
            for label in group["disciplines"]:
                self.assertIn(label, guide["markdown"])
        self.assertEqual(get_coordination_skill("coordination-manager")["metadata"]["domain_group"], "ALL")

    def test_role_mismatch_duplicate_metadata_and_unresolved_scope_fail(self):
        original = get_coordination_skill("coordination-manager")["markdown"]
        variants = (
            original.replace("id: coordination-manager", "id: coordination-lead-1"),
            original.replace("employee_id: coordination-manager", "employee_id: foreign-employee"),
            original.replace("live_verified: false", "live_verified: true"),
            original.replace("domain_group: ALL", "domain_group: 1"),
            original.replace("version: 1.0.0", "version: 1.0.0\nversion: 1.0.0"),
            original.replace("## Procedure", "## Missing Procedure"),
            original + "\nUnresolved target: ${scope}\n",
        )
        for text in variants:
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                _validate("coordination-manager", text)

    def test_employee_path_cannot_escape_or_select_an_unregistered_procedure(self):
        for identity in ("../manager", "coordination-lead-11", "discipline-dnsint", ""):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                get_coordination_skill(identity)


if __name__ == "__main__":
    unittest.main()
