"""Reference-only vendored skill discovery; does not run scripts."""
import tempfile
import unittest
from pathlib import Path

from traceatlas.skills.external_skills import (
    ExternalSkillDirectory, SkillArchiveError, open_external_skills
)

SKILL = "---\nname: parsing-public-dns\ndomain: cybersecurity\nsubdomain: threat-intelligence\ndescription: Review DNS records\nlicense: Apache-2.0\n---\n# Procedure\n"


class VendoredSkillTests(unittest.TestCase):
    def test_directory_catalog_and_read_only_reference(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            directory = root / "parsing-public-dns"
            directory.mkdir()
            (directory / "SKILL.md").write_text(SKILL, encoding="utf-8")
            (directory / "scripts").mkdir()
            (directory / "scripts" / "agent.py").write_text(
                "raise AssertionError('NEVER_EXECUTE')", encoding="utf-8")
            library = open_external_skills(directory=root)
            self.assertIsInstance(library, ExternalSkillDirectory)
            catalog = library.catalog(query="dns")
            self.assertEqual(catalog["registered_external_skills"], 1)
            self.assertFalse(catalog["execution_enabled"])
            reference = library.reference("parsing-public-dns")
            self.assertEqual(reference["markdown"], SKILL)
            self.assertFalse(reference["executable"])
            self.assertNotIn("NEVER_EXECUTE", reference["markdown"])

    def test_missing_or_mismatched_skill_is_not_registered(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            (root / "missing-skill").mkdir()
            (root / "invalid-skill").mkdir()
            (root / "invalid-skill" / "SKILL.md").write_text(SKILL)
            library = ExternalSkillDirectory(root)
            self.assertEqual(library.catalog()["registered_external_skills"], 0)
            self.assertEqual(set(library.catalog()["missing_primary_skill_files"]),
                             {"missing-skill", "invalid-skill"})

    def test_path_and_archive_directory_conflict(self):
        with tempfile.TemporaryDirectory() as dirname:
            with self.assertRaises(SkillArchiveError):
                open_external_skills(archive="fake.zip", directory=dirname)
            folder = Path(dirname) / "parsing-public-dns"
            folder.mkdir()
            (folder / "SKILL.md").write_text(SKILL)
            with self.assertRaises(SkillArchiveError):
                ExternalSkillDirectory(dirname).reference("../../outside")

    def test_tampering_after_index_is_detected(self):
        with tempfile.TemporaryDirectory() as dirname:
            directory = Path(dirname) / "parsing-public-dns"
            directory.mkdir()
            path = directory / "SKILL.md"
            path.write_text(SKILL)
            library = ExternalSkillDirectory(dirname)
            path.write_text(SKILL + "\nchanged")
            with self.assertRaises(SkillArchiveError):
                library.reference("parsing-public-dns")


if __name__ == "__main__":
    unittest.main()
