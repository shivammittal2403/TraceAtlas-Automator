"""External skill ZIPs are untrusted, non-executable reference material."""
import tempfile
import unittest
from pathlib import Path
import zipfile
from traceatlas.skills.external_skills import ExternalSkillArchive, SkillArchiveError

GOOD = "---\nname: investigating-public-dns\ndomain: cybersecurity\nsubdomain: threat-intelligence\ndescription: Analyze public DNS records\nlicense: Apache-2.0\n---\n# Investigating Public DNS\n"


def make_zip(root, entries):
    target = root / "skills.zip"
    with zipfile.ZipFile(target, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return target


class ExternalSkillsTests(unittest.TestCase):
    def test_readonly_catalog_and_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = make_zip(root, {
                "skills/investigating-public-dns/SKILL.md": GOOD,
                "skills/investigating-public-dns/scripts/agent.py": "raise RuntimeError('must never execute')",
                "skills/investigating-public-dns/LICENSE": "Apache-2.0"})
            library = ExternalSkillArchive(path)
            catalog = library.catalog(query="dns")
            self.assertEqual(catalog["registered_external_skills"], 1)
            self.assertFalse(catalog["execution_enabled"])
            self.assertFalse(catalog["skills"][0]["executable"])
            reference = library.reference("investigating-public-dns")
            self.assertEqual(reference["markdown"], GOOD)
            self.assertNotIn("must never execute", reference["markdown"])
            self.assertTrue(reference["requires_human_review"])

    def test_traversal_and_wrong_identity_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for item in ["skills/../escape/SKILL.md", "skills/other/SKILL.md",
                         "/skills/investigating-public-dns/SKILL.md",
                         "skills\\investigating-public-dns\\SKILL.md"]:
                path = make_zip(root, {item: GOOD})
                with self.subTest(item=item), self.assertRaises(SkillArchiveError):
                    ExternalSkillArchive(path)

    def test_duplicate_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "skills.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("skills/investigating-public-dns/SKILL.md", GOOD)
                z.writestr("skills/INVESTIGATING-PUBLIC-DNS/SKILL.md", GOOD)
            with self.assertRaises(SkillArchiveError):
                ExternalSkillArchive(path)
            path = root / "symlink.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("skills/investigating-public-dns/SKILL.md", GOOD)
                entry = zipfile.ZipInfo("skills/investigating-public-dns/scripts/agent.py")
                entry.create_system = 3
                entry.external_attr = (0o120777 << 16)
                z.writestr(entry, "/etc/passwd")
            with self.assertRaises(SkillArchiveError):
                ExternalSkillArchive(path)

    def test_missing_primary_skill_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = make_zip(Path(tmp), {
                "skills/investigating-public-dns/SKILL.md": GOOD,
                "skills/missing-primary/scripts/agent.py": "pass"})
            library = ExternalSkillArchive(path)
            self.assertEqual(library.catalog()["missing_primary_skill_files"], ["missing-primary"])
            with self.assertRaises(SkillArchiveError):
                library.reference("missing-primary")

    def test_invalid_queries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = make_zip(Path(tmp), {"skills/investigating-public-dns/SKILL.md": GOOD})
            library = ExternalSkillArchive(path)
            with self.assertRaises(SkillArchiveError):
                library.catalog(limit=0)
            with self.assertRaises(SkillArchiveError):
                library.reference("../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
