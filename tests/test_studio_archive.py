"""Verify Studio reconstruction, redaction identities and its offline smoke suite."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("studio_assembler", ROOT / "extras/traceatlas_studio/assemble.py")
ASSEMBLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLER)


class StudioArchiveTests(unittest.TestCase):
    def test_verified_assembly_and_offline_self_test(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "studio.py"
            with patch.object(ASSEMBLER, "HERE", Path(directory)), patch.object(ASSEMBLER, "OUTPUT", target):
                ASSEMBLER.assemble()
            # Preserve the existing CLI self-test, while making accidental collection fail.
            bootstrap = (
                "import runpy,socket,sys\n"
                "def forbidden(*a,**k): raise AssertionError('Offline self-test attempted network')\n"
                "socket.create_connection=forbidden\n"
                "socket.socket.connect=forbidden\n"
                "sys.argv=[sys.argv[1], '--self-test']\n"
                "runpy.run_path(sys.argv[0], run_name='__main__')\n"
            )
            environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
            environment["PYTHONIOENCODING"] = "utf-8"
            result = subprocess.run([sys.executable, "-I", "-c", bootstrap, str(target)],
                                    capture_output=True, text=True, encoding="utf-8",
                                    timeout=90, cwd=directory, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-1000:])
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "PASS")
            self.assertTrue(report["original_sha256_match"])
            self.assertEqual(len(report["domain_smoke"]), 19)
            self.assertEqual(set(report["domain_smoke"].values()), {"PASS"})

    def test_bad_source_checksum_cannot_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "studio.py"
            with patch.object(ASSEMBLER, "EXPECTED_SHA256", "0" * 64), \
                    patch.object(ASSEMBLER, "OUTPUT", target):
                with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
                    ASSEMBLER.assemble()
            self.assertFalse(target.exists())
