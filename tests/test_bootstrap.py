from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_scripts_are_valid_bash(self):
        for name in ("setup.sh", "set.sh", "start.sh"):
            path = ROOT / name
            self.assertTrue(path.is_file(), name)
            result = subprocess.run(
                ["bash", "-n", str(path)], capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_setup_has_offline_fallback_and_verification(self):
        script = (ROOT / "setup.sh").read_text(encoding="utf-8")
        self.assertIn("using system Python with isolated PYTHONPATH", script)
        self.assertIn("unittest discover", script)
        self.assertIn("compileall", script)
        self.assertIn("integrations doctor", script)
        self.assertIn("intel doctor", script)
        self.assertIn("capabilities doctor", script)
        self.assertIn("SOURCE_FINGERPRINT", script)
        self.assertIn("TRACEATLAS_FORCE_SETUP", script)
        self.assertIn("Recovering an interrupted setup lock", script)
        self.assertIn("openosint-venv", script)
        self.assertIn("TRACEATLAS_SKIP_OPENOSINT", script)
        self.assertIn("uv sync --locked", script)
        self.assertIn("-m openosint.cli --help", script)

    def test_launcher_uses_module_entrypoint_without_shell_eval(self):
        script = (ROOT / "start.sh").read_text(encoding="utf-8")
        self.assertIn('-m traceatlas.cli "$@"', script)
        self.assertNotIn("eval ", script)


if __name__ == "__main__":
    unittest.main()
