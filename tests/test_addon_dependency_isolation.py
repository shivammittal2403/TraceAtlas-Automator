"""Optional add-on dependencies must not break the standard-library core import path.

The clean CI core job installs only `python -m pip install .` (no PyYAML). The
vendored archive add-ons may use optional third-party libraries, but importing
them and running their governed fallbacks must succeed without those extras.
Reproduces the undeclared-yaml defect found against main 6470957.
"""
from __future__ import annotations

import builtins
import io
import unittest


def _without_yaml(import_fn):
    def blocked(name, *args, **kwargs):
        if name == "yaml" or name.startswith("yaml."):
            raise ModuleNotFoundError("No module named 'yaml'")
        return import_fn(name, *args, **kwargs)
    return blocked


class AddonDependencyIsolationTests(unittest.TestCase):
    def setUp(self):
        self._real_import = builtins.__import__
        self._stale = {name: mod for name, mod in list(__import__("sys").modules.items())
                       if name == "yaml" or name.startswith("yaml.")
                       or name.startswith("traceatlas.addons.cute_v1")}
        for name in self._stale:
            del __import__("sys").modules[name]

    def tearDown(self):
        builtins.__import__ = self._real_import
        import sys
        for name in ("traceatlas.addons.cute_v1.sources.registry",
                     "traceatlas.addons.cute_v1.ingestion.parsers.generic_structured"):
            sys.modules.pop(name, None)
        sys.modules.update(self._stale)

    def test_cute_source_registry_imports_without_pyyaml(self):
        builtins.__import__ = _without_yaml(self._real_import)
        from traceatlas.addons.cute_v1.sources.registry import SourceRegistry

        registry = SourceRegistry.load_default()
        # Built-in integration-tested records remain available even with no YAML extra.
        self.assertIsNotNone(registry.get("dns-system"))

    def test_yaml_parser_reports_unavailable_without_pyyaml(self):
        builtins.__import__ = _without_yaml(self._real_import)
        from traceatlas.addons.cute_v1.ingestion.parsers.generic_structured import YamlParser
        from traceatlas.addons.cute_v1.ingestion.limits import IngestionLimits

        result = YamlParser().parse(io.BytesIO(b"a: 1\n"), artifact_id="art-1",
                                    limits=IngestionLimits())
        self.assertFalse(result.ok)
        self.assertTrue(any("PyYAML" in issue.message for issue in result.errors))


if __name__ == "__main__":
    unittest.main()
