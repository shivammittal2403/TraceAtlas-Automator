"""Optional suite-wide invocation and native UI smoke tests.

Successful invocation is not live-source proof or deep feature qualification.
"""
from contextlib import ExitStack
import importlib
import json
import os
import unittest
from unittest.mock import patch

from fixture_inputs import fixture
from traceatlas.addons.intelligence_v1.registry import catalog
from traceatlas.workforce.intelligence import run_offline


class AllModuleContracts(unittest.TestCase):
    pass


def smoke(item):
    def test(self):
        contract, result = run_offline(item["id"], fixture(item))
        self.assertIsInstance(result, (dict, list))
        json.dumps(result, allow_nan=False)
        self.assertFalse(contract["live_verified"])
        self.assertFalse(contract["hosted_verified"])
        if item["adapter"] == "pipeline":
            self.assertEqual(result["status"], "BLOCKED_CONFIGURATION")
    return test


class AllNativePanels(unittest.TestCase):
    """Exercise actual Tk initialization; skip transparently without a display."""


def native(item):
    @unittest.skipUnless(os.environ.get("DISPLAY"), "Native Tk verification requires Xvfb/display")
    def test(self):
        module = importlib.import_module("traceatlas.addons.intelligence_v1.modules." + item["id"])
        app = None
        with ExitStack() as stack:
            for name in ("showinfo", "showwarning", "showerror", "askyesno"):
                stack.enter_context(patch("tkinter.messagebox." + name, return_value=False))
            for target in ("urllib.request.urlopen", "socket.create_connection", "socket.socket.connect"):
                stack.enter_context(patch(target, side_effect=AssertionError("UI initialization cannot collect externally")))
            try:
                app = getattr(module, item["gui_entry"])()
                app.withdraw()
                app.update_idletasks()
                self.assertTrue(app.winfo_exists())
                self.assertEqual(app.last_result, {})
            finally:
                if app is not None:
                    app.destroy()
    return test


for item in catalog()["modules"]:
    setattr(AllModuleContracts, "test_" + item["id"], smoke(item))
    if item.get("gui_entry"):
        setattr(AllNativePanels, "test_" + item["id"], native(item))


if __name__ == "__main__":
    unittest.main()
