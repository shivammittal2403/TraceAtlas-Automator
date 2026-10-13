"""Real Tk regressions for current-case report export and panel reset."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.addons.intelligence_v1.modules import orgint, osint


@unittest.skipUnless(os.environ.get("DISPLAY"), "Native Tk verification requires Xvfb/display")
class PanelStateTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("showinfo", "showwarning", "showerror"):
            self.stack.enter_context(patch("tkinter.messagebox." + name))
        for target in ("urllib.request.urlopen", "socket.create_connection", "socket.socket.connect"):
            self.stack.enter_context(patch(target, side_effect=AssertionError("Offline panel used network")))

    def panel(self, cls):
        app = cls()
        self.addCleanup(app.destroy)
        app.withdraw()
        return app

    def test_orgint_export_rebuilds_after_case_changes(self):
        app = self.panel(orgint.TraceAtlasORGINTPanel)
        app.set_widget_value("case_id", "CASE-A")
        app.generate_plan()
        app.analyzed_files = [{"filename": "case-a-evidence.json"}]
        app.parsed["organizations"] = [{"name": "case-a-only"}]
        app.set_widget_value("case_id", "CASE-B")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with patch.object(orgint.filedialog, "asksaveasfilename", return_value=str(path)):
                app.export_json()
            result = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result["payload"]["case_id"], "CASE-B")
        self.assertNotIn("case-a-only", json.dumps(result))
        self.assertNotIn("case-a-evidence", json.dumps(result))
        self.assertEqual(app.analyzed_files, [])

    def test_orgint_copy_uses_current_form_and_clear_resets_caches(self):
        app = self.panel(orgint.TraceAtlasORGINTPanel)
        app.generate_plan()
        app.set_widget_value("case_id", "CURRENT-CASE")
        with patch.object(app, "clipboard_clear"), patch.object(app, "clipboard_append") as copy:
            app.copy_output()
        self.assertEqual(json.loads(copy.call_args.args[0])["payload"]["case_id"], "CURRENT-CASE")
        app.analyzed_files = [{"filename": "old.json"}]
        app.parsed["organizations"] = [{"name": "old"}]
        with patch.object(orgint.messagebox, "askyesno", return_value=False):
            app.clear_form()
        self.assertTrue(app.last_result)
        with patch.object(orgint.messagebox, "askyesno", return_value=True):
            app.clear_form()
        self.assertEqual(app.last_result, {})
        self.assertEqual(app.analyzed_files, [])
        self.assertEqual(app.parsed, orgint.empty_parsed())
        self.assertEqual(app.output.get("1.0", "end").strip(), "")
        self.assertEqual(app.get_widget_value("case_id"), "ORGINT-CASE-001")

    def test_orgint_export_cancel_and_io_failure(self):
        app = self.panel(orgint.TraceAtlasORGINTPanel)
        with patch.object(orgint.filedialog, "asksaveasfilename", return_value=""), patch("builtins.open") as opened:
            app.export_json()
        opened.assert_not_called()
        with patch.object(orgint.filedialog, "asksaveasfilename", return_value="report.json"), \
                patch("builtins.open", side_effect=PermissionError("read-only")), \
                patch.object(orgint.messagebox, "showerror") as error:
            app.export_json()
        error.assert_called_once()
        self.assertTrue(app.last_result)

    def test_orgint_local_report_identifies_its_case(self):
        app = self.panel(orgint.TraceAtlasORGINTPanel)
        payload = app.collect_payload()
        result = app._build_local_analysis_report([], orgint.empty_parsed(), payload, orgint.policy_screen(payload))
        self.assertEqual(result["payload"]["case_id"], payload["case_id"])

    def test_osint_result_matches_display_and_invalidates_on_edit(self):
        app = self.panel(osint.TraceAtlasOSINTPanel)
        self.assertEqual(app.last_result, {})
        app.generate_plan()
        self.assertEqual(app.last_result, json.loads(app.output.get("1.0", "end")))
        app.set_widget_value("case_id", "SECOND-CASE")
        app.collect_payload()
        self.assertEqual(app.last_result, {})
        app.generate_plan()
        self.assertEqual(app.last_result["payload"]["case_id"], "SECOND-CASE")
        with patch.object(osint.messagebox, "askyesno", return_value=True):
            app.clear_form()
        self.assertEqual(app.last_result, {})
        self.assertEqual(app.output.get("1.0", "end").strip(), "")
