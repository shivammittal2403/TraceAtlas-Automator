"""Headless regressions for standalone planning methods; native Tk is not exercised."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_panel(filename):
    tk = types.ModuleType('tkinter')
    tk.Tk = object
    tk.TclError = RuntimeError
    ttk = types.ModuleType('tkinter.ttk')
    dialogs = types.ModuleType('tkinter.filedialog')
    messages = types.ModuleType('tkinter.messagebox')
    dialogs.asksaveasfilename = mock.Mock(return_value='')
    messages.showinfo = mock.Mock()
    messages.showwarning = mock.Mock()
    messages.showerror = mock.Mock()
    tk.ttk, tk.filedialog, tk.messagebox = ttk, dialogs, messages
    spec = importlib.util.spec_from_file_location('planning_test_' + filename[:-3], ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {
        'tkinter': tk, 'tkinter.ttk': ttk,
        'tkinter.filedialog': dialogs, 'tkinter.messagebox': messages,
    }):
        spec.loader.exec_module(module)
    return module


class OutputBuffer:
    def __init__(self):
        self.value = ''

    def delete(self, *args):
        self.value = ''

    def insert(self, index, value):
        self.value = value

    def get(self, *args):
        return self.value


def pane_for(module, name):
    pane = object.__new__(getattr(module, name))
    pane.output = OutputBuffer()
    pane.notebook = types.SimpleNamespace(select=mock.Mock())
    pane.output_tab = object()
    pane.last_result = {}
    return pane


def synthetic_payload(target='Example Company'):
    return {
        'case_id': 'SYNTHETIC-CASE', 'task_id': 'SYNTHETIC-TASK',
        'objective': 'Review publicly available information',
        'target': target, 'target_type': 'company',
        'questions': ['What public posts are available?'],
        'platforms': ['GitHub'], 'jurisdiction': 'IN',
        'authorization': {}, 'scope': {'allowed_source_types': ['public API']},
        'time_range': {'from': '2024-01-01', 'to': '2024-12-31'},
    }


class PlanningPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.osint = load_panel('OSINTpanel.py')
        cls.social = load_panel('socmint.py')

    def test_defaults_do_not_assert_authority_or_configured_connectors(self):
        for module, name in [(self.osint, 'TraceAtlasOSINTPanel'), (self.social, 'TraceAtlasSOCMINTPanel')]:
            with self.subTest(panel=name):
                pane = pane_for(module, name)
                fields = {}
                pane.set_widget_value = lambda key, value: fields.__setitem__(key, value)
                pane._set_defaults()
                self.assertEqual(json.loads(fields['authorization']), {})
                self.assertEqual(module.parse_list(fields['configured_connectors']), [])

    def test_planned_rows_never_establish_authority(self):
        for authorization in ({}, {'authorized_by': 'unverified supplied text'}):
            with self.subTest(authorization=authorization):
                payload = synthetic_payload()
                payload['authorization'] = authorization
                osint_pane = pane_for(self.osint, 'TraceAtlasOSINTPanel')
                social_pane = pane_for(self.social, 'TraceAtlasSOCMINTPanel')
                plans = [
                    osint_pane._build_search_plan(payload),
                    social_pane._build_search_plan(payload, payload['questions'], ['GitHub'], [{'type': 'target', 'value': payload['target']}]),
                ]
                for plan in plans:
                    self.assertTrue(plan)
                    for row in plan:
                        self.assertEqual(row['authorization_status'], 'NOT_VERIFIED_PLANNING_ONLY')
                        self.assertEqual(row['execution_status'], 'NOT_EXECUTED_PLANNING_ONLY')

    def test_social_truncation_rows_never_establish_authority(self):
        pane = pane_for(self.social, 'TraceAtlasSOCMINTPanel')
        payload = synthetic_payload()
        plan = pane._build_search_plan(
            payload, ['Public posts and connections'] * 9,
            self.social.DEFAULT_PLATFORMS,
            [{'type': 'target', 'value': 'Synthetic ' + str(index)} for index in range(12)],
        )
        self.assertTrue(any(row['search_type'] == 'planning_limit' for row in plan))
        self.assertTrue(any(row['search_type'] == 'truncation' for row in plan))
        self.assertTrue(all(row['authorization_status'] == 'NOT_VERIFIED_PLANNING_ONLY' for row in plan))

    def test_keyword_screen_does_not_establish_authority(self):
        pane = pane_for(self.social, 'TraceAtlasSOCMINTPanel')
        payload = synthetic_payload()
        self.assertEqual(pane.policy_screen(payload)['status'], 'NOT_VERIFIED_PLANNING_ONLY')
        payload['authorization'] = {'authorized_by': 'unverified supplied text'}
        self.assertEqual(pane.policy_screen(payload)['status'], 'NOT_VERIFIED_PLANNING_ONLY')

    def test_social_export_rebuilds_changed_form_and_policy(self):
        for blocked in (False, True):
            with self.subTest(blocked=blocked), tempfile.TemporaryDirectory() as temporary:
                pane = pane_for(self.social, 'TraceAtlasSOCMINTPanel')
                current = synthetic_payload('Old Example')
                pane.collect_payload = lambda: current
                pane.generate_plan()
                self.assertEqual(pane.last_result['payload']['target'], 'Old Example')
                current = synthetic_payload('Current Example')
                current['scope'] = {'allowed_source_types': ['public GitHub organization only']}
                if blocked:
                    current['objective'] = 'Access a private account'
                pane.run_policy_screen()
                destination = Path(temporary) / 'plan.json'
                with mock.patch.object(self.social.filedialog, 'asksaveasfilename', return_value=str(destination)):
                    pane.export_json()
                saved = json.loads(destination.read_text(encoding='utf-8'))
                self.assertEqual(saved['payload']['target'], 'Current Example')
                self.assertEqual(saved['payload']['scope'], current['scope'])
                self.assertEqual(saved['mode'], 'POLICY_BLOCKED' if blocked else 'PLANNING_ONLY')
                if blocked:
                    self.assertEqual(saved['search_plan'], [])
                else:
                    self.assertTrue(saved['socmint_search_plan'])
                    self.assertTrue(all(row.get('target_identifier') == 'Current Example' for row in saved['socmint_search_plan']))

    def test_osint_plan_limit_and_reset_are_exact(self):
        pane = pane_for(self.osint, 'TraceAtlasOSINTPanel')
        pane._query_families_for_target = lambda *args: [('web_search', 'proposed_public_index', 'public_web', 'review')]
        payload = synthetic_payload()
        payload['questions'] = ['Public question'] * self.osint.MAX_PLANNED_QUERIES
        self.assertEqual(len(pane._build_search_plan(payload)), self.osint.MAX_PLANNED_QUERIES)
        self.assertFalse(pane.plan_truncated)
        payload['questions'].append('One more public question')
        self.assertEqual(len(pane._build_search_plan(payload)), self.osint.MAX_PLANNED_QUERIES)
        self.assertTrue(pane.plan_truncated)
        payload['questions'] = ['Small public question']
        self.assertEqual(len(pane._build_search_plan(payload)), 1)
        self.assertFalse(pane.plan_truncated)

    def test_osint_generated_output_reports_truncation(self):
        pane = pane_for(self.osint, 'TraceAtlasOSINTPanel')
        payload = synthetic_payload()
        payload['questions'] = ['Public question'] * (self.osint.MAX_PLANNED_QUERIES + 1)
        pane.collect_payload = lambda: payload
        pane.generate_plan()
        result = json.loads(pane.output.value)
        self.assertEqual(len(result['search_plan']), self.osint.MAX_PLANNED_QUERIES)
        self.assertEqual(result['planning_limits'], {'max_planned_queries': self.osint.MAX_PLANNED_QUERIES, 'truncated': True})
        self.assertTrue(any('truncated' in warning.lower() for warning in result['warnings']))


if __name__ == '__main__':
    unittest.main()
