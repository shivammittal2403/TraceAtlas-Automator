"""Release identity and configuration never stand in for observed hosted proof."""
from __future__ import annotations

import importlib.util
import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas import __version__
from traceatlas.deployment import DeploymentDoctor
from vercel_app_data import CANONICAL_REPOSITORY, VERSION, build_identity

ROOT = Path(__file__).resolve().parents[1]


class BuildIdentityTests(unittest.TestCase):
    def test_package_console_and_project_versions_agree(self):
        version = re.search(r'^version = "([^"]+)"$', (ROOT / 'pyproject.toml').read_text(), re.M).group(1)
        self.assertEqual(VERSION, version)
        self.assertEqual(VERSION, __version__)
        self.assertIn(f'id="version">{VERSION}</span>', (ROOT / 'public/index.html').read_text())

    def test_missing_metadata_does_not_invent_a_commit_or_link(self):
        with patch.dict(os.environ, {}, clear=True):
            identity = build_identity()
        self.assertIsNone(identity['commit_sha'])
        self.assertIsNone(identity['observed_repository'])
        self.assertIsNone(identity['deployment_id'])
        self.assertEqual(identity['repository_link'], 'NOT_VERIFIED')
        self.assertEqual(identity['metadata_source'], 'NOT_AVAILABLE')

    def test_metadata_names_the_actual_commit_and_wrong_repository(self):
        values = {'VERCEL_GIT_COMMIT_SHA': 'A' * 40, 'VERCEL_GIT_REPO_OWNER': 'shivammittal2403',
                  'VERCEL_GIT_REPO_SLUG': 'TraceAtlas-OSINT', 'VERCEL_ENV': 'production',
                  'VERCEL_DEPLOYMENT_ID': 'dpl_SyntheticBuild'}
        with patch.dict(os.environ, values, clear=True):
            identity = build_identity()
        self.assertEqual(identity['commit_sha'], 'a' * 40)
        self.assertEqual(identity['repository_link'], 'MISMATCH')
        self.assertEqual(identity['expected_repository'], CANONICAL_REPOSITORY)
        self.assertEqual(identity['environment'], 'production')
        values['VERCEL_GIT_REPO_SLUG'] = 'TraceAtlas-Automator'
        with patch.dict(os.environ, values, clear=True):
            self.assertEqual(build_identity()['repository_link'], 'MATCH')

    def test_malformed_metadata_and_unrelated_secrets_are_not_reflected(self):
        for sha in ('a' * 39, 'a' * 41, 'HEAD', 'a' * 40 + '\n'):
            with self.subTest(sha=sha), patch.dict(os.environ, {
                'VERCEL_GIT_COMMIT_SHA': sha, 'VERCEL_GIT_REPO_OWNER': '../user',
                'VERCEL_GIT_REPO_SLUG': 'repo\nforged', 'VERCEL_ENV': 'production\nforged',
                'VERCEL_DEPLOYMENT_ID': 'dpl_bad\n', 'SUPABASE_SECRET_KEY': 'fixture-never-public',
            }, clear=True):
                identity = build_identity()
            self.assertIsNone(identity['commit_sha'])
            self.assertIsNone(identity['observed_repository'])
            self.assertIsNone(identity['deployment_id'])
            self.assertEqual(identity['environment'], 'UNKNOWN')
            self.assertNotIn('fixture-never-public', str(identity))

    def test_health_does_not_infer_worker_or_hosted_readiness_from_config(self):
        spec = importlib.util.spec_from_file_location('build_identity_health', ROOT / 'api/health.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        handler = module.handler.__new__(module.handler)
        for configured in (False, True):
            with self.subTest(configured=configured), patch.object(module, 'configured', return_value=configured), \
                 patch.object(handler, '_send') as send, patch.dict(os.environ, {}, clear=True):
                handler.do_GET()
            status, payload = send.call_args.args
            self.assertEqual(status, 200)
            self.assertEqual(payload['configuration_ready'], configured)
            self.assertIsNone(payload['isolated_worker'])
            self.assertTrue(payload['worker_required'])
            self.assertEqual(payload['hosted_readiness'], 'NOT_VERIFIED')
            self.assertIsNone(payload['build']['commit_sha'])

    def test_static_production_config_cannot_qualify_a_hosted_release(self):
        with patch.dict(os.environ, {'SUPABASE_URL': 'https://fixture.supabase.co',
                                    'SUPABASE_PUBLISHABLE_KEY': 'sb_publishable_synthetic_fixture'}, clear=True):
            result = DeploymentDoctor(ROOT).run(production=True)
        self.assertTrue(result['ready'])
        self.assertTrue(result['production_configuration_ready'])
        self.assertFalse(result['production_ready'])
        self.assertEqual(result['hosted_verification'], 'NOT_VERIFIED')


if __name__ == '__main__':
    unittest.main()
