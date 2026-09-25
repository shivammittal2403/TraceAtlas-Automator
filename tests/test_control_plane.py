from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from vercel_control import ControlPlaneError, SupabaseGateway, clear_session_cookie, session_cookie, validate_asset


ROOT = Path(__file__).resolve().parents[1]


class ControlPlaneTests(unittest.TestCase):
    def test_cloud_asset_scope_rejects_identity_and_private_networks(self):
        self.assertEqual(validate_asset("domain", "Example.COM"), ("domain", "example.com"))
        self.assertEqual(validate_asset("hash", "A" * 64), ("hash", "a" * 64))
        for kind, value in (("email", "person@example.com"), ("ip", "127.0.0.1"),
                            ("ip", "10.0.0.1"), ("url", "http://localhost/admin"),
                            ("url", "https://user:pass@example.com")):
            with self.subTest(kind=kind, value=value), self.assertRaises(ControlPlaneError):
                validate_asset(kind, value)

    def test_session_cookie_is_short_lived_http_only_and_strict(self):
        cookie = session_cookie("a" * 40, 999999)
        for marker in ("HttpOnly", "Secure", "SameSite=Strict", "Max-Age=3600"):
            self.assertIn(marker, cookie)
        self.assertIn("Max-Age=0", clear_session_cookie())

    def test_gateway_blocks_arbitrary_tables_and_rpc(self):
        env = {"SUPABASE_URL": "https://abcdefghijklmnopqrst.supabase.co",
               "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_" + "x" * 40}
        with patch.dict(os.environ, env, clear=False):
            gateway = SupabaseGateway("a" * 40)
            with self.assertRaisesRegex(ControlPlaneError, "blocked_table"):
                gateway.select("auth.users", {"select": "*"})
            with self.assertRaisesRegex(ControlPlaneError, "blocked_function"):
                gateway.rpc("run_sql", {})

    def test_supabase_migration_has_rls_and_worker_boundaries(self):
        sql = (ROOT / "supabase/migrations/20260925000100_traceatlas_control_plane.sql").read_text()
        self.assertEqual(sql.count(" enable row level security;"), 10)
        self.assertIn("revoke all on all tables in schema public from anon, authenticated", sql)
        self.assertIn("or not (select private.is_org_member(v_organisation_id", sql)
        self.assertIn("for update skip locked", sql)
        self.assertNotIn("grant insert on public.investigation_jobs to authenticated", sql)
        self.assertNotIn("create policy jobs_insert", sql)
        self.assertIn("grant execute on function public.claim_next_investigation_job(text) to service_role", sql)
        self.assertNotIn("grant execute on function public.claim_next_investigation_job(text) to authenticated", sql)

    def test_supabase_foreign_keys_have_covering_indexes(self):
        sql = (ROOT / "supabase/migrations/20260925000200_traceatlas_fk_indexes.sql").read_text()
        self.assertEqual(sql.count("create index if not exists"), 21)
        for marker in (
            "evidence_items_case_org_fk_idx",
            "graph_edges_source_org_fk_idx",
            "investigation_jobs_asset_org_fk_idx",
            "job_events_job_org_fk_idx",
        ):
            self.assertIn(marker, sql)


if __name__ == "__main__":
    unittest.main()
