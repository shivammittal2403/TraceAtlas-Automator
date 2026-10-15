"""Recon-ng core adapter contract. No real internet or unapproved scripts executed."""
from __future__ import annotations
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.policy import PolicyError
from traceatlas.integrations.registry import TOOLS
from traceatlas.integrations.runner import IntegrationRunner
from traceatlas.integrations.recon_ng import (
    APPROVED_MODULES, RECON_UPSTREAM_SHA, MARKETPLACE_SHA, catalog_marketplace,
    read_workspace_events, stage_approved_module, validate_module, workspace_alias
)

APPROVED = "recon/domains-hosts/certificate_transparency"


class ReconNgIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = CaseDB(self.root / "case.db")
        self.db.create_case("case-1", "Recon", "Test authorized recon")
        self.runner = IntegrationRunner(self.db, self.root)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _make_marketplace(self):
        src = self.root / "marketplace" / "modules" / "recon" / "domains-hosts"
        src.mkdir(parents=True, exist_ok=True)
        (src / "certificate_transparency.py").write_text(
            "class Module:\n    meta = {'name':'CT', 'description':'Cert lookup', 'version':'1'}\n",encoding="utf8")
        other = self.root / "marketplace" / "modules" / "exploitation" / "injection"
        other.mkdir(parents=True)
        (other / "command_injector.py").write_text("raise RuntimeError('must never run')\\n")
        return self.root / "marketplace"

    def _make_db(self, path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(path) as c:
            c.execute("CREATE TABLE domains (domain TEXT, notes TEXT, module TEXT)")
            c.execute("CREATE TABLE hosts (host TEXT, ip_address TEXT, module TEXT)")
            c.execute("CREATE TABLE credentials (username TEXT, password TEXT)")
            c.executemany("INSERT INTO domains VALUES (?,?,?)", [
                ("example.org", "ignore", APPROVED),
                ("evil.example.org.bad", "ignore", APPROVED),
            ])
            c.execute("INSERT INTO hosts VALUES (?,?,?)", ("api.example.org","10.2.3.4", APPROVED))
            c.execute("INSERT INTO credentials VALUES (?,?)",("someone","super-secret-should-not-escape"))

    def test_full_pinned_upstream_sources_are_declared(self):
        self.assertEqual(len(RECON_UPSTREAM_SHA),40)
        self.assertEqual(len(MARKETPLACE_SHA),40)
        self.assertEqual(len(APPROVED_MODULES),2)

    def test_marketplace_catalog_ast_not_code_execution(self):
        root=self._make_marketplace()
        listing=catalog_marketplace(root)
        self.assertEqual(len(listing),2)
        self.assertEqual(len([x for x in listing if x["execution"]=="approved_passive"]),1)
        self.assertEqual(next(x for x in listing if x["module_id"]==APPROVED)["name"],"CT")

    def test_only_allowlisted_modules_can_run(self):
        for bad in ("exploitation/injection/command_injector", "recon/domains-hosts/brute_hosts",
                    "../recon/domains-hosts/hackertarget", "recon/domains-hosts/anything;rm"):
            with self.subTest(module=bad), self.assertRaises(PolicyError):
                validate_module(bad,"domain","example.org")
        self.assertEqual(validate_module(APPROVED,"domain","example.org"),APPROVED)

    def test_path_and_target_validation(self):
        with self.assertRaises(PolicyError):
            validate_module(APPROVED,"ip","8.8.8.8")
        with self.assertRaises(PolicyError):
            validate_module(APPROVED,"domain","127.0.0.1")
        self.assertRegex(workspace_alias("../../etc/passwd"),r"^ta_[0-9a-f]{20}$")

    def test_copy_isolated_module_no_symlink_and_no_side_effect(self):
        market=self._make_marketplace()
        home=self.root/"home"
        home.mkdir()
        dst=stage_approved_module(market,home,APPROVED)
        self.assertTrue(dst.is_file())
        self.assertIn("/.recon-ng/modules/",dst.as_posix())
        self.assertNotEqual(dst.parent,market)
        with self.assertRaises(ValueError):
            stage_approved_module(market,home,APPROVED)

    def test_workspace_import_is_read_only_redacts_credentials_and_filters_scope(self):
        database=self.root/"data.db"
        self._make_db(database)
        before=hashlib.sha256(database.read_bytes()).hexdigest()
        report=read_workspace_events(database,target_type="domain",target="example.org",module=APPROVED)
        self.assertEqual([x["data"] for x in report["records"]],["example.org","api.example.org"])
        self.assertEqual(report["workspace_db_sha256"],before)
        self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(),before)
        self.assertNotIn("super-secret-should-not-escape",json.dumps(report))
        self.assertGreater(report["out_of_scope_or_invalid_dropped"],0)

    def test_command_only_approved_module_and_safe_workspace(self):
        spec=TOOLS["recon-ng"]
        args,_=self.runner.build_command(spec,"/usr/bin/recon-cli","example.org","../evil",self.root,{"module":APPROVED})
        self.assertEqual(args[0],"/usr/bin/recon-cli")
        self.assertEqual(args[args.index("-w")+1],workspace_alias("../evil"))
        self.assertIn("--stealth",args)
        with self.assertRaises(PolicyError):
            self.runner.build_command(spec,"/usr/bin/recon-cli","example.org","case-1",self.root,{"module":"exploitation/injection/command_injector"})

    def test_existing_runner_blocks_arbitrary_marketplace_module(self):
        with self.assertRaises(PolicyError):
            self.runner.run("case-1","recon-ng","domain","example.org",
                            authorized=True,options={"module":"exploitation/injection/command_injector"})

    def test_recon_ng_rejects_cross_type_scope_and_extra_options(self):
        for kind, value in (("username","example.org"),("email","alice@example.org")):
            with self.subTest(kind=kind), self.assertRaises(PolicyError):
                self.runner.run("case-1","recon-ng",kind,value,authorized=True,
                                options={"module":APPROVED})
        with self.assertRaises(PolicyError):
            self.runner.run("case-1","recon-ng","domain","example.org",
                            authorized=True,options={"module":APPROVED,"case":"../../escape"})

    def test_end_to_end_mocked_workspace_event_ingestion(self):
        self._make_marketplace()
        market=self.root/"marketplace"
        def fake_run(command, **kwargs):
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["env"]["HOME"],str(kwargs["cwd"]))
            self.assertIn("--stealth",command)
            home=Path(kwargs["cwd"])
            db=home/".recon-ng"/"workspaces"/workspace_alias("case-1")/"data.db"
            self._make_db(db)
            return subprocess.CompletedProcess(command,0,stdout="execution output",stderr="")
        with patch.object(self.runner,"resolve_binary",return_value="/usr/bin/recon-cli"), \
             patch("traceatlas.integrations.recon_ng.marketplace_root",return_value=market), \
             patch("traceatlas.integrations.runner.subprocess.run",side_effect=fake_run):
            report=self.runner.run("case-1","recon-ng","domain","example.org",authorized=True,
                                   options={"module":APPROVED})
        self.assertEqual(report["status"],"completed")
        self.assertEqual(report["stats"]["structured_records"],2)
        self.assertEqual(report["stats"]["out_of_scope_dropped"],1)
        self.assertGreater(len(self.db.evidence("case-1")),0)
        events=self.db.spider_events(report["scan_id"])
        self.assertEqual([e["data"] for e in events[1:]],["example.org","api.example.org"])

if __name__=="__main__":
    unittest.main()
