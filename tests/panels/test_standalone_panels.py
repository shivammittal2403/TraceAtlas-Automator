"""Offline regressions: no real investigation targets or remote requests."""
import importlib
import json
import math
import tempfile
import hashlib
import subprocess
import wave
from pathlib import Path
import socket
import sys
import tkinter as tk
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "integrations" / "standalone-panels"))
NAMES = ["audint", "geomint", "imgmint", "maretineint", "osint",
         "scamint", "socmint", "vedmint", "webint"]


class PanelTests(unittest.TestCase):
    def test_each_panel_starts_without_invented_authorization(self):
        for name in NAMES:
            with self.subTest(panel=name):
                module = importlib.import_module(name)
                cls = next(value for key, value in vars(module).items()
                           if key.startswith("TraceAtlas") and key.endswith("Panel"))
                app = cls()
                try:
                    app.withdraw()
                    app.update_idletasks()
                    self.assertEqual(app.collect_payload()["authorization"], {})
                finally:
                    app.destroy()

    def test_every_panel_generates_and_exports_current_case(self):
        for name in NAMES:
            with self.subTest(panel=name):
                module = importlib.import_module(name)
                cls = next(value for key, value in vars(module).items()
                           if key.startswith("TraceAtlas") and key.endswith("Panel"))
                app = cls()
                try:
                    with patch.object(module.messagebox, "showwarning"), \
                         patch.object(module.messagebox, "showinfo"), \
                         patch.object(module.messagebox, "showerror") as errors, \
                         patch.object(module.messagebox, "askyesno", return_value=True), \
                         tempfile.TemporaryDirectory() as directory:
                        app.set_widget_value("case_id", "FIRST")
                        app.generate_plan()
                        app.set_widget_value("case_id", "SECOND")
                        destination = str(Path(directory) / "export.json")
                        with patch.object(module.filedialog, "asksaveasfilename", return_value=destination):
                            if name == "osint":
                                app.export_task_json()
                            else:
                                app.export_json()
                        errors.assert_not_called()
                        result = json.loads(Path(destination).read_text())
                        self.assertEqual(result.get("payload", result)["case_id"], "SECOND")
                        app.clear_form()
                        self.assertFalse(app.__dict__.get("last_result"))
                finally:
                    app.destroy()

    def test_case_change_invalidates_cached_evidence_in_every_panel(self):
        for name in NAMES:
            with self.subTest(panel=name):
                module = importlib.import_module(name)
                cls = next(value for key, value in vars(module).items()
                           if key.startswith("TraceAtlas") and key.endswith("Panel"))
                app = cls()
                try:
                    app.collect_payload()
                    app.last_result = {"old_case": True}
                    for key in ("analyzed_audio", "analyzed_videos", "analyzed_images",
                                "analyzed_files", "extracted_segments", "extracted_frames"):
                        if key in app.__dict__:
                            setattr(app, key, [{"old_case": True}])
                    app.collect_payload()
                    self.assertEqual(app.last_result, {"old_case": True})
                    app.set_widget_value("case_id", "NEW-CASE")
                    app.collect_payload()
                    self.assertEqual(app.last_result, {})
                    for key in ("analyzed_audio", "analyzed_videos", "analyzed_images",
                                "analyzed_files", "extracted_segments", "extracted_frames"):
                        if key in app.__dict__:
                            self.assertEqual(getattr(app, key), [])
                finally:
                    app.destroy()

    def test_background_results_cannot_cross_cases_or_supersede_new_work(self):
        import webint
        from panel_state import begin_work, apply_result, invalidate
        app = webint.TraceAtlasWEBINTPanel()
        try:
            payload = app.collect_payload()
            token = begin_work(app)
            callback = Mock()
            app.set_widget_value("case_id", "NEW-CASE")
            self.assertFalse(apply_result(app, token, payload, callback))
            callback.assert_not_called()
            payload = app.collect_payload()
            token = begin_work(app)
            newer = begin_work(app)
            self.assertFalse(apply_result(app, token, payload, callback))
            self.assertTrue(apply_result(app, newer, payload, callback))
            callback.assert_called_once()
            invalidate(app)
            self.assertFalse(apply_result(app, newer, payload, callback))
        finally:
            app.destroy()

    def test_media_rejects_non_finite_metadata(self):
        for name in ["audint", "vedmint"]:
            module = importlib.import_module(name)
            for value in ["NaN", "Infinity", "-Infinity", float("nan"), None, "bad"]:
                with self.subTest(panel=name, value=value):
                    self.assertIsNone(module.safe_float(value))
            self.assertEqual(module.safe_float("1.25"), 1.25)

    def test_search_plan_cap_and_reset(self):
        import osint
        app = osint.TraceAtlasOSINTPanel()
        try:
            payload = app.collect_payload()
            payload.update(target="example.org", questions=["public records"] * 1000)
            plan = app._build_search_plan(payload)
            self.assertEqual(len(plan), osint.MAX_PLANNED_QUERIES)
            self.assertTrue(app.plan_truncated)
            self.assertTrue(all(p["authorization_status"] == "NOT_VERIFIED" for p in plan))
            payload["questions"] = ["public records"]
            self.assertLess(len(app._build_search_plan(payload)), osint.MAX_PLANNED_QUERIES)
            self.assertFalse(app.plan_truncated)
        finally:
            app.destroy()


class EvidenceTests(unittest.TestCase):
    def test_real_media_processing_preserves_originals(self):
        import audint
        import vedmint
        import imgmint
        from PIL import Image
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audio = root / "tone.wav"
            with wave.open(str(audio), "wb") as output:
                output.setnchannels(1)
                output.setsampwidth(2)
                output.setframerate(8000)
                output.writeframes(bytes(16000))
            video = root / "clip.mp4"
            subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi",
                            "-i", "color=c=blue:s=32x32:d=1", "-c:v", "mpeg4",
                            str(video)], check=True, timeout=30)
            picture = root / "image.png"
            Image.new("RGB", (16, 16), "blue").save(picture)
            original_hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (audio, video, picture)}
            self.assertEqual(audint.analyze_audio_file(str(audio))["status"], "SUCCEEDED")
            self.assertEqual(vedmint.analyze_video_file(str(video))["status"], "SUCCEEDED")
            image = imgmint.analyze_image_file(str(picture))
            self.assertEqual(image["status"], "SUCCEEDED")
            self.assertEqual((image["width"], image["height"]), (16, 16))
            for source, module, method in [
                (audio, audint, "extract_sample_segments_for_audio"),
                (video, vedmint, "extract_sample_frames_for_video"),
            ]:
                first = getattr(module, method)(str(source), directory)
                second = getattr(module, method)(str(source), directory)
                self.assertTrue(first)
                self.assertTrue(all(item["status"] == "SUCCEEDED" for item in first + second))
                self.assertTrue(set(x["output_path"] for x in first).isdisjoint(
                                x["output_path"] for x in second))
                for item in first + second:
                    path = Path(item["output_path"])
                    self.assertEqual(item["content_hash"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(original_hashes, {p: hashlib.sha256(p.read_bytes()).hexdigest()
                                             for p in original_hashes})

    def test_dms_boundaries_and_geojson_order(self):
        import geomint
        self.assertEqual(geomint.dms_to_decimal(90, 0, 0, "N"), 90)
        self.assertEqual(geomint.dms_to_decimal(180, 0, 0, "W"), -180)
        for args in [(10, 60, 0, "N"), (10, 0, 60, "E"), (90, 0, 1, "N"),
                     (181, 0, 0, "W"), (10, 0, float("nan"), "E")]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                geomint.dms_to_decimal(*args)
        invalid = geomint.parse_coordinates("10°60'00\"N 20°00'00\"E")
        self.assertFalse(invalid["parsed"])
        self.assertTrue(invalid["errors"])
        coordinates = geomint.parse_coordinates("[77.2, 28.6]")["parsed"]
        self.assertEqual(len(coordinates), 1)
        self.assertEqual((coordinates[0]["lat"], coordinates[0]["lon"]), (28.6, 77.2))

    def test_extractions_use_unique_paths_and_cannot_overwrite(self):
        for name, method, probe in [
            ("audint", "extract_sample_segments_for_audio", "ffprobe_audio"),
            ("vedmint", "extract_sample_frames_for_video", "ffprobe_video"),
        ]:
            module = importlib.import_module(name)
            with self.subTest(panel=name), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source.bin"
                source.write_bytes(b"original evidence")
                with patch.object(module.shutil, "which", return_value="ffmpeg"), \
                     patch.object(module, probe, return_value={"status": "UNAVAILABLE"}), \
                     patch.object(module.subprocess, "run", return_value=Mock(returncode=1, stderr="fixture")) as run:
                    first = getattr(module, method)(str(source), directory)[0]
                    second = getattr(module, method)(str(source), directory)[0]
                self.assertNotEqual(first["output_path"], second["output_path"])
                self.assertEqual(source.read_bytes(), b"original evidence")
                for call in run.call_args_list:
                    command = call.args[0]
                    self.assertIn("-n", command)
                    self.assertNotIn("-y", command)
                    self.assertIn("-nostdin", command)
                    self.assertEqual(command[command.index("-protocol_whitelist") + 1], "file,pipe")

    def test_unimplemented_ais_is_not_reported_as_zero_findings(self):
        import maretineint
        result = maretineint.analyze_ais_quality({"ais_obs": [{"timestamp": "bad"}]})
        self.assertEqual(result["status"], "NOT_IMPLEMENTED")
        self.assertIsNone(result["gaps_detected"])
        self.assertIsNone(result["anomalies_detected"])


class WebTests(unittest.TestCase):
    def test_redirects_revalidate_scope_and_close_response(self):
        import webint
        import io
        from email.message import Message
        from urllib.error import HTTPError
        headers = Message()
        headers["Location"] = "https://outside.example/"
        body = io.BytesIO(b"redirect")
        redirect = HTTPError("https://example.org/", 302, "redirect", headers, body)
        opener = Mock()
        opener.open.side_effect = redirect
        with patch.object(webint, "is_safe_hostname", return_value=True), \
             patch.object(webint, "public_opener", return_value=opener):
            result = webint.safe_fetch_url("https://example.org/", ["example.org"])
        self.assertNotEqual(result["status"], "SUCCEEDED")
        self.assertIn("HOST_NOT_IN_ALLOWED_DOMAIN_SCOPE", result["reasons"])
        opener.open.assert_called_once()
        self.assertTrue(body.closed)

    def test_rebinding_between_validation_and_connect_is_rejected(self):
        import webint
        import public_transport
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
        # URL validation may occur more than once; the connection's port-bearing
        # lookup always returns the rebound private answer.
        def resolve(host, port, *args, **kwargs):
            return private if port is not None else public
        with patch.object(public_transport.socket, "getaddrinfo", side_effect=resolve), \
             patch.object(public_transport.socket, "socket") as factory:
            result = webint.safe_fetch_url("http://example.org/")
        self.assertNotEqual(result["status"], "SUCCEEDED")
        factory.assert_not_called()

    def test_ports_and_ipv6(self):
        import webint
        with patch.object(webint, "is_safe_hostname", return_value=True):
            for url in ["https://example.org:bad", "https://example.org:99999",
                        "http://example.org:443", "https://example.org:80",
                        "http://example.org:0"]:
                with self.subTest(url=url):
                    self.assertFalse(webint.validate_public_url(url)[0])
            self.assertEqual(webint.validate_public_url("https://[2606:4700::1111]:443/x#f"),
                             (True, "https://[2606:4700::1111]/x", []))
            self.assertFalse(webint.validate_public_url("https://evil-example.org", ["example.org"])[0])
            self.assertTrue(webint.validate_public_url("https://sub.example.org.", ["example.org"])[0])

    def test_connection_uses_numeric_validated_address(self):
        import public_transport as transport
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        sock = Mock()
        with patch.object(transport.socket, "getaddrinfo", return_value=answer) as dns, \
             patch.object(transport.socket, "socket", return_value=sock):
            self.assertIs(transport.public_socket("example.org", 443, 10), sock)
        dns.assert_called_once()
        sock.connect.assert_called_once_with(("93.184.216.34", 443))

    def test_mixed_dns_answers_block_before_connect(self):
        import public_transport as transport
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "224.0.0.1"]:
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
                       (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))]
            with self.subTest(address=address), \
                 patch.object(transport.socket, "getaddrinfo", return_value=answers), \
                 patch.object(transport.socket, "socket") as factory:
                with self.assertRaises(OSError):
                    transport.public_socket("example.org", 80, 10)
                factory.assert_not_called()

    def test_tls_keeps_original_hostname(self):
        import public_transport as transport
        context, raw = Mock(), Mock()
        connection = transport.PublicHTTPSConnection("example.org", context=context)
        with patch.object(transport, "public_socket", return_value=raw):
            connection.connect()
        context.wrap_socket.assert_called_once_with(raw, server_hostname="example.org")

    def test_opener_has_error_handling_and_no_environment_proxy(self):
        import public_transport as transport
        import webint
        from urllib.request import HTTPDefaultErrorHandler, ProxyHandler
        with patch.dict("os.environ", {"https_proxy": "http://127.0.0.1:8888"}):
            opener = transport.public_opener(webint.NoRedirect())
        self.assertTrue(any(isinstance(h, HTTPDefaultErrorHandler) for h in opener.handlers))
        self.assertFalse(any(isinstance(h, ProxyHandler) and h.proxies for h in opener.handlers))


if __name__ == "__main__":
    unittest.main()
