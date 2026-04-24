from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import app


class ApiBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "api_scans.sqlite3"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["service"], "fwb-api")

    def test_root_endpoint(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["docs_url"], "/docs")
        self.assertEqual(payload["api_base"], "/api/v1")

    def test_favicon_no_content(self) -> None:
        response = self.client.get("/favicon.ico")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.content, b"")

    def test_desktop_preview_origin_is_allowed(self) -> None:
        response = self.client.options(
            "/health",
            headers={
                "Origin": "http://127.0.0.1:4173",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "http://127.0.0.1:4173",
        )

    def test_dashboard_entrypoint(self) -> None:
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("Firmware Security Workbench", response.text)
        self.assertIn("Dashboard Assistant", response.text)
        self.assertIn("Risk DNA", response.text)
        self.assertIn("YARA matches", response.text)
        self.assertIn("SBOM", response.text)
        self.assertIn("CVE candidates", response.text)
        self.assertIn("Hardening plan", response.text)

    def test_dashboard_logo_asset(self) -> None:
        response = self.client.get("/dashboard/static/logo-fwb.svg")
        self.assertEqual(response.status_code, 200)
        self.assertIn("image/svg+xml", response.headers.get("content-type", ""))
        self.assertIn("<svg", response.text)

    def test_scan_create_list_and_show(self) -> None:
        firmware_bytes = (
            b"FWB_API_TEST\nwifi_password=test123\nmqtt://broker.local\nDEBUG: ready\n"
        )
        files = {"file": ("api-demo.bin", firmware_bytes, "application/octet-stream")}
        data = {
            "min_string_length": "4",
            "max_strings": "2000",
            "save": "true",
            "db_path": str(self.db_path),
        }

        create_response = self.client.post("/api/v1/scans", files=files, data=data)
        self.assertEqual(create_response.status_code, 200)
        created = create_response.json()
        self.assertEqual(created["file"]["name"], "api-demo.bin")
        self.assertTrue(created["storage"]["saved"])
        self.assertGreater(created["analysis"]["secret_exposure_count"], 0)
        self.assertGreater(created["analysis"]["endpoint_count"], 0)
        self.assertIn("security_posture", created["analysis"])
        self.assertIn("rule_engine", created["analysis"])
        self.assertIn("rule_match_count", created["analysis"])
        self.assertIn("component_candidate_count", created["analysis"])
        self.assertIn("cve_candidate_count", created["analysis"])
        self.assertIn("hardening_simulation", created["analysis"])
        self.assertIn("hardening_actions_count", created["analysis"])
        self.assertIn("sbom", created)
        self.assertEqual(created["sbom"]["metadata"]["component"]["name"], "api-demo.bin")
        self.assertEqual(created["sbom"]["components"][0]["name"], "api-demo.bin")
        scan_id = created["storage"]["scan_id"]
        self.assertIsInstance(scan_id, int)

        list_response = self.client.get(
            "/api/v1/scans",
            params={"db_path": str(self.db_path), "limit": 10},
        )
        self.assertEqual(list_response.status_code, 200)
        listed = list_response.json()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["scans"][0]["id"], scan_id)
        self.assertEqual(listed["scans"][0]["file_name"], "api-demo.bin")

        show_response = self.client.get(
            f"/api/v1/scans/{scan_id}",
            params={"db_path": str(self.db_path)},
        )
        self.assertEqual(show_response.status_code, 200)
        shown = show_response.json()
        self.assertEqual(shown["scan_id"], scan_id)
        self.assertEqual(shown["result"]["file"]["name"], "api-demo.bin")

    def test_scan_without_saving(self) -> None:
        firmware_bytes = b"FWB_API_TEST\npassword=temp\n"
        files = {"file": ("no-save.bin", firmware_bytes, "application/octet-stream")}
        data = {
            "save": "false",
            "db_path": str(self.db_path),
        }

        create_response = self.client.post("/api/v1/scans", files=files, data=data)
        self.assertEqual(create_response.status_code, 200)
        created = create_response.json()
        self.assertFalse(created["storage"]["saved"])
        self.assertIsNone(created["storage"]["scan_id"])
        self.assertGreater(created["analysis"]["secret_exposure_count"], 0)
        self.assertIn("rule_match_count", created["analysis"])
        self.assertIn("cve_candidate_count", created["analysis"])
        self.assertIn("hardening_simulation", created["analysis"])
        self.assertIn("sbom", created)

        list_response = self.client.get(
            "/api/v1/scans",
            params={"db_path": str(self.db_path), "limit": 10},
        )
        self.assertEqual(list_response.status_code, 200)
        listed = list_response.json()
        self.assertEqual(listed["count"], 0)

    def test_diff_endpoint(self) -> None:
        old_bytes = b"FW_V1\npassword=demo123\nmqtt://broker.local\n"
        new_bytes = b"FW_V2\npassword=demo123\nmqtt://broker.local\nadmin=true\n"
        files = {
            "old_file": ("fw-old.bin", old_bytes, "application/octet-stream"),
            "new_file": ("fw-new.bin", new_bytes, "application/octet-stream"),
        }
        data = {"min_string_length": "4", "max_strings": "2000"}

        response = self.client.post("/api/v1/diff", files=files, data=data)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("old_scan", payload)
        self.assertIn("new_scan", payload)
        self.assertIn("diff", payload)
        self.assertEqual(payload["old_scan"]["sbom"]["components"][0]["name"], "fw-old.bin")
        self.assertEqual(payload["new_scan"]["sbom"]["components"][0]["name"], "fw-new.bin")
        self.assertTrue(payload["diff"]["summary"]["changed"])
        self.assertIn("risk_shift", payload["diff"])
        self.assertIn("hardening_shift", payload["diff"])


if __name__ == "__main__":
    unittest.main()
