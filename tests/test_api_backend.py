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

        list_response = self.client.get(
            "/api/v1/scans",
            params={"db_path": str(self.db_path), "limit": 10},
        )
        self.assertEqual(list_response.status_code, 200)
        listed = list_response.json()
        self.assertEqual(listed["count"], 0)


if __name__ == "__main__":
    unittest.main()
