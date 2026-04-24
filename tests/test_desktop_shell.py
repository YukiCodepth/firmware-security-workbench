from __future__ import annotations

import json
import unittest
from pathlib import Path


class DesktopShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]

    def test_desktop_shell_files_exist(self) -> None:
        expected_files = [
            "desktop/app/index.html",
            "desktop/app/styles.css",
            "desktop/app/main.js",
            "desktop/package.json",
            "desktop/src-tauri/tauri.conf.json",
            "desktop/src-tauri/capabilities/default.json",
            "desktop/src-tauri/Cargo.toml",
            "desktop/src-tauri/src/main.rs",
            "docs/phase-18-desktop-app-shell.md",
            "docs/phase-19-nextgen-ui-packaging.md",
            ".github/workflows/desktop-packages.yml",
        ]
        for relative_path in expected_files:
            with self.subTest(path=relative_path):
                self.assertTrue((self.repo_root / relative_path).exists())

    def test_desktop_shell_contains_core_views(self) -> None:
        html = (self.repo_root / "desktop" / "app" / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("Mission Control", html)
        self.assertIn("Scan Studio", html)
        self.assertIn("Hardening Studio", html)
        self.assertIn("Release Timeline", html)

    def test_tauri_config_points_to_desktop_app(self) -> None:
        config = json.loads(
            (self.repo_root / "desktop" / "src-tauri" / "tauri.conf.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(config["productName"], "Firmware Security Workbench")
        self.assertEqual(config["build"]["frontendDist"], "../app")
        self.assertEqual(config["build"]["devUrl"], "http://127.0.0.1:4173")

    def test_desktop_package_workflow_targets_three_operating_systems(self) -> None:
        workflow = (
            self.repo_root / ".github" / "workflows" / "desktop-packages.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("macos-latest", workflow)
        self.assertIn("windows-latest", workflow)
        self.assertIn("ubuntu-latest", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)


if __name__ == "__main__":
    unittest.main()
