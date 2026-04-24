from __future__ import annotations

import json
import unittest
from html.parser import HTMLParser
from pathlib import Path


class IdCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key == "id" and value is not None:
                self.ids.add(value)


def collect_ids(html: str) -> set[str]:
    parser = IdCollector()
    parser.feed(html)
    return parser.ids


class DesktopShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]

    def test_desktop_shell_files_exist(self) -> None:
        expected_files = [
            "desktop/app/index.html",
            "desktop/app/styles.css",
            "desktop/app/main.js",
            "desktop/app-icon.svg",
            "desktop/package.json",
            "desktop/package-lock.json",
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
        self.assertIn('data-target="mission-section"', html)
        self.assertIn('data-target="scan-section"', html)
        self.assertIn('data-target="hardening-section"', html)
        self.assertIn('data-target="reports-section"', html)

    def test_desktop_shell_script_wires_interactive_controls(self) -> None:
        script = (self.repo_root / "desktop" / "app" / "main.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("railButtons", script)
        self.assertIn("scrollIntoView", script)
        self.assertIn("refs.scanForm.addEventListener", script)
        self.assertIn("refs.demoBtn.addEventListener", script)
        self.assertIn("refs.refreshBtn.addEventListener", script)
        self.assertIn("refs.firmwareFile.addEventListener", script)

    def test_dashboard_dom_contains_all_javascript_targets(self) -> None:
        html = (self.repo_root / "frontend" / "index.html").read_text(encoding="utf-8")
        ids = collect_ids(html)
        required_ids = {
            "scan-form",
            "firmware-file",
            "min-string-length",
            "max-strings",
            "history-limit",
            "db-path",
            "save-scan",
            "scan-status",
            "history-body",
            "refresh-history",
            "load-history",
            "clear-detail-btn",
            "mission-risk-score",
            "mission-file-name",
            "mission-summary",
            "metric-file",
            "metric-type",
            "metric-entropy",
            "metric-findings",
            "finding-list",
            "strings-list",
            "assistant-chat",
            "assistant-form",
            "assistant-input",
            "clear-assistant-btn",
        }
        self.assertTrue(required_ids.issubset(ids))

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
        self.assertIn("bundle: dmg", workflow)
        self.assertIn("bundle: msi", workflow)
        self.assertIn("bundle: deb", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)

    def test_desktop_build_generates_icons_before_packaging(self) -> None:
        package_json = json.loads(
            (self.repo_root / "desktop" / "package.json").read_text(encoding="utf-8")
        )
        self.assertEqual(package_json["version"], "0.4.0")
        self.assertEqual(package_json["scripts"]["prebuild"], "tauri icon app-icon.svg")
        self.assertEqual(package_json["scripts"]["build"], "tauri build")


if __name__ == "__main__":
    unittest.main()
