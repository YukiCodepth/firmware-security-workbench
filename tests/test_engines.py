from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cli.cve_engine import compare_versions, match_cve_candidates
from cli.diff_engine import scan_and_diff_firmware
from cli.report_exporter import render_diff_markdown, render_scan_markdown
from cli.scanner import scan_firmware


class CveEngineTests(unittest.TestCase):
    def test_compare_versions(self) -> None:
        self.assertEqual(compare_versions("1.2.3", "1.2.3"), 0)
        self.assertEqual(compare_versions("1.2.4", "1.2.3"), 1)
        self.assertEqual(compare_versions("1.2.2", "1.2.3"), -1)
        self.assertEqual(compare_versions("1.2.3a", "1.2.3"), 1)

    def test_match_cve_candidates(self) -> None:
        components = [
            {"name": "OpenSSL", "version": "1.1.1k", "confidence": "high"},
            {"name": "zlib", "version": "1.2.11", "confidence": "medium"},
        ]
        matches = match_cve_candidates(components)
        ids = {entry["cve_id"] for entry in matches}
        self.assertIn("CVE-2023-0286", ids)
        self.assertIn("CVE-2018-25032", ids)


class DiffAndReportTests(unittest.TestCase):
    def test_scan_and_diff(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as old_file:
            old_file.write(b"FW_A\npassword=abc\n")
            old_path = Path(old_file.name)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as new_file:
            new_file.write(b"FW_B\npassword=abc\nadmin=true\n")
            new_path = Path(new_file.name)

        try:
            payload = scan_and_diff_firmware(old_path, new_path, enable_rules=False)
            self.assertIn("diff", payload)
            self.assertTrue(payload["diff"]["summary"]["changed"])
            self.assertIn("risk_shift", payload["diff"])
        finally:
            old_path.unlink(missing_ok=True)
            new_path.unlink(missing_ok=True)

    def test_render_reports(self) -> None:
        scan_payload = {
            "file": {"name": "demo.bin", "type_guess": "Raw Binary", "sha256": "abc"},
            "analysis": {
                "entropy": 5.0,
                "suspicious_count": 1,
                "secret_exposure_count": 1,
                "rule_match_count": 1,
                "component_candidate_count": 1,
                "cve_candidate_count": 1,
                "suspicious_findings": [{"severity": "high", "confidence": "high", "offset_hex": "0x1", "string": "password=abc"}],
                "cve_candidates": [{"confidence": "high", "cve_id": "CVE-2023-0001", "component_name": "OpenSSL", "component_version": "1.1.1k", "severity": "high", "cvss_base_score": 7.4}],
            },
        }
        text = render_scan_markdown(scan_payload)
        self.assertIn("Firmware Security Report", text)

        diff_payload = {
            "diff": {
                "summary": {"old_file": "a.bin", "new_file": "b.bin", "changed": True},
                "delta": {"suspicious": 1, "secrets": 0, "endpoints": 0, "rules": 0, "components": 0, "cves": 0},
                "risk_shift": {"trend": "risk_increased", "score_delta": 10, "old_band": "medium", "new_band": "high"},
            }
        }
        diff_text = render_diff_markdown(diff_payload)
        self.assertIn("Firmware Diff Report", diff_text)

    def test_sample_corpus_scan(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        sample = repo_root / "samples" / "corpus" / "esp32-lab-vuln.bin"
        result = scan_firmware(sample)
        self.assertGreater(result["analysis"]["suspicious_count"], 0)
        self.assertGreater(result["analysis"]["secret_exposure_count"], 0)


if __name__ == "__main__":
    unittest.main()
