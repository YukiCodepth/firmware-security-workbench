from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cli.scanner import (
    extract_printable_strings,
    scan_firmware,
    sha256_hex,
    shannon_entropy,
)


class ScannerCoreTests(unittest.TestCase):
    def test_sha256_matches_known_vector(self) -> None:
        self.assertEqual(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_entropy_zero_for_single_repeated_byte(self) -> None:
        self.assertEqual(shannon_entropy(b"\x00" * 128), 0.0)

    def test_extract_printable_strings_with_offsets(self) -> None:
        strings, truncated = extract_printable_strings(
            b"\x00abc\x00hello_world\x00", min_length=5, max_strings=10
        )
        self.assertFalse(truncated)
        self.assertEqual(len(strings), 1)
        self.assertEqual(strings[0]["value"], "hello_world")
        self.assertEqual(strings[0]["offset"], 5)

    def test_scan_firmware_finds_suspicious_patterns(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
            temp_file.write(
                b"FW\npassword=demo1234\nmqtt://broker.local\nDEBUG: trace\n"
            )
            temp_path = Path(temp_file.name)

        try:
            result = scan_firmware(temp_path)
            self.assertEqual(result["file"]["type_guess"], "Raw Binary")
            self.assertGreater(result["analysis"]["strings_count"], 0)
            self.assertGreater(result["analysis"]["suspicious_count"], 0)
        finally:
            temp_path.unlink(missing_ok=True)


class ScannerCliTests(unittest.TestCase):
    def test_cli_scan_json_output(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        firmware_path = repo_root / "samples" / "demo-firmware.bin"

        completed = subprocess.run(
            [sys.executable, "-m", "cli", "scan", str(firmware_path), "--json"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["file"]["name"], "demo-firmware.bin")
        self.assertIn("sha256", payload["file"])
        self.assertIn("analysis", payload)
        self.assertIn("suspicious_findings", payload["analysis"])


if __name__ == "__main__":
    unittest.main()
