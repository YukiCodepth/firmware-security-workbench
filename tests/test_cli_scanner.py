from __future__ import annotations

import json
import struct
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
from cli.storage import get_scan_record, list_scans, save_scan_result


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
            self.assertGreater(result["analysis"]["secret_exposure_count"], 0)
            self.assertGreater(result["analysis"]["endpoint_count"], 0)
            self.assertIn("security_posture", result["analysis"])

            exposures = result["analysis"]["secret_exposures"]
            redacted_text = " ".join(item["evidence_redacted"] for item in exposures)
            self.assertNotIn("demo1234", redacted_text)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_secret_exposure_assignment_redaction(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
            temp_file.write(b"api_key=ABCDEF1234567890\naccess_token=tokenvalue123\n")
            temp_path = Path(temp_file.name)

        try:
            result = scan_firmware(temp_path)
            exposures = result["analysis"]["secret_exposures"]
            self.assertGreaterEqual(len(exposures), 2)
            indicators = {item["indicator"] for item in exposures}
            self.assertTrue({"api_key", "access_token"}.issubset(indicators))
            for item in exposures:
                self.assertIn("*", item["evidence_redacted"])
        finally:
            temp_path.unlink(missing_ok=True)

    def test_scan_intel_hex_metadata(self) -> None:
        hex_payload = (
            b":10010000214601360121470136007EFE09D2190140\n"
            b":00000001FF\n"
        )
        with tempfile.NamedTemporaryFile(suffix=".hex", delete=False) as temp_file:
            temp_file.write(hex_payload)
            temp_path = Path(temp_file.name)

        try:
            result = scan_firmware(temp_path)
            self.assertEqual(result["file"]["type_guess"], "Intel HEX")
            format_details = result["file"]["format_details"]
            self.assertEqual(format_details["parser_status"], "ok")
            self.assertEqual(format_details["valid_records"], 2)
            self.assertEqual(format_details["data_records"], 1)
            self.assertEqual(format_details["total_data_bytes"], 16)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_scan_uf2_metadata(self) -> None:
        header = struct.pack(
            "<IIIIIIII",
            0x0A324655,
            0x9E5D5157,
            0x00002000,
            0x10000000,
            16,
            0,
            1,
            0xE48BFF56,
        )
        payload = b"FWB_UF2_DEMO_0001"
        block = header + payload + bytes(476 - len(payload)) + struct.pack("<I", 0x0AB16F30)

        with tempfile.NamedTemporaryFile(suffix=".uf2", delete=False) as temp_file:
            temp_file.write(block)
            temp_path = Path(temp_file.name)

        try:
            result = scan_firmware(temp_path)
            self.assertEqual(result["file"]["type_guess"], "UF2")
            self.assertEqual(result["file"]["architecture_hint"], "RP2040")
            format_details = result["file"]["format_details"]
            self.assertEqual(format_details["valid_blocks"], 1)
            self.assertEqual(format_details["invalid_blocks"], 0)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_scan_elf_metadata(self) -> None:
        ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
        elf_header = struct.pack(
            "<HHIQQQIHHHHHH",
            2,  # e_type
            0x3E,  # e_machine (x86-64)
            1,  # e_version
            0x400000,  # e_entry
            0,  # e_phoff
            0,  # e_shoff
            0,  # e_flags
            64,  # e_ehsize
            0,  # e_phentsize
            0,  # e_phnum
            0,  # e_shentsize
            0,  # e_shnum
            0,  # e_shstrndx
        )
        elf_data = ident + elf_header

        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as temp_file:
            temp_file.write(elf_data)
            temp_path = Path(temp_file.name)

        try:
            result = scan_firmware(temp_path)
            self.assertEqual(result["file"]["type_guess"], "ELF")
            self.assertEqual(result["file"]["architecture_hint"], "AMD x86-64")
            format_details = result["file"]["format_details"]
            self.assertEqual(format_details["class"], "ELF64")
            self.assertEqual(format_details["machine"], "AMD x86-64")
            self.assertEqual(format_details["entry_point_hex"], "0x400000")
        finally:
            temp_path.unlink(missing_ok=True)


class ScannerCliTests(unittest.TestCase):
    def test_cli_scan_json_output(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        firmware_path = repo_root / "samples" / "demo-firmware.bin"

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "cli",
                "scan",
                str(firmware_path),
                "--json",
                "--no-save",
            ],
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
        self.assertIn("format_details", payload["file"])
        self.assertIn("storage", payload)

    def test_cli_history_list_and_show(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        firmware_path = repo_root / "samples" / "demo-firmware.bin"

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "fwb_history.sqlite3"

            scan_cmd = [
                sys.executable,
                "-m",
                "cli",
                "scan",
                str(firmware_path),
                "--db",
                str(db_path),
                "--json",
            ]
            scan_run = subprocess.run(
                scan_cmd,
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(scan_run.returncode, 0, msg=scan_run.stderr)
            scan_payload = json.loads(scan_run.stdout)
            scan_id = scan_payload["storage"]["scan_id"]

            list_cmd = [
                sys.executable,
                "-m",
                "cli",
                "history",
                "list",
                "--db",
                str(db_path),
                "--json",
            ]
            list_run = subprocess.run(
                list_cmd,
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(list_run.returncode, 0, msg=list_run.stderr)
            history_rows = json.loads(list_run.stdout)
            self.assertGreaterEqual(len(history_rows), 1)
            self.assertEqual(history_rows[0]["id"], scan_id)

            show_cmd = [
                sys.executable,
                "-m",
                "cli",
                "history",
                "show",
                str(scan_id),
                "--db",
                str(db_path),
                "--json",
            ]
            show_run = subprocess.run(
                show_cmd,
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(show_run.returncode, 0, msg=show_run.stderr)
            show_payload = json.loads(show_run.stdout)
            self.assertEqual(show_payload["scan_id"], scan_id)
            self.assertIn("result", show_payload)
            self.assertIn("file", show_payload["result"])


class StorageLayerTests(unittest.TestCase):
    def test_save_list_and_get_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "local_scans.sqlite3"
            sample = scan_firmware(Path(__file__).resolve().parents[1] / "samples" / "demo-firmware.bin")

            scan_id = save_scan_result(sample, db_path=db_path)
            self.assertGreater(scan_id, 0)

            rows = list_scans(db_path=db_path, limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["id"], scan_id)
            self.assertEqual(rows[0]["file_name"], "demo-firmware.bin")

            record = get_scan_record(scan_id=scan_id, db_path=db_path)
            self.assertEqual(record["scan_id"], scan_id)
            self.assertIn("result", record)
            self.assertEqual(record["result"]["file"]["name"], "demo-firmware.bin")


if __name__ == "__main__":
    unittest.main()
