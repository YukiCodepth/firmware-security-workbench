from __future__ import annotations

import hashlib
import math
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

ScannerResult = dict[str, object]


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


KEYWORD_RULES: list[tuple[str, str, str]] = [
    ("-----begin", "critical", "high"),
    ("private key", "critical", "high"),
    ("api_key", "high", "high"),
    ("access_token", "high", "high"),
    ("password", "high", "high"),
    ("passwd", "high", "high"),
    ("secret", "high", "medium"),
    ("token", "high", "medium"),
    ("mqtt://", "medium", "medium"),
    ("http://", "medium", "medium"),
    ("admin", "medium", "low"),
    ("root", "medium", "low"),
    ("ota", "medium", "medium"),
    ("update", "low", "low"),
    ("debug", "low", "low"),
]


class ScanError(Exception):
    """Raised when a scan cannot be completed."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for value in data:
        byte_counts[value] += 1

    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _is_probably_intel_hex(path: Path, data: bytes) -> bool:
    if path.suffix.lower() == ".hex":
        return True

    try:
        text = data[:2048].decode("ascii", errors="ignore")
    except UnicodeDecodeError:
        return False

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    sample = lines[:5]
    return all(line.startswith(":") for line in sample)


def _is_probably_uf2(data: bytes) -> bool:
    if len(data) < 512:
        return False
    try:
        first_magic, second_magic = struct.unpack_from("<II", data, 0)
    except struct.error:
        return False

    return first_magic == 0x0A324655 and second_magic == 0x9E5D5157


def guess_file_type(path: Path, data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if _is_probably_intel_hex(path, data):
        return "Intel HEX"
    if _is_probably_uf2(data):
        return "UF2"
    if path.suffix.lower() == ".bin":
        return "Raw Binary"
    if path.suffix:
        return f"Binary ({path.suffix.lower()})"
    return "Unknown Binary"


def extract_printable_strings(
    data: bytes, min_length: int = 4, max_strings: int | None = 2000
) -> tuple[list[dict[str, object]], bool]:
    if min_length < 2:
        raise ValueError("min_length must be >= 2")

    pattern = re.compile(rb"[ -~]{" + str(min_length).encode("ascii") + rb",}")
    strings: list[dict[str, object]] = []
    truncated = False

    for match in pattern.finditer(data):
        strings.append(
            {
                "value": match.group(0).decode("ascii", errors="ignore"),
                "offset": match.start(),
            }
        )
        if max_strings is not None and len(strings) >= max_strings:
            truncated = True
            break

    return strings, truncated


def _higher_ranked(left: str, right: str, rank_table: dict[str, int]) -> str:
    if rank_table[left] >= rank_table[right]:
        return left
    return right


def detect_suspicious_strings(
    extracted_strings: list[dict[str, object]],
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []

    for item in extracted_strings:
        raw_value = item["value"]
        if not isinstance(raw_value, str):
            continue

        lower_value = raw_value.lower()
        matched_keywords: list[str] = []
        severity = "info"
        confidence = "low"

        for keyword, keyword_severity, keyword_confidence in KEYWORD_RULES:
            if keyword in lower_value:
                matched_keywords.append(keyword)
                severity = _higher_ranked(severity, keyword_severity, SEVERITY_RANK)
                confidence = _higher_ranked(
                    confidence, keyword_confidence, CONFIDENCE_RANK
                )

        if not matched_keywords:
            continue

        findings.append(
            {
                "string": raw_value[:180],
                "offset": item["offset"],
                "offset_hex": hex(int(item["offset"])),
                "keywords": sorted(set(matched_keywords)),
                "severity": severity,
                "confidence": confidence,
            }
        )

    findings.sort(
        key=lambda item: (
            SEVERITY_RANK[item["severity"]],
            CONFIDENCE_RANK[item["confidence"]],
        ),
        reverse=True,
    )
    return findings


def scan_firmware(
    file_path: str | Path,
    *,
    min_string_length: int = 4,
    max_strings: int = 2000,
) -> ScannerResult:
    path = Path(file_path)
    if not path.exists():
        raise ScanError(f"File not found: {path}")
    if not path.is_file():
        raise ScanError(f"Path is not a file: {path}")

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ScanError(f"Unable to read file {path}: {exc}") from exc

    strings, strings_truncated = extract_printable_strings(
        data, min_length=min_string_length, max_strings=max_strings
    )
    suspicious_findings = detect_suspicious_strings(strings)

    return {
        "scanner": {
            "name": "Firmware Security Workbench",
            "version": "0.1.0-dev",
            "phase": "02-cli-scanner-mvp",
            "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "file": {
            "path": str(path.resolve()),
            "name": path.name,
            "extension": path.suffix.lower() or None,
            "size_bytes": len(data),
            "sha256": sha256_hex(data),
            "type_guess": guess_file_type(path, data),
        },
        "analysis": {
            "entropy": shannon_entropy(data),
            "strings_count": len(strings),
            "strings_truncated": strings_truncated,
            "strings_preview": [entry["value"] for entry in strings[:25]],
            "suspicious_count": len(suspicious_findings),
            "suspicious_findings": suspicious_findings,
        },
    }
