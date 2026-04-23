from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ScannerResult = dict[str, object]


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

ELF_MACHINE_MAP = {
    0x03: "Intel 80386",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3E: "AMD x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

ELF_OSABI_MAP = {
    0: "System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "Linux",
    6: "Solaris",
    9: "FreeBSD",
}

UF2_FAMILY_MAP = {
    0xE48BFF56: "RP2040",
}

UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30


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


def _hex(value: int | None) -> str | None:
    if value is None:
        return None
    return hex(value)


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

    text = data[:4096].decode("ascii", errors="ignore")
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

    return first_magic == UF2_MAGIC_START0 and second_magic == UF2_MAGIC_START1


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


def _parse_elf_sections(
    data: bytes,
    *,
    elf_class: int,
    endian_prefix: str,
    section_offset: int,
    section_entry_size: int,
    section_count: int,
    shstr_index: int,
) -> dict[str, object]:
    if section_count <= 0 or section_entry_size <= 0:
        return {
            "section_names_preview": [],
            "section_names_truncated": False,
            "symbol_tables": {},
            "parser_warning": "No section header table.",
        }

    expected_size = section_offset + (section_count * section_entry_size)
    if expected_size > len(data):
        return {
            "section_names_preview": [],
            "section_names_truncated": False,
            "symbol_tables": {},
            "parser_warning": "Section table extends beyond file size.",
        }

    if elf_class == 2:
        section_fmt = endian_prefix + "IIQQQQIIQQ"
        name_idx = 0
        type_idx = 1
        offset_idx = 4
        size_idx = 5
        entsize_idx = 9
    else:
        section_fmt = endian_prefix + "IIIIIIIIII"
        name_idx = 0
        type_idx = 1
        offset_idx = 4
        size_idx = 5
        entsize_idx = 9

    expected_entry_size = struct.calcsize(section_fmt)
    if section_entry_size < expected_entry_size:
        return {
            "section_names_preview": [],
            "section_names_truncated": False,
            "symbol_tables": {},
            "parser_warning": "Unexpected section header entry size.",
        }

    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        section = struct.unpack_from(section_fmt, data, offset)
        sections.append(
            (
                section[name_idx],
                section[type_idx],
                section[offset_idx],
                section[size_idx],
            )
        )

    if shstr_index < 0 or shstr_index >= section_count:
        return {
            "section_names_preview": [],
            "section_names_truncated": False,
            "symbol_tables": {},
            "parser_warning": "Invalid section string table index.",
        }

    shstr_header = sections[shstr_index]
    shstr_offset = shstr_header[2]
    shstr_size = shstr_header[3]
    if shstr_offset + shstr_size > len(data):
        return {
            "section_names_preview": [],
            "section_names_truncated": False,
            "symbol_tables": {},
            "parser_warning": "Section string table extends beyond file size.",
        }

    shstr_table = data[shstr_offset : shstr_offset + shstr_size]

    def resolve_name(name_offset: int) -> str:
        if name_offset >= len(shstr_table):
            return ""
        end = shstr_table.find(b"\x00", name_offset)
        if end == -1:
            end = len(shstr_table)
        return shstr_table[name_offset:end].decode("utf-8", errors="ignore")

    section_names = []
    symbol_tables: dict[str, int] = {}
    for idx, section in enumerate(sections):
        name = resolve_name(section[0])
        if name:
            section_names.append(name)
        section_type = section[1]
        section_size = section[3]
        if section_type in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
            # Use standard ELF symbol entry sizes for estimates.
            if section_type == 2:
                entry_size = 24 if elf_class == 2 else 16
                table_name = ".symtab"
            else:
                entry_size = 24 if elf_class == 2 else 16
                table_name = ".dynsym"
            symbol_tables[table_name] = section_size // entry_size if entry_size else 0
        elif name in (".symtab", ".dynsym"):
            entry_size = 24 if elf_class == 2 else 16
            symbol_tables[name] = section_size // entry_size if entry_size else 0

        if idx > 10000:
            break

    preview_limit = 20
    return {
        "section_names_preview": section_names[:preview_limit],
        "section_names_truncated": len(section_names) > preview_limit,
        "symbol_tables": symbol_tables,
    }


def _analyze_elf(data: bytes) -> dict[str, object]:
    details: dict[str, object] = {
        "format": "ELF",
        "parser_status": "partial",
    }

    if len(data) < 16:
        details["parser_status"] = "invalid"
        details["parser_warning"] = "File too small for ELF header."
        return details

    ident = data[:16]
    elf_class = ident[4]
    endian = ident[5]
    os_abi = ident[7]

    if elf_class not in (1, 2):
        details["parser_status"] = "invalid"
        details["parser_warning"] = "Unsupported ELF class."
        return details
    if endian not in (1, 2):
        details["parser_status"] = "invalid"
        details["parser_warning"] = "Unsupported ELF endianness."
        return details

    endian_prefix = "<" if endian == 1 else ">"
    header_fmt = (
        endian_prefix + ("HHIQQQIHHHHHH" if elf_class == 2 else "HHIIIIIHHHHHH")
    )
    header_size = struct.calcsize(header_fmt)
    full_header_size = 16 + header_size
    if len(data) < full_header_size:
        details["parser_status"] = "invalid"
        details["parser_warning"] = "ELF header is truncated."
        return details

    header = struct.unpack_from(header_fmt, data, 16)
    machine = header[1]
    entry = header[3]
    phoff = header[4]
    shoff = header[5]
    phnum = header[9]
    shentsize = header[10]
    shnum = header[11]
    shstrndx = header[12]

    details.update(
        {
            "parser_status": "ok",
            "class": "ELF64" if elf_class == 2 else "ELF32",
            "endianness": "little" if endian == 1 else "big",
            "os_abi": ELF_OSABI_MAP.get(os_abi, f"Unknown ({os_abi})"),
            "machine_code": machine,
            "machine": ELF_MACHINE_MAP.get(machine, f"Unknown ({machine})"),
            "entry_point_hex": _hex(entry),
            "program_header_offset_hex": _hex(phoff),
            "program_headers_count": phnum,
            "section_header_offset_hex": _hex(shoff),
            "section_header_entry_size": shentsize,
            "section_headers_count": shnum,
            "section_string_table_index": shstrndx,
        }
    )

    section_info = _parse_elf_sections(
        data,
        elf_class=elf_class,
        endian_prefix=endian_prefix,
        section_offset=shoff,
        section_entry_size=shentsize,
        section_count=shnum,
        shstr_index=shstrndx,
    )
    details.update(section_info)
    if "parser_warning" in section_info and details["parser_status"] == "ok":
        details["parser_status"] = "partial"
    return details


def _analyze_intel_hex(data: bytes) -> dict[str, object]:
    lines = [line.strip() for line in data.decode("ascii", errors="ignore").splitlines()]
    lines = [line for line in lines if line]

    details: dict[str, object] = {
        "format": "Intel HEX",
        "parser_status": "ok",
        "records_total": len(lines),
    }
    if not lines:
        details["parser_status"] = "invalid"
        details["parser_warning"] = "No Intel HEX records found."
        return details

    record_types = Counter()
    valid_records = 0
    invalid_records = 0
    checksum_failures = 0
    data_records = 0
    total_data_bytes = 0
    eof_seen = False

    linear_base: int | None = None
    segment_base: int | None = None
    min_address: int | None = None
    max_address: int | None = None

    for line in lines:
        if not line.startswith(":"):
            invalid_records += 1
            continue

        hex_part = line[1:]
        if len(hex_part) % 2 != 0:
            invalid_records += 1
            continue

        try:
            record = bytes.fromhex(hex_part)
        except ValueError:
            invalid_records += 1
            continue

        if len(record) < 5:
            invalid_records += 1
            continue

        byte_count = record[0]
        expected_size = byte_count + 5
        if len(record) != expected_size:
            invalid_records += 1
            continue

        checksum_ok = (sum(record) & 0xFF) == 0
        if not checksum_ok:
            checksum_failures += 1

        valid_records += 1
        address = (record[1] << 8) | record[2]
        record_type = record[3]
        payload = record[4 : 4 + byte_count]
        record_types[f"{record_type:02X}"] += 1

        if record_type == 0x04 and byte_count == 2:
            linear_base = ((payload[0] << 8) | payload[1]) << 16
            segment_base = None
        elif record_type == 0x02 and byte_count == 2:
            segment_base = ((payload[0] << 8) | payload[1]) << 4
            linear_base = None
        elif record_type == 0x00:
            base = linear_base if linear_base is not None else (segment_base or 0)
            start_address = base + address
            end_address = start_address + max(byte_count - 1, 0)
            total_data_bytes += byte_count
            data_records += 1
            min_address = (
                start_address
                if min_address is None
                else min(min_address, start_address)
            )
            max_address = end_address if max_address is None else max(max_address, end_address)
        elif record_type == 0x01:
            eof_seen = True

    if invalid_records > 0:
        details["parser_status"] = "partial"
        details["parser_warning"] = "Some lines were not valid Intel HEX records."
    if valid_records == 0:
        details["parser_status"] = "invalid"
        details["parser_warning"] = "No valid Intel HEX records found."

    details.update(
        {
            "valid_records": valid_records,
            "invalid_records": invalid_records,
            "checksum_failures": checksum_failures,
            "record_types": dict(record_types),
            "data_records": data_records,
            "total_data_bytes": total_data_bytes,
            "eof_record_seen": eof_seen,
            "address_range_hex": {
                "start": _hex(min_address),
                "end": _hex(max_address),
            },
        }
    )
    return details


def _analyze_uf2(data: bytes) -> dict[str, object]:
    details: dict[str, object] = {
        "format": "UF2",
        "parser_status": "ok",
        "total_bytes": len(data),
    }

    total_blocks = len(data) // 512
    trailing_bytes = len(data) % 512
    if total_blocks == 0:
        details["parser_status"] = "invalid"
        details["parser_warning"] = "UF2 data is smaller than one block."
        return details

    valid_blocks = 0
    invalid_blocks = 0
    payload_sizes: list[int] = []
    num_blocks_hints = set()
    family_ids = set()
    min_target: int | None = None
    max_target: int | None = None

    for index in range(total_blocks):
        block = data[index * 512 : (index + 1) * 512]
        try:
            (
                magic0,
                magic1,
                _flags,
                target_addr,
                payload_size,
                _block_no,
                num_blocks,
                family_id,
            ) = struct.unpack_from("<IIIIIIII", block, 0)
            (magic_end,) = struct.unpack_from("<I", block, 508)
        except struct.error:
            invalid_blocks += 1
            continue

        if (
            magic0 != UF2_MAGIC_START0
            or magic1 != UF2_MAGIC_START1
            or magic_end != UF2_MAGIC_END
        ):
            invalid_blocks += 1
            continue

        valid_blocks += 1
        clamped_payload = min(payload_size, 476)
        payload_sizes.append(clamped_payload)
        num_blocks_hints.add(num_blocks)

        if family_id != 0:
            family_ids.add(family_id)

        block_end = target_addr + max(clamped_payload - 1, 0)
        min_target = target_addr if min_target is None else min(min_target, target_addr)
        max_target = block_end if max_target is None else max(max_target, block_end)

    if invalid_blocks > 0 or trailing_bytes > 0:
        details["parser_status"] = "partial"
    if valid_blocks == 0:
        details["parser_status"] = "invalid"
        details["parser_warning"] = "No valid UF2 blocks found."

    details.update(
        {
            "total_blocks": total_blocks,
            "valid_blocks": valid_blocks,
            "invalid_blocks": invalid_blocks,
            "trailing_bytes": trailing_bytes,
            "payload_size_range": {
                "min": min(payload_sizes) if payload_sizes else None,
                "max": max(payload_sizes) if payload_sizes else None,
            },
            "num_blocks_hints": sorted(num_blocks_hints),
            "target_address_range_hex": {
                "start": _hex(min_target),
                "end": _hex(max_target),
            },
            "family_ids_hex": sorted(hex(family_id) for family_id in family_ids),
            "family_names": sorted(
                UF2_FAMILY_MAP[family_id]
                for family_id in family_ids
                if family_id in UF2_FAMILY_MAP
            ),
        }
    )
    return details


def analyze_format(path: Path, data: bytes) -> tuple[str, dict[str, object], str | None]:
    file_type = guess_file_type(path, data)
    if file_type == "ELF":
        details = _analyze_elf(data)
        architecture_hint = details.get("machine")
        return file_type, details, architecture_hint if isinstance(architecture_hint, str) else None
    if file_type == "Intel HEX":
        return file_type, _analyze_intel_hex(data), None
    if file_type == "UF2":
        details = _analyze_uf2(data)
        family_names = details.get("family_names")
        if isinstance(family_names, list) and family_names:
            return file_type, details, ", ".join(family_names)
        return file_type, details, None

    return (
        file_type,
        {
            "format": file_type,
            "parser_status": "not_applicable",
            "header_hex_preview": data[:16].hex(),
        },
        None,
    )


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
    type_guess, format_details, architecture_hint = analyze_format(path, data)

    return {
        "scanner": {
            "name": "Firmware Security Workbench",
            "version": "0.3.0-dev",
            "phase": "05-fastapi-backend",
            "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "file": {
            "path": str(path.resolve()),
            "name": path.name,
            "extension": path.suffix.lower() or None,
            "size_bytes": len(data),
            "sha256": sha256_hex(data),
            "type_guess": type_guess,
            "architecture_hint": architecture_hint,
            "format_details": format_details,
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
