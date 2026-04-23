from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanError, scan_firmware


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwb",
        description="Firmware Security Workbench command-line scanner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a firmware file and print findings",
    )
    scan_parser.add_argument("file", help="Path to firmware file")
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON output",
    )
    scan_parser.add_argument(
        "--out",
        type=Path,
        help="Optional output file path for JSON result",
    )
    scan_parser.add_argument(
        "--min-string-length",
        type=int,
        default=4,
        help="Minimum printable string length (default: 4)",
    )
    scan_parser.add_argument(
        "--max-strings",
        type=int,
        default=2000,
        help="Maximum extracted strings before truncation (default: 2000)",
    )
    return parser


def _print_summary(result: dict[str, object]) -> None:
    file_info = result["file"]
    analysis = result["analysis"]
    findings = analysis["suspicious_findings"][:10]
    format_details = file_info.get("format_details", {})

    print("Firmware Security Workbench Scan")
    print("--------------------------------")
    print(f"File: {file_info['name']}")
    print(f"Path: {file_info['path']}")
    print(f"Type: {file_info['type_guess']}")
    if file_info.get("architecture_hint"):
        print(f"Architecture hint: {file_info['architecture_hint']}")
    if isinstance(format_details, dict) and format_details.get("parser_status"):
        print(f"Format parser status: {format_details['parser_status']}")
    print(f"Size (bytes): {file_info['size_bytes']}")
    print(f"SHA256: {file_info['sha256']}")
    print(f"Entropy: {analysis['entropy']}")
    print(f"Extracted strings: {analysis['strings_count']}")
    print(f"Suspicious findings: {analysis['suspicious_count']}")

    if not findings:
        print("\nNo suspicious keyword findings in extracted strings.")
        return

    print("\nTop suspicious findings:")
    for finding in findings:
        print(
            f"- [{finding['severity']}/{finding['confidence']}] "
            f"{finding['offset_hex']} keywords={','.join(finding['keywords'])} "
            f"text={finding['string']}"
        )


def run_scan_command(args: argparse.Namespace) -> int:
    try:
        result = scan_firmware(
            args.file,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
        )
    except ScanError as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 2

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_summary(result)
        if args.out:
            print(f"\nSaved JSON result: {args.out}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
