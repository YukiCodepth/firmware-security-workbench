from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanError, scan_firmware
from .storage import DEFAULT_DB_PATH, get_scan_record, list_scans, save_scan_result


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
    scan_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"SQLite database path for scan history (default: {DEFAULT_DB_PATH})",
    )
    scan_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save this scan to the SQLite history database",
    )

    history_parser = subparsers.add_parser(
        "history",
        help="Read saved scan history from SQLite",
    )
    history_subparsers = history_parser.add_subparsers(
        dest="history_command", required=True
    )

    history_list_parser = history_subparsers.add_parser(
        "list",
        help="List recent saved scans",
    )
    history_list_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum scans to list (default: 20)",
    )
    history_list_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    history_list_parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output",
    )

    history_show_parser = history_subparsers.add_parser(
        "show",
        help="Show one saved scan",
    )
    history_show_parser.add_argument("scan_id", type=int, help="Saved scan id")
    history_show_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    history_show_parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON output",
    )
    return parser


def _print_summary(result: dict[str, object]) -> None:
    file_info = result["file"]
    analysis = result["analysis"]
    findings = analysis["suspicious_findings"][:10]
    secret_exposures = analysis.get("secret_exposures", [])[:8]
    endpoints = analysis.get("endpoints_preview", [])[:8]
    posture = analysis.get("security_posture", {})
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
    print(f"Secret exposures: {analysis.get('secret_exposure_count', 0)}")
    print(f"Network endpoints: {analysis.get('endpoint_count', 0)}")
    if isinstance(posture, dict) and posture:
        print(
            f"Security posture: {posture.get('risk_level', '-')}"
            f" (score {posture.get('score', '-')}, top severity {posture.get('top_severity', '-')})"
        )

    if not findings:
        print("\nNo suspicious keyword findings in extracted strings.")
    else:
        print("\nTop suspicious findings:")
        for finding in findings:
            print(
                f"- [{finding['severity']}/{finding['confidence']}] "
                f"{finding['offset_hex']} keywords={','.join(finding['keywords'])} "
                f"text={finding['string']}"
            )

    if secret_exposures:
        print("\nTop secret exposures:")
        for exposure in secret_exposures:
            print(
                f"- [{exposure['severity']}/{exposure['confidence']}] "
                f"{exposure['offset_hex']} {exposure['indicator']} "
                f"{exposure['evidence_redacted']}"
            )

    if endpoints:
        print("\nEndpoint preview:")
        for endpoint in endpoints:
            print(f"- {endpoint}")


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

    saved_scan_id: int | None = None
    if not args.no_save:
        saved_scan_id = save_scan_result(result, db_path=args.db)
        result["storage"] = {
            "saved": True,
            "scan_id": saved_scan_id,
            "database_path": str(args.db.resolve()),
        }
    else:
        result["storage"] = {
            "saved": False,
            "scan_id": None,
            "database_path": str(args.db.resolve()),
        }

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_summary(result)
        if saved_scan_id is not None:
            print(f"Saved scan id: {saved_scan_id} (db: {args.db})")
        else:
            print(f"Scan was not saved (--no-save). Target db: {args.db}")
        if args.out:
            print(f"\nSaved JSON result: {args.out}")

    return 0


def _print_history_table(rows: list[dict[str, object]], db_path: Path) -> None:
    print(f"Scan history from {db_path} ({len(rows)} entries)")
    print("ID  UTC Timestamp                 Type         Findings  File")
    print("--  ----------------------------  -----------  --------  ----------------")
    for row in rows:
        scan_id = row.get("id")
        scanned_at = str(row.get("scanned_at_utc", ""))[:28]
        file_type = str(row.get("type_guess", ""))[:11]
        suspicious = row.get("suspicious_count", 0)
        file_name = str(row.get("file_name", ""))
        print(
            f"{str(scan_id).rjust(2)}  {scanned_at:<28}  {file_type:<11}  "
            f"{str(suspicious).rjust(8)}  {file_name}"
        )


def run_history_list_command(args: argparse.Namespace) -> int:
    rows = list_scans(db_path=args.db, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        _print_history_table(rows, args.db)
    return 0


def run_history_show_command(args: argparse.Namespace) -> int:
    try:
        record = get_scan_record(scan_id=args.scan_id, db_path=args.db)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    result = record["result"]
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"Stored scan #{record['scan_id']} ({record['scanned_at_utc']})")
        _print_summary(result)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)
    if args.command == "history":
        if args.history_command == "list":
            return run_history_list_command(args)
        if args.history_command == "show":
            return run_history_show_command(args)
        print("Unknown history command.", file=sys.stderr)
        return 2

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
