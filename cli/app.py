from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diff_engine import scan_and_diff_firmware
from .report_exporter import export_diff_report, export_scan_report
from .rule_engine import DEFAULT_RULES_DIR
from .scanner import ScanError, scan_firmware
from .storage import DEFAULT_DB_PATH, get_scan_record, list_scans, save_scan_result

REPORT_FORMAT_CHOICES = ("json", "markdown", "md", "html")


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
        "--sbom-out",
        type=Path,
        help="Optional output file path for CycloneDX SBOM JSON",
    )
    scan_parser.add_argument(
        "--report-format",
        choices=REPORT_FORMAT_CHOICES,
        help="Optional report format export for this scan",
    )
    scan_parser.add_argument(
        "--report-out",
        type=Path,
        help="Optional report output path for this scan",
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
        "--no-rules",
        action="store_true",
        help="Disable YARA/rules-engine scanning",
    )
    scan_parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help=f"Directory containing YARA rule files (default: {DEFAULT_RULES_DIR})",
    )
    scan_parser.add_argument(
        "--rules-file",
        type=Path,
        action="append",
        help="Additional YARA rule file path. Can be passed multiple times.",
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

    diff_parser = subparsers.add_parser(
        "diff",
        help="Scan and compare two firmware files",
    )
    diff_parser.add_argument("old_file", help="Older or baseline firmware file path")
    diff_parser.add_argument("new_file", help="Newer firmware file path")
    diff_parser.add_argument("--json", action="store_true", help="Print full JSON output")
    diff_parser.add_argument("--out", type=Path, help="Optional output file path for JSON diff")
    diff_parser.add_argument(
        "--report-format",
        choices=REPORT_FORMAT_CHOICES,
        help="Optional report format export for this diff",
    )
    diff_parser.add_argument(
        "--report-out",
        type=Path,
        help="Optional report output path for this diff",
    )
    diff_parser.add_argument(
        "--min-string-length",
        type=int,
        default=4,
        help="Minimum printable string length (default: 4)",
    )
    diff_parser.add_argument(
        "--max-strings",
        type=int,
        default=2000,
        help="Maximum extracted strings before truncation (default: 2000)",
    )
    diff_parser.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable YARA/rules-engine scanning for both files",
    )
    diff_parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help=f"Directory containing YARA rule files (default: {DEFAULT_RULES_DIR})",
    )
    diff_parser.add_argument(
        "--rules-file",
        type=Path,
        action="append",
        help="Additional YARA rule file path. Can be passed multiple times.",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Render a report from existing scan/diff JSON",
    )
    report_parser.add_argument("input", type=Path, help="Input JSON file path")
    report_parser.add_argument(
        "--kind",
        choices=("scan", "diff"),
        required=True,
        help="Input JSON kind",
    )
    report_parser.add_argument(
        "--format",
        choices=REPORT_FORMAT_CHOICES,
        required=True,
        help="Report format to render",
    )
    report_parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path for rendered report",
    )
    return parser


def _print_summary(result: dict[str, object]) -> None:
    file_info = result["file"]
    analysis = result["analysis"]
    findings = analysis["suspicious_findings"][:10]
    secret_exposures = analysis.get("secret_exposures", [])[:8]
    endpoints = analysis.get("endpoints_preview", [])[:8]
    posture = analysis.get("security_posture", {})
    rule_matches = analysis.get("rule_matches", [])[:6]
    component_candidates = analysis.get("component_candidates", [])[:8]
    cve_candidates = analysis.get("cve_candidates", [])[:8]
    cve_confidence = analysis.get("cve_confidence_summary", {})
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
    print(
        f"SBOM candidates: {analysis.get('component_candidate_count', 0)} "
        f"(sbom components={analysis.get('sbom_component_count', 0)})"
    )
    print(
        f"CVE candidates: {analysis.get('cve_candidate_count', 0)} "
        f"(high={cve_confidence.get('high', 0)}, medium={cve_confidence.get('medium', 0)}, low={cve_confidence.get('low', 0)})"
    )
    print(
        f"Rules engine: {analysis.get('rule_engine', '-')} "
        f"(loaded={analysis.get('rules_loaded', 0)}, matches={analysis.get('rule_match_count', 0)})"
    )
    if isinstance(posture, dict) and posture:
        print(
            f"Security posture: {posture.get('risk_level', '-')}"
            f" (score {posture.get('score', '-')}, top severity {posture.get('top_severity', '-')})"
        )
    risk_dna = analysis.get("risk_dna", {})
    hardening = analysis.get("hardening_simulation", {})
    if not isinstance(hardening, dict):
        hardening = {}
    projected = hardening.get("projected", {})
    if not isinstance(projected, dict):
        projected = {}
    if isinstance(risk_dna, dict) and risk_dna:
        print(
            f"Risk DNA: {risk_dna.get('band', '-')}"
            f" (score {risk_dna.get('score', '-')}, fingerprint {risk_dna.get('fingerprint', '-')})"
        )
    if hardening:
        print(
            "Hardening simulator: "
            f"projected score {projected.get('score', '-')} "
            f"({projected.get('band', '-')}), "
            f"actions {hardening.get('actions_count', 0)}"
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

    if rule_matches:
        print("\nTop rule matches:")
        for match in rule_matches:
            print(
                f"- [{match.get('severity', 'info')}] "
                f"{match.get('rule_name', 'unknown_rule')} "
                f"tags={','.join(match.get('tags', []))}"
            )

    if component_candidates:
        print("\nTop SBOM candidates:")
        for candidate in component_candidates:
            print(
                f"- [{candidate.get('confidence', 'low')}] "
                f"{candidate.get('name', 'unknown')} {candidate.get('version', '?')}"
            )

    if cve_candidates:
        print("\nTop CVE candidates:")
        for candidate in cve_candidates:
            print(
                f"- [{candidate.get('confidence', 'low')}] {candidate.get('cve_id', 'UNKNOWN-CVE')} "
                f"{candidate.get('component_name', 'unknown')} {candidate.get('component_version', '?')} "
                f"severity={candidate.get('severity', 'unknown')} cvss={candidate.get('cvss_base_score', '-')}"
            )
    hardening_actions = hardening.get("actions", [])
    if isinstance(hardening_actions, list) and hardening_actions:
        print("\nTop hardening actions:")
        for action in hardening_actions[:5]:
            print(
                f"- {action.get('title', 'Unnamed action')} "
                f"(effort={action.get('effort', '-')}, reduction={action.get('estimated_risk_reduction', 0)})"
            )


def _print_diff_summary(diff_payload: dict[str, object]) -> None:
    diff = diff_payload.get("diff", {})
    if not isinstance(diff, dict):
        print("Invalid diff payload.", file=sys.stderr)
        return

    summary = diff.get("summary", {})
    delta = diff.get("delta", {})
    risk_shift = diff.get("risk_shift", {})
    hardening_shift = diff.get("hardening_shift", {})
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(delta, dict):
        delta = {}
    if not isinstance(risk_shift, dict):
        risk_shift = {}
    if not isinstance(hardening_shift, dict):
        hardening_shift = {}

    print("Firmware Security Workbench Diff")
    print("--------------------------------")
    print(f"Old file: {summary.get('old_file', 'old')}")
    print(f"New file: {summary.get('new_file', 'new')}")
    print(f"Changed: {summary.get('changed', False)}")
    print(
        "Delta: "
        f"suspicious={delta.get('suspicious', 0)}, "
        f"secrets={delta.get('secrets', 0)}, "
        f"endpoints={delta.get('endpoints', 0)}, "
        f"rules={delta.get('rules', 0)}, "
        f"components={delta.get('components', 0)}, "
        f"cves={delta.get('cves', 0)}"
    )
    print(
        "Risk shift: "
        f"trend={risk_shift.get('trend', 'risk_stable')}, "
        f"score_delta={risk_shift.get('score_delta', 0)}, "
        f"{risk_shift.get('old_band', '-')} -> {risk_shift.get('new_band', '-')}"
    )
    print(
        "Hardening shift: "
        f"trend={hardening_shift.get('trend', 'hardening_stable')}, "
        f"potential_delta={hardening_shift.get('reduction_potential_delta', 0)}, "
        f"{hardening_shift.get('old_projected_band', '-')} -> {hardening_shift.get('new_projected_band', '-')}"
    )


def _export_scan_report_if_requested(
    result: dict[str, object],
    *,
    report_format: str | None,
    report_out: Path | None,
) -> Path | None:
    if report_format is None and report_out is None:
        return None
    if report_format is None or report_out is None:
        raise ValueError("Both --report-format and --report-out are required together.")
    return export_scan_report(result, report_format=report_format, output_path=report_out)


def _export_diff_report_if_requested(
    diff_payload: dict[str, object],
    *,
    report_format: str | None,
    report_out: Path | None,
) -> Path | None:
    if report_format is None and report_out is None:
        return None
    if report_format is None or report_out is None:
        raise ValueError("Both --report-format and --report-out are required together.")
    return export_diff_report(diff_payload, report_format=report_format, output_path=report_out)


def run_scan_command(args: argparse.Namespace) -> int:
    try:
        result = scan_firmware(
            args.file,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
            enable_rules=not args.no_rules,
            rules_dir=args.rules_dir,
            rule_paths=args.rules_file,
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
    if args.sbom_out:
        args.sbom_out.parent.mkdir(parents=True, exist_ok=True)
        args.sbom_out.write_text(json.dumps(result["sbom"], indent=2), encoding="utf-8")

    try:
        report_path = _export_scan_report_if_requested(
            result,
            report_format=args.report_format,
            report_out=args.report_out,
        )
    except ValueError as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 2

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
        if args.sbom_out:
            print(f"Saved SBOM JSON: {args.sbom_out}")
        if report_path is not None:
            print(f"Saved report: {report_path}")

    return 0


def run_diff_command(args: argparse.Namespace) -> int:
    try:
        payload = scan_and_diff_firmware(
            args.old_file,
            args.new_file,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
            enable_rules=not args.no_rules,
            rules_dir=args.rules_dir,
            rule_paths=args.rules_file,
        )
    except ScanError as exc:
        print(f"Diff failed: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 2

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    try:
        report_path = _export_diff_report_if_requested(
            payload,
            report_format=args.report_format,
            report_out=args.report_out,
        )
    except ValueError as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        _print_diff_summary(payload)
        if args.out:
            print(f"Saved JSON diff: {args.out}")
        if report_path is not None:
            print(f"Saved report: {report_path}")
    return 0


def run_report_render_command(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Unable to read input report source: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        if args.kind == "scan":
            output = export_scan_report(
                payload,
                report_format=args.format,
                output_path=args.out,
            )
        else:
            output = export_diff_report(
                payload,
                report_format=args.format,
                output_path=args.out,
            )
    except ValueError as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 2

    print(f"Saved report: {output}")
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
    if args.command == "diff":
        return run_diff_command(args)
    if args.command == "report":
        return run_report_render_command(args)
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
