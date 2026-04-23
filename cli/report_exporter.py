from __future__ import annotations

import html
import json
from pathlib import Path


def _write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def render_scan_markdown(scan_result: dict[str, object]) -> str:
    file_info = scan_result.get("file", {})
    analysis = scan_result.get("analysis", {})
    if not isinstance(file_info, dict):
        file_info = {}
    if not isinstance(analysis, dict):
        analysis = {}

    lines: list[str] = []
    lines.append("# Firmware Security Report")
    lines.append("")
    lines.append(f"- File: `{file_info.get('name', '-')}`")
    lines.append(f"- Type: `{file_info.get('type_guess', '-')}`")
    lines.append(f"- SHA256: `{file_info.get('sha256', '-')}`")
    lines.append(f"- Entropy: `{analysis.get('entropy', '-')}`")
    lines.append(f"- Suspicious findings: `{analysis.get('suspicious_count', 0)}`")
    lines.append(f"- Secret exposures: `{analysis.get('secret_exposure_count', 0)}`")
    lines.append(f"- Rule matches: `{analysis.get('rule_match_count', 0)}`")
    lines.append(f"- SBOM candidates: `{analysis.get('component_candidate_count', 0)}`")
    lines.append(f"- CVE candidates: `{analysis.get('cve_candidate_count', 0)}`")
    hardening = analysis.get("hardening_simulation", {})
    if not isinstance(hardening, dict):
        hardening = {}
    baseline = hardening.get("baseline", {})
    projected = hardening.get("projected", {})
    if not isinstance(baseline, dict):
        baseline = {}
    if not isinstance(projected, dict):
        projected = {}
    if hardening:
        lines.append(
            "- Hardening projection: "
            f"`{baseline.get('score', '-')}` -> `{projected.get('score', '-')}` "
            f"(actions: `{hardening.get('actions_count', 0)}`)"
        )
    lines.append("")
    lines.append("## Top Findings")
    findings = list(analysis.get("suspicious_findings", []))[:10]
    if findings:
        for finding in findings:
            lines.append(
                f"- [{finding.get('severity','info')}/{finding.get('confidence','low')}] "
                f"{finding.get('offset_hex','-')} {finding.get('string','')}"
            )
    else:
        lines.append("- No suspicious findings.")
    lines.append("")
    lines.append("## Top CVE Candidates")
    cves = list(analysis.get("cve_candidates", []))[:10]
    if cves:
        for cve in cves:
            lines.append(
                f"- [{cve.get('confidence','low')}] {cve.get('cve_id','UNKNOWN')} "
                f"{cve.get('component_name','-')} {cve.get('component_version','-')} "
                f"(severity: {cve.get('severity','unknown')}, cvss: {cve.get('cvss_base_score','-')})"
            )
    else:
        lines.append("- No CVE candidates.")
    lines.append("")
    lines.append("## Hardening Simulator")
    if hardening:
        lines.append(
            f"- Baseline: `{baseline.get('score', '-')}` (`{baseline.get('band', '-')}`)"
        )
        lines.append(
            f"- Projected: `{projected.get('score', '-')}` (`{projected.get('band', '-')}`)"
        )
        lines.append(f"- Estimated reduction: `{projected.get('estimated_reduction', 0)}`")
        lines.append(f"- Recommended actions: `{hardening.get('actions_count', 0)}`")
        actions = list(hardening.get("actions", []))[:8]
        if actions:
            lines.append("")
            lines.append("### Top Actions")
            for action in actions:
                lines.append(
                    f"- {action.get('title', 'Unnamed action')} "
                    f"(effort: {action.get('effort', '-')}, "
                    f"reduction: {action.get('estimated_risk_reduction', 0)})"
                )
    else:
        lines.append("- Hardening simulation data is not available.")
    return "\n".join(lines) + "\n"


def render_diff_markdown(diff_payload: dict[str, object]) -> str:
    diff = diff_payload.get("diff", {})
    if not isinstance(diff, dict):
        diff = {}
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

    lines: list[str] = []
    lines.append("# Firmware Diff Report")
    lines.append("")
    lines.append(f"- Old file: `{summary.get('old_file','old')}`")
    lines.append(f"- New file: `{summary.get('new_file','new')}`")
    lines.append(f"- Changed: `{summary.get('changed', False)}`")
    lines.append("")
    lines.append("## Delta")
    for key in ("suspicious", "secrets", "endpoints", "rules", "components", "cves"):
        lines.append(f"- {key}: `{delta.get(key, 0)}`")
    lines.append("")
    lines.append("## Risk Shift")
    lines.append(f"- Trend: `{risk_shift.get('trend','risk_stable')}`")
    lines.append(f"- Score delta: `{risk_shift.get('score_delta', 0)}`")
    lines.append(f"- Old band: `{risk_shift.get('old_band', '-')}`")
    lines.append(f"- New band: `{risk_shift.get('new_band', '-')}`")
    lines.append("")
    lines.append("## Hardening Shift")
    lines.append(f"- Trend: `{hardening_shift.get('trend', 'hardening_stable')}`")
    lines.append(
        "- Reduction potential (old -> new): "
        f"`{hardening_shift.get('old_reduction_potential', 0)}` -> "
        f"`{hardening_shift.get('new_reduction_potential', 0)}`"
    )
    lines.append(
        f"- Reduction potential delta: `{hardening_shift.get('reduction_potential_delta', 0)}`"
    )
    lines.append(
        "- Projected band (old -> new): "
        f"`{hardening_shift.get('old_projected_band', '-')}` -> "
        f"`{hardening_shift.get('new_projected_band', '-')}`"
    )
    return "\n".join(lines) + "\n"


def render_scan_html(scan_result: dict[str, object]) -> str:
    md = render_scan_markdown(scan_result)
    pre = html.escape(md)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>FWB Scan Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;}"
        "pre{white-space:pre-wrap;background:#f6f8fa;padding:16px;border-radius:8px;}</style>"
        "</head><body><h1>Firmware Security Workbench</h1>"
        f"<pre>{pre}</pre></body></html>"
    )


def render_diff_html(diff_payload: dict[str, object]) -> str:
    md = render_diff_markdown(diff_payload)
    pre = html.escape(md)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>FWB Diff Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;}"
        "pre{white-space:pre-wrap;background:#f6f8fa;padding:16px;border-radius:8px;}</style>"
        "</head><body><h1>Firmware Security Workbench</h1>"
        f"<pre>{pre}</pre></body></html>"
    )


def export_scan_report(
    scan_result: dict[str, object],
    *,
    report_format: str,
    output_path: Path,
) -> Path:
    fmt = report_format.lower()
    if fmt == "json":
        content = json.dumps(scan_result, indent=2)
    elif fmt in {"md", "markdown"}:
        content = render_scan_markdown(scan_result)
    elif fmt == "html":
        content = render_scan_html(scan_result)
    else:
        raise ValueError(f"Unsupported report format: {report_format}")
    _write_output(output_path, content)
    return output_path


def export_diff_report(
    diff_payload: dict[str, object],
    *,
    report_format: str,
    output_path: Path,
) -> Path:
    fmt = report_format.lower()
    if fmt == "json":
        content = json.dumps(diff_payload, indent=2)
    elif fmt in {"md", "markdown"}:
        content = render_diff_markdown(diff_payload)
    elif fmt == "html":
        content = render_diff_html(diff_payload)
    else:
        raise ValueError(f"Unsupported report format: {report_format}")
    _write_output(output_path, content)
    return output_path
