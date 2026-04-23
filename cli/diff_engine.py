from __future__ import annotations

from pathlib import Path
from typing import Any

from .risk_dna import build_risk_dna, diff_risk_dna
from .scanner import scan_firmware


def _key_findings(item: dict[str, object]) -> tuple[str, str]:
    return (str(item.get("offset_hex", "")), str(item.get("string", "")))


def _key_secrets(item: dict[str, object]) -> tuple[str, str]:
    return (str(item.get("indicator", "")), str(item.get("evidence_redacted", "")))


def _key_rules(item: dict[str, object]) -> tuple[str, str]:
    return (str(item.get("rule_name", "")), str(item.get("severity", "")))


def _key_components(item: dict[str, object]) -> tuple[str, str]:
    return (str(item.get("name", "")), str(item.get("version", "")))


def _key_cves(item: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(item.get("cve_id", "")),
        str(item.get("component_name", "")),
        str(item.get("component_version", "")),
    )


def _diff_list(
    old_items: list[dict[str, object]],
    new_items: list[dict[str, object]],
    *,
    key_fn,
) -> dict[str, list[dict[str, object]]]:
    old_map = {key_fn(item): item for item in old_items}
    new_map = {key_fn(item): item for item in new_items}
    added = [new_map[key] for key in new_map.keys() - old_map.keys()]
    removed = [old_map[key] for key in old_map.keys() - new_map.keys()]
    return {"added": added, "removed": removed}


def diff_scan_results(
    old_result: dict[str, object],
    new_result: dict[str, object],
) -> dict[str, object]:
    old_analysis = old_result.get("analysis", {})
    new_analysis = new_result.get("analysis", {})
    if not isinstance(old_analysis, dict):
        old_analysis = {}
    if not isinstance(new_analysis, dict):
        new_analysis = {}

    old_findings = list(old_analysis.get("suspicious_findings", []))
    new_findings = list(new_analysis.get("suspicious_findings", []))
    old_secrets = list(old_analysis.get("secret_exposures", []))
    new_secrets = list(new_analysis.get("secret_exposures", []))
    old_endpoints = [str(item) for item in old_analysis.get("endpoints_preview", [])]
    new_endpoints = [str(item) for item in new_analysis.get("endpoints_preview", [])]
    old_rules = list(old_analysis.get("rule_matches", []))
    new_rules = list(new_analysis.get("rule_matches", []))
    old_components = list(old_analysis.get("component_candidates", []))
    new_components = list(new_analysis.get("component_candidates", []))
    old_cves = list(old_analysis.get("cve_candidates", []))
    new_cves = list(new_analysis.get("cve_candidates", []))

    old_dna = (
        old_analysis.get("risk_dna")
        if isinstance(old_analysis.get("risk_dna"), dict)
        else build_risk_dna(old_result)
    )
    new_dna = (
        new_analysis.get("risk_dna")
        if isinstance(new_analysis.get("risk_dna"), dict)
        else build_risk_dna(new_result)
    )
    risk_shift = diff_risk_dna(old_dna, new_dna)

    findings_diff = _diff_list(old_findings, new_findings, key_fn=_key_findings)
    secrets_diff = _diff_list(old_secrets, new_secrets, key_fn=_key_secrets)
    rules_diff = _diff_list(old_rules, new_rules, key_fn=_key_rules)
    components_diff = _diff_list(old_components, new_components, key_fn=_key_components)
    cves_diff = _diff_list(old_cves, new_cves, key_fn=_key_cves)

    old_endpoint_set = set(old_endpoints)
    new_endpoint_set = set(new_endpoints)
    endpoints_diff = {
        "added": sorted(new_endpoint_set - old_endpoint_set),
        "removed": sorted(old_endpoint_set - new_endpoint_set),
    }

    return {
        "summary": {
            "old_file": old_result.get("file", {}).get("name", "old"),
            "new_file": new_result.get("file", {}).get("name", "new"),
            "changed": any(
                [
                    findings_diff["added"],
                    findings_diff["removed"],
                    secrets_diff["added"],
                    secrets_diff["removed"],
                    endpoints_diff["added"],
                    endpoints_diff["removed"],
                    rules_diff["added"],
                    rules_diff["removed"],
                    components_diff["added"],
                    components_diff["removed"],
                    cves_diff["added"],
                    cves_diff["removed"],
                ]
            ),
        },
        "old": {
            "counts": {
                "suspicious": int(old_analysis.get("suspicious_count", 0)),
                "secrets": int(old_analysis.get("secret_exposure_count", 0)),
                "endpoints": int(old_analysis.get("endpoint_count", 0)),
                "rules": int(old_analysis.get("rule_match_count", 0)),
                "components": int(old_analysis.get("component_candidate_count", 0)),
                "cves": int(old_analysis.get("cve_candidate_count", 0)),
            },
            "risk_dna": old_dna,
        },
        "new": {
            "counts": {
                "suspicious": int(new_analysis.get("suspicious_count", 0)),
                "secrets": int(new_analysis.get("secret_exposure_count", 0)),
                "endpoints": int(new_analysis.get("endpoint_count", 0)),
                "rules": int(new_analysis.get("rule_match_count", 0)),
                "components": int(new_analysis.get("component_candidate_count", 0)),
                "cves": int(new_analysis.get("cve_candidate_count", 0)),
            },
            "risk_dna": new_dna,
        },
        "delta": {
            "suspicious": int(new_analysis.get("suspicious_count", 0))
            - int(old_analysis.get("suspicious_count", 0)),
            "secrets": int(new_analysis.get("secret_exposure_count", 0))
            - int(old_analysis.get("secret_exposure_count", 0)),
            "endpoints": int(new_analysis.get("endpoint_count", 0))
            - int(old_analysis.get("endpoint_count", 0)),
            "rules": int(new_analysis.get("rule_match_count", 0))
            - int(old_analysis.get("rule_match_count", 0)),
            "components": int(new_analysis.get("component_candidate_count", 0))
            - int(old_analysis.get("component_candidate_count", 0)),
            "cves": int(new_analysis.get("cve_candidate_count", 0))
            - int(old_analysis.get("cve_candidate_count", 0)),
        },
        "risk_shift": risk_shift,
        "changes": {
            "suspicious_findings": findings_diff,
            "secret_exposures": secrets_diff,
            "endpoints": endpoints_diff,
            "rule_matches": rules_diff,
            "component_candidates": components_diff,
            "cve_candidates": cves_diff,
        },
    }


def scan_and_diff_firmware(
    old_file: str | Path,
    new_file: str | Path,
    *,
    min_string_length: int = 4,
    max_strings: int = 2000,
    enable_rules: bool = True,
    rules_dir: str | Path | None = None,
    rule_paths: list[str | Path] | None = None,
) -> dict[str, object]:
    old_result = scan_firmware(
        old_file,
        min_string_length=min_string_length,
        max_strings=max_strings,
        enable_rules=enable_rules,
        rules_dir=rules_dir,
        rule_paths=rule_paths,
    )
    new_result = scan_firmware(
        new_file,
        min_string_length=min_string_length,
        max_strings=max_strings,
        enable_rules=enable_rules,
        rules_dir=rules_dir,
        rule_paths=rule_paths,
    )
    return {
        "old_scan": old_result,
        "new_scan": new_result,
        "diff": diff_scan_results(old_result, new_result),
    }
