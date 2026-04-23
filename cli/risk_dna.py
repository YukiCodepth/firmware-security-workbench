from __future__ import annotations

import hashlib
import json
from typing import Any


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except Exception:
        return 0


def _float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except Exception:
        return 0.0


def _risk_band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def build_risk_dna(scan_result: dict[str, object]) -> dict[str, object]:
    file_info = scan_result.get("file", {}) if isinstance(scan_result, dict) else {}
    analysis = scan_result.get("analysis", {}) if isinstance(scan_result, dict) else {}
    if not isinstance(file_info, dict):
        file_info = {}
    if not isinstance(analysis, dict):
        analysis = {}

    suspicious_count = _int(analysis.get("suspicious_count", 0))
    secret_count = _int(analysis.get("secret_exposure_count", 0))
    endpoint_count = _int(analysis.get("endpoint_count", 0))
    rule_match_count = _int(analysis.get("rule_match_count", 0))
    component_count = _int(analysis.get("component_candidate_count", 0))
    cve_count = _int(analysis.get("cve_candidate_count", 0))
    entropy = _float(analysis.get("entropy", 0.0))
    type_guess = str(file_info.get("type_guess", "unknown"))

    tags: list[str] = []
    if suspicious_count > 0:
        tags.append("FINDINGS")
    if secret_count > 0:
        tags.append("CREDS")
    if endpoint_count > 0:
        tags.append("NET")
    if rule_match_count > 0:
        tags.append("RULES")
    if component_count > 0:
        tags.append("SBOM")
    if cve_count > 0:
        tags.append("CVE")
    if entropy >= 7.0:
        tags.append("HIGH_ENTROPY")
    if entropy <= 2.0:
        tags.append("LOW_ENTROPY")
    if "ELF" in type_guess.upper():
        tags.append("ELF")
    if "UF2" in type_guess.upper():
        tags.append("UF2")
    if "HEX" in type_guess.upper():
        tags.append("HEX")
    if not tags:
        tags.append("BASELINE")

    score = min(
        100,
        suspicious_count * 6
        + secret_count * 14
        + endpoint_count * 4
        + rule_match_count * 3
        + component_count * 2
        + cve_count * 15
        + int(min(max(entropy, 0.0), 8.0)),
    )
    band = _risk_band(score)

    signature_payload = {
        "type_guess": type_guess,
        "tags": sorted(set(tags)),
        "suspicious_count": suspicious_count,
        "secret_count": secret_count,
        "endpoint_count": endpoint_count,
        "rule_match_count": rule_match_count,
        "component_count": component_count,
        "cve_count": cve_count,
        "entropy_bucket": round(entropy, 2),
    }
    signature_raw = json.dumps(signature_payload, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(signature_raw.encode("utf-8")).hexdigest()[:24]

    return {
        "version": "1.0",
        "tags": sorted(set(tags)),
        "score": score,
        "band": band,
        "fingerprint": fingerprint,
        "signature": signature_payload,
    }


def diff_risk_dna(
    old_dna: dict[str, Any],
    new_dna: dict[str, Any],
) -> dict[str, object]:
    old_tags = set(old_dna.get("tags", []))
    new_tags = set(new_dna.get("tags", []))
    old_score = _int(old_dna.get("score", 0))
    new_score = _int(new_dna.get("score", 0))
    score_delta = new_score - old_score

    if score_delta >= 12:
        trend = "risk_increased"
    elif score_delta <= -12:
        trend = "risk_decreased"
    else:
        trend = "risk_stable"

    return {
        "old_band": old_dna.get("band", "unknown"),
        "new_band": new_dna.get("band", "unknown"),
        "old_score": old_score,
        "new_score": new_score,
        "score_delta": score_delta,
        "trend": trend,
        "added_tags": sorted(new_tags - old_tags),
        "removed_tags": sorted(old_tags - new_tags),
        "fingerprint_changed": old_dna.get("fingerprint") != new_dna.get("fingerprint"),
    }
