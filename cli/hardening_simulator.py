from __future__ import annotations

from typing import Any


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

INSECURE_ENDPOINT_SCHEMES = {"http", "mqtt", "ws", "ftp"}


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except Exception:
        return 0


def _risk_band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _severity_points(severity: str) -> int:
    table = {
        "critical": 18,
        "high": 12,
        "medium": 7,
        "low": 3,
        "info": 1,
    }
    return table.get(severity.lower(), 1)


def _confidence_factor(confidence: str) -> float:
    table = {"high": 1.0, "medium": 0.8, "low": 0.6}
    return table.get(confidence.lower(), 0.6)


def _string_has_any(value: str, terms: list[str]) -> bool:
    text = value.lower()
    return any(term in text for term in terms)


def _is_insecure_endpoint(url: str) -> bool:
    if "://" not in url:
        return False
    scheme = url.split("://", 1)[0].lower().strip()
    return scheme in INSECURE_ENDPOINT_SCHEMES


def _sorted_actions(actions: list[dict[str, object]]) -> list[dict[str, object]]:
    effort_rank = {"low": 0, "medium": 1, "high": 2}
    return sorted(
        actions,
        key=lambda item: (
            -_int(item.get("estimated_risk_reduction", 0)),
            effort_rank.get(str(item.get("effort", "high")), 2),
            str(item.get("title", "")),
        ),
    )


def _safe_list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            result.append(item)
    return result


def _safe_list_of_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        result.append(str(item))
    return result


def _build_scenario(
    *,
    name: str,
    description: str,
    actions: list[dict[str, object]],
    baseline_score: int,
) -> dict[str, object]:
    reduction = int(
        sum(
            _int(action.get("estimated_risk_reduction", 0))
            * _confidence_factor(str(action.get("confidence", "low")))
            for action in actions
        )
    )
    max_reduction_cap = max(5, int(baseline_score * 0.8))
    reduction = min(max(reduction, 0), max_reduction_cap)
    projected_score = max(0, baseline_score - reduction)
    return {
        "name": name,
        "description": description,
        "action_count": len(actions),
        "projected_score": projected_score,
        "projected_band": _risk_band(projected_score),
        "reduction": reduction,
        "actions": [str(action.get("title", "Unnamed action")) for action in actions],
    }


def simulate_hardening(scan_result: dict[str, object]) -> dict[str, object]:
    analysis = scan_result.get("analysis", {})
    file_info = scan_result.get("file", {})
    if not isinstance(analysis, dict):
        analysis = {}
    if not isinstance(file_info, dict):
        file_info = {}

    risk_dna = analysis.get("risk_dna", {})
    security_posture = analysis.get("security_posture", {})
    if not isinstance(risk_dna, dict):
        risk_dna = {}
    if not isinstance(security_posture, dict):
        security_posture = {}

    suspicious_findings = _safe_list_of_dicts(analysis.get("suspicious_findings"))
    secret_exposures = _safe_list_of_dicts(analysis.get("secret_exposures"))
    endpoints_preview = _safe_list_of_strings(analysis.get("endpoints_preview"))
    cve_candidates = _safe_list_of_dicts(analysis.get("cve_candidates"))
    rule_matches = _safe_list_of_dicts(analysis.get("rule_matches"))
    component_candidates = _safe_list_of_dicts(analysis.get("component_candidates"))

    baseline_score = _int(risk_dna.get("score", security_posture.get("score", 0)))
    if baseline_score <= 0:
        baseline_score = min(
            100,
            _int(analysis.get("suspicious_count", 0)) * 5
            + _int(analysis.get("secret_exposure_count", 0)) * 10
            + _int(analysis.get("cve_candidate_count", 0)) * 12
            + _int(analysis.get("rule_match_count", 0)) * 2,
        )

    baseline_band = str(risk_dna.get("band", _risk_band(baseline_score)))
    action_index: dict[str, dict[str, object]] = {}

    def add_action(action: dict[str, object]) -> None:
        action_id = str(action.get("id", "")).strip()
        if not action_id:
            return
        if action_id in action_index:
            existing = action_index[action_id]
            existing["estimated_risk_reduction"] = min(
                35,
                _int(existing.get("estimated_risk_reduction", 0))
                + _int(action.get("estimated_risk_reduction", 0)),
            )
            existing["evidence_count"] = _int(existing.get("evidence_count", 0)) + _int(
                action.get("evidence_count", 0)
            )
            return
        action_index[action_id] = action

    if secret_exposures:
        high_count = sum(
            1
            for item in secret_exposures
            if str(item.get("severity", "low")).lower() in {"high", "critical"}
        )
        add_action(
            {
                "id": "rotate-credentials-and-secrets",
                "title": "Rotate embedded credentials and move secrets to secure storage",
                "effort": "medium",
                "confidence": "high",
                "estimated_risk_reduction": min(34, 12 + len(secret_exposures) * 3 + high_count * 3),
                "evidence_count": len(secret_exposures),
                "owner": "firmware-security",
                "why": "Secrets in firmware are high-value attacker targets and are easy to extract statically.",
                "first_step": "Replace hardcoded tokens/passwords with per-device secrets from secure element or encrypted provisioning flow.",
            }
        )

    insecure_endpoints = [url for url in endpoints_preview if _is_insecure_endpoint(url)]
    if insecure_endpoints:
        add_action(
            {
                "id": "enforce-encrypted-transport",
                "title": "Enforce TLS and authenticated transport for firmware network paths",
                "effort": "medium",
                "confidence": "high",
                "estimated_risk_reduction": min(22, 10 + len(insecure_endpoints) * 2),
                "evidence_count": len(insecure_endpoints),
                "owner": "connectivity",
                "why": "Plaintext protocols enable interception and credential replay attacks.",
                "first_step": "Migrate HTTP/MQTT/WS endpoints to HTTPS/MQTTS/WSS with certificate pinning policy.",
            }
        )

    debug_hits = [
        item
        for item in suspicious_findings
        if _string_has_any(str(item.get("string", "")), ["debug", "trace", "console"])
        or any(
            _string_has_any(str(keyword), ["debug", "trace"])
            for keyword in item.get("keywords", [])
            if isinstance(keyword, str)
        )
    ]
    if debug_hits:
        add_action(
            {
                "id": "strip-debug-surface",
                "title": "Strip debug paths and lock debug interfaces for production builds",
                "effort": "low",
                "confidence": "high",
                "estimated_risk_reduction": min(16, 6 + len(debug_hits) * 2),
                "evidence_count": len(debug_hits),
                "owner": "platform",
                "why": "Debug symbols and traces can leak runtime internals and become privilege shortcuts.",
                "first_step": "Disable debug compile flags and require signed unlock challenge for service mode.",
            }
        )

    admin_hits = [
        item
        for item in suspicious_findings
        if _string_has_any(str(item.get("string", "")), ["admin", "root", "panel", "console"])
    ]
    if admin_hits:
        add_action(
            {
                "id": "harden-admin-surface",
                "title": "Harden admin interfaces with least privilege and explicit authz",
                "effort": "medium",
                "confidence": "medium",
                "estimated_risk_reduction": min(18, 7 + len(admin_hits) * 2),
                "evidence_count": len(admin_hits),
                "owner": "application-security",
                "why": "Administrative strings often correlate with hidden management functionality.",
                "first_step": "Gate admin endpoints behind role checks, MFA-capable service auth, and disabled-by-default mode.",
            }
        )

    ota_hits = [
        item
        for item in suspicious_findings
        if _string_has_any(str(item.get("string", "")), ["ota", "firmware update", "update_url", "fw.bin"])
    ]
    if ota_hits:
        add_action(
            {
                "id": "verify-signed-ota",
                "title": "Enforce signed OTA manifests and anti-rollback controls",
                "effort": "high",
                "confidence": "high",
                "estimated_risk_reduction": min(24, 10 + len(ota_hits) * 2),
                "evidence_count": len(ota_hits),
                "owner": "release-engineering",
                "why": "Insecure update paths are one of the fastest routes to persistent compromise.",
                "first_step": "Require image signatures, monotonic version counters, and reject downgrade images.",
            }
        )

    if cve_candidates:
        high_cves = sum(
            1
            for cve in cve_candidates
            if str(cve.get("severity", "")).lower() in {"high", "critical"}
        )
        add_action(
            {
                "id": "patch-known-cves",
                "title": "Patch vulnerable component versions and re-scan",
                "effort": "medium",
                "confidence": "high",
                "estimated_risk_reduction": min(36, 12 + len(cve_candidates) * 2 + high_cves * 3),
                "evidence_count": len(cve_candidates),
                "owner": "dependency-management",
                "why": "Known CVEs represent externally documented exploit paths.",
                "first_step": "Upgrade top vulnerable dependencies then re-run scan and diff to verify risk reduction.",
            }
        )

    if component_candidates and not cve_candidates:
        add_action(
            {
                "id": "sbom-lifecycle-enforcement",
                "title": "Enforce SBOM lifecycle policy with version pinning and freshness SLA",
                "effort": "medium",
                "confidence": "medium",
                "estimated_risk_reduction": min(14, 5 + len(component_candidates)),
                "evidence_count": len(component_candidates),
                "owner": "supply-chain",
                "why": "Component drift without vulnerability tracking creates hidden long-term risk.",
                "first_step": "Add CI policy to fail builds when component age or support window exceeds threshold.",
            }
        )

    if rule_matches:
        top_rule = max(
            (str(item.get("severity", "low")).lower() for item in rule_matches),
            key=lambda sev: SEVERITY_RANK.get(sev, 0),
        )
        add_action(
            {
                "id": "convert-rule-matches-to-ci-gates",
                "title": "Convert high-confidence rule matches into CI security gates",
                "effort": "low",
                "confidence": "high",
                "estimated_risk_reduction": min(12, 4 + len(rule_matches)),
                "evidence_count": len(rule_matches),
                "owner": "devsecops",
                "why": "Rule hits should become enforceable controls, not one-off observations.",
                "first_step": f"Fail CI on {top_rule} severity rule matches unless an approved waiver exists.",
            }
        )

    entropy = float(analysis.get("entropy", 0.0))
    if entropy >= 7.2:
        add_action(
            {
                "id": "high-entropy-triage",
                "title": "Perform high-entropy section triage for packed or encrypted payloads",
                "effort": "high",
                "confidence": "medium",
                "estimated_risk_reduction": 9,
                "evidence_count": 1,
                "owner": "reverse-engineering",
                "why": "High entropy can hide obfuscated logic or bundled artifacts.",
                "first_step": "Map high-entropy ranges and classify expected encryption vs unexpected packing.",
            }
        )

    firmware_type = str(file_info.get("type_guess", "")).lower()
    if any(tag in firmware_type for tag in ("raw", "uf2", "hex")):
        add_action(
            {
                "id": "device-identity-binding",
                "title": "Add device-identity binding for firmware provenance verification",
                "effort": "high",
                "confidence": "medium",
                "estimated_risk_reduction": 8,
                "evidence_count": 1,
                "owner": "platform-security",
                "why": "Identity binding prevents cloned firmware from being replayed across unauthorized devices.",
                "first_step": "Bind firmware boot approval to device-specific hardware identity claims.",
            }
        )

    actions = _sorted_actions(list(action_index.values()))

    estimated_total_reduction = int(
        sum(
            _int(item.get("estimated_risk_reduction", 0))
            * _confidence_factor(str(item.get("confidence", "low")))
            for item in actions
        )
    )
    max_reduction_cap = max(4, int(baseline_score * 0.72))
    estimated_total_reduction = min(max(estimated_total_reduction, 0), max_reduction_cap)
    projected_score = max(0, baseline_score - estimated_total_reduction)
    projected_band = _risk_band(projected_score)

    quick_actions = [item for item in actions if str(item.get("effort", "")) == "low"][:3]
    balanced_actions = actions[: min(5, len(actions))]
    aggressive_actions = actions[: min(8, len(actions))]

    scenarios = [
        _build_scenario(
            name="quick-patch",
            description="Apply low-effort controls first for immediate risk reduction.",
            actions=quick_actions,
            baseline_score=baseline_score,
        ),
        _build_scenario(
            name="balanced-sprint",
            description="Apply top blended controls during one sprint.",
            actions=balanced_actions,
            baseline_score=baseline_score,
        ),
        _build_scenario(
            name="aggressive-lockdown",
            description="Apply all major controls for maximal hardening.",
            actions=aggressive_actions,
            baseline_score=baseline_score,
        ),
    ]

    return {
        "version": "1.0",
        "baseline": {"score": baseline_score, "band": baseline_band},
        "projected": {
            "score": projected_score,
            "band": projected_band,
            "estimated_reduction": estimated_total_reduction,
        },
        "actions_count": len(actions),
        "actions": actions,
        "scenarios": scenarios,
        "top_priority_action": actions[0]["title"] if actions else None,
    }


def diff_hardening_simulation(
    old_simulation: dict[str, Any],
    new_simulation: dict[str, Any],
) -> dict[str, object]:
    if not isinstance(old_simulation, dict):
        old_simulation = {}
    if not isinstance(new_simulation, dict):
        new_simulation = {}

    old_baseline = old_simulation.get("baseline", {})
    old_projected = old_simulation.get("projected", {})
    new_baseline = new_simulation.get("baseline", {})
    new_projected = new_simulation.get("projected", {})
    if not isinstance(old_baseline, dict):
        old_baseline = {}
    if not isinstance(old_projected, dict):
        old_projected = {}
    if not isinstance(new_baseline, dict):
        new_baseline = {}
    if not isinstance(new_projected, dict):
        new_projected = {}

    old_reduction = _int(old_projected.get("estimated_reduction", 0))
    new_reduction = _int(new_projected.get("estimated_reduction", 0))
    potential_delta = new_reduction - old_reduction

    if potential_delta >= 8:
        trend = "hardening_more_urgent"
    elif potential_delta <= -8:
        trend = "hardening_improved"
    else:
        trend = "hardening_stable"

    return {
        "trend": trend,
        "old_reduction_potential": old_reduction,
        "new_reduction_potential": new_reduction,
        "reduction_potential_delta": potential_delta,
        "old_projected_band": old_projected.get("band", old_baseline.get("band", "unknown")),
        "new_projected_band": new_projected.get("band", new_baseline.get("band", "unknown")),
        "old_actions_count": _int(old_simulation.get("actions_count", 0)),
        "new_actions_count": _int(new_simulation.get("actions_count", 0)),
    }
