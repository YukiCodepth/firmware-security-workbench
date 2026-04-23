from __future__ import annotations

import re
from typing import Any


CVSS_SEVERITY_BANDS: list[tuple[float, str]] = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]

COMPONENT_ALIASES = {
    "openssl": "OpenSSL",
    "mbedtls": "mbedTLS",
    "wolfssl": "wolfSSL",
    "busybox": "BusyBox",
    "u-boot": "U-Boot",
    "uboot": "U-Boot",
    "linux kernel": "Linux Kernel",
    "linux": "Linux Kernel",
    "zlib": "zlib",
    "musl libc": "musl libc",
    "musl": "musl libc",
}

CVE_CATALOG: list[dict[str, object]] = [
    {
        "cve_id": "CVE-2023-0286",
        "component": "OpenSSL",
        "summary": "X.400 address type confusion in OpenSSL certificate verification.",
        "references": ["https://www.openssl.org/news/secadv/20230207.txt"],
        "cvss_base_score": 7.4,
        "affected": {"gte": "1.0.2", "lt": "3.0.8"},
    },
    {
        "cve_id": "CVE-2022-0778",
        "component": "OpenSSL",
        "summary": "Infinite loop in BN_mod_sqrt() can cause denial of service.",
        "references": ["https://www.openssl.org/news/secadv/20220315.txt"],
        "cvss_base_score": 7.5,
        "affected": {"gte": "1.0.2", "lt": "1.1.1n"},
    },
    {
        "cve_id": "CVE-2021-44732",
        "component": "mbedTLS",
        "summary": "Integer overflow in mbed TLS affecting specific cryptographic operations.",
        "references": ["https://mbed-tls.readthedocs.io/en/latest/security-advisories/"],
        "cvss_base_score": 5.9,
        "affected": {"gte": "2.16.0", "lt": "2.28.1"},
    },
    {
        "cve_id": "CVE-2018-25032",
        "component": "zlib",
        "summary": "zlib memory corruption issue in deflate implementation.",
        "references": ["https://zlib.net/ChangeLog.txt"],
        "cvss_base_score": 7.5,
        "affected": {"gte": "1.2.2", "lt": "1.2.12"},
    },
    {
        "cve_id": "CVE-2022-30065",
        "component": "BusyBox",
        "summary": "BusyBox vulnerability candidate for specific pre-1.35 releases.",
        "references": ["https://busybox.net/"],
        "cvss_base_score": 6.5,
        "affected": {"lt": "1.35.0"},
    },
    {
        "cve_id": "CVE-2021-27138",
        "component": "U-Boot",
        "summary": "Potential vulnerability candidate in older U-Boot branches.",
        "references": ["https://u-boot.readthedocs.io/"],
        "cvss_base_score": 6.8,
        "affected": {"lt": "2021.04"},
    },
]


def normalize_component_name(name: str) -> str:
    normalized = re.sub(r"\s+", " ", name.strip().lower())
    return COMPONENT_ALIASES.get(normalized, name)


def _tokenize_version(version: str) -> list[tuple[int, Any]]:
    parts = re.findall(r"\d+|[a-z]+", version.lower())
    tokens: list[tuple[int, Any]] = []
    for item in parts:
        if item.isdigit():
            tokens.append((0, int(item)))
        else:
            tokens.append((1, item))
    return tokens


def compare_versions(left: str, right: str) -> int:
    left_tokens = _tokenize_version(left)
    right_tokens = _tokenize_version(right)
    max_len = max(len(left_tokens), len(right_tokens))

    for index in range(max_len):
        l_token = left_tokens[index] if index < len(left_tokens) else (0, 0)
        r_token = right_tokens[index] if index < len(right_tokens) else (0, 0)
        if l_token == r_token:
            continue
        if l_token < r_token:
            return -1
        return 1
    return 0


def _version_in_range(version: str, constraints: dict[str, str]) -> bool:
    eq = constraints.get("eq")
    if eq is not None and compare_versions(version, eq) != 0:
        return False
    gt = constraints.get("gt")
    if gt is not None and compare_versions(version, gt) <= 0:
        return False
    gte = constraints.get("gte")
    if gte is not None and compare_versions(version, gte) < 0:
        return False
    lt = constraints.get("lt")
    if lt is not None and compare_versions(version, lt) >= 0:
        return False
    lte = constraints.get("lte")
    if lte is not None and compare_versions(version, lte) > 0:
        return False
    prefix = constraints.get("prefix")
    if prefix is not None and not version.startswith(prefix):
        return False
    return True


def _cvss_to_severity(cvss_base_score: float) -> str:
    for threshold, label in CVSS_SEVERITY_BANDS:
        if cvss_base_score >= threshold:
            return label
    return "info"


def _confidence_from_component(component_confidence: str) -> str:
    if component_confidence == "high":
        return "high"
    if component_confidence == "medium":
        return "medium"
    return "low"


def summarize_cve_confidence(cve_candidates: list[dict[str, object]]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0}
    for candidate in cve_candidates:
        confidence = str(candidate.get("confidence", "low"))
        if confidence not in summary:
            continue
        summary[confidence] += 1
    return summary


def match_cve_candidates(
    component_candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    dedupe: set[tuple[str, str, str]] = set()

    for component in component_candidates:
        raw_name = str(component.get("name", ""))
        normalized_name = normalize_component_name(raw_name)
        version = str(component.get("version", ""))
        component_confidence = str(component.get("confidence", "low"))

        for record in CVE_CATALOG:
            cve_component = str(record["component"])
            if normalize_component_name(cve_component) != normalized_name:
                continue

            constraints = dict(record.get("affected", {}))
            if not _version_in_range(version, constraints):
                continue

            cve_id = str(record["cve_id"])
            key = (cve_id, raw_name, version)
            if key in dedupe:
                continue
            dedupe.add(key)

            cvss = float(record.get("cvss_base_score", 0.0))
            candidates.append(
                {
                    "cve_id": cve_id,
                    "component_name": raw_name,
                    "component_version": version,
                    "summary": str(record.get("summary", "")),
                    "cvss_base_score": cvss,
                    "severity": _cvss_to_severity(cvss),
                    "confidence": _confidence_from_component(component_confidence),
                    "source": "local-catalog",
                    "references": list(record.get("references", [])),
                    "match_rule": {
                        "component": cve_component,
                        "affected": constraints,
                    },
                    "review_note": "Candidate match only. Validate with vendor advisory and full SBOM context.",
                }
            )

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    confidence_rank = {"high": 2, "medium": 1, "low": 0}
    candidates.sort(
        key=lambda item: (
            severity_rank.get(str(item["severity"]), 0),
            confidence_rank.get(str(item["confidence"]), 0),
            float(item["cvss_base_score"]),
        ),
        reverse=True,
    )
    return candidates
