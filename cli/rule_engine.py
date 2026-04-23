from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:  # pragma: no cover - optional dependency path
    import yara  # type: ignore
except Exception:  # pragma: no cover - optional dependency path
    yara = None


DEFAULT_RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "yara"
SEVERITY_VALUES = {"critical", "high", "medium", "low", "info"}

RULE_BLOCK_RE = re.compile(
    r"(?ms)rule\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*([^{]+))?\s*\{(.*?)\}"
)
SECTION_RE = re.compile(
    r"(?ims)^\s*(meta|strings|condition)\s*:\s*(.*?)(?=^\s*(?:meta|strings|condition)\s*:|\Z)"
)
STRING_DEF_RE = re.compile(r'^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"\s*(.*)$')
RULE_DECL_RE = re.compile(r"(?m)^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*\b")


def _serialize_meta(meta: dict[str, object]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in meta.items():
        out[str(key)] = str(value)
    return out


def _severity_from_meta_or_tags(meta: dict[str, object], tags: list[str]) -> str:
    meta_severity = meta.get("severity")
    if isinstance(meta_severity, str):
        lowered = meta_severity.lower()
        if lowered in SEVERITY_VALUES:
            return lowered

    for tag in tags:
        lowered = tag.lower()
        if lowered in SEVERITY_VALUES:
            return lowered
    return "info"


def _count_rule_defs(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    return len(RULE_DECL_RE.findall(text))


def _collect_rule_files(
    *,
    rules_dir: Path | None,
    rule_paths: list[Path] | None,
) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    warnings: list[str] = []

    if rules_dir is not None:
        if not rules_dir.exists():
            warnings.append(f"Rules directory not found: {rules_dir}")
        elif not rules_dir.is_dir():
            warnings.append(f"Rules path is not a directory: {rules_dir}")
        else:
            patterns = ("*.yar", "*.yara", "*.rule")
            for pattern in patterns:
                files.extend(sorted(rules_dir.glob(pattern)))

    if rule_paths:
        for path in rule_paths:
            if path.exists() and path.is_file():
                files.append(path)
            else:
                warnings.append(f"Rule file not found: {path}")

    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped, warnings


def _normalize_yara_strings(
    raw_strings: list[object], *, max_strings_per_match: int
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for item in raw_strings:
        if len(out) >= max_strings_per_match:
            break

        if isinstance(item, tuple) and len(item) >= 3:
            offset = int(item[0])
            identifier = str(item[1])
            raw = item[2]
            text = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
            out.append(
                {
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "identifier": identifier,
                    "text": text[:180],
                }
            )
            continue

        identifier = getattr(item, "identifier", "")
        instances = getattr(item, "instances", [])
        for instance in instances:
            if len(out) >= max_strings_per_match:
                break
            offset = int(getattr(instance, "offset", 0))
            data = getattr(instance, "matched_data", b"")
            if isinstance(data, bytes):
                text = data.decode("utf-8", errors="ignore")
            else:
                text = str(data)
            out.append(
                {
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "identifier": str(identifier),
                    "text": text[:180],
                }
            )
    return out


def _scan_with_yara_python(
    data: bytes,
    *,
    rule_files: list[Path],
    max_strings_per_match: int,
) -> tuple[list[dict[str, object]], list[str]]:
    warnings: list[str] = []
    file_map = {f"ns{i}": str(path) for i, path in enumerate(rule_files)}
    try:
        compiled = yara.compile(filepaths=file_map)
        matches = compiled.match(data=data, timeout=30)
    except Exception as exc:  # pragma: no cover - only when optional engine present
        warnings.append(f"yara-python compile/match failed: {exc}")
        return [], warnings

    normalized: list[dict[str, object]] = []
    for match in matches:
        rule_name = str(getattr(match, "rule", "unknown_rule"))
        tags = [str(tag) for tag in (getattr(match, "tags", []) or [])]
        meta = dict(getattr(match, "meta", {}) or {})
        strings = _normalize_yara_strings(
            list(getattr(match, "strings", []) or []),
            max_strings_per_match=max_strings_per_match,
        )
        normalized.append(
            {
                "rule_name": rule_name,
                "namespace": str(getattr(match, "namespace", "default")),
                "severity": _severity_from_meta_or_tags(meta, tags),
                "tags": tags,
                "meta": _serialize_meta(meta),
                "strings": strings,
            }
        )
    return normalized, warnings


def _parse_sections(block: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    for section_name, section_body in SECTION_RE.findall(block):
        sections[section_name.lower()] = section_body.strip()
    return sections


def _parse_meta_block(meta_block: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in meta_block.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip().strip('"')
        if key:
            meta[key] = raw_value
    return meta


def _parse_strings_block(strings_block: str) -> list[dict[str, object]]:
    defs: list[dict[str, object]] = []
    for line in strings_block.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        match = STRING_DEF_RE.match(line)
        if not match:
            continue
        string_id = f"${match.group(1)}"
        pattern = match.group(2)
        options = match.group(3).lower().split()
        defs.append(
            {
                "id": string_id,
                "pattern": pattern,
                "nocase": "nocase" in options,
            }
        )
    return defs


def _evaluate_condition(
    condition: str,
    *,
    matched_ids: set[str],
    available_ids: set[str],
) -> bool:
    normalized = " ".join(condition.lower().split())
    if not normalized:
        return bool(matched_ids)
    if normalized == "any of them":
        return bool(matched_ids)
    if normalized == "all of them":
        return bool(available_ids) and available_ids.issubset(matched_ids)
    num_match = re.match(r"^(\d+)\s+of\s+them$", normalized)
    if num_match:
        needed = int(num_match.group(1))
        return len(matched_ids) >= needed

    referenced = set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", normalized))
    if referenced:
        if " and " in normalized:
            return referenced.issubset(matched_ids)
        if " or " in normalized:
            return any(item in matched_ids for item in referenced)
        return next(iter(referenced)) in matched_ids

    return bool(matched_ids)


def _scan_with_builtin_parser(
    data: bytes,
    *,
    rule_files: list[Path],
    max_strings_per_match: int,
) -> tuple[list[dict[str, object]], int, list[str]]:
    text = data.decode("latin-1", errors="ignore")
    matches: list[dict[str, object]] = []
    loaded_rule_count = 0
    warnings: list[str] = []

    for file_path in rule_files:
        try:
            rule_text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append(f"Unable to read rule file {file_path}: {exc}")
            continue

        blocks = RULE_BLOCK_RE.findall(rule_text)
        if not blocks:
            warnings.append(f"No parseable rules in {file_path.name}")
            continue

        for rule_name, raw_tags, block in blocks:
            loaded_rule_count += 1
            sections = _parse_sections(block)
            strings = _parse_strings_block(sections.get("strings", ""))
            condition = sections.get("condition", "")
            meta = _parse_meta_block(sections.get("meta", ""))
            tags = [item.strip() for item in raw_tags.split() if item.strip()]
            available_ids = {item["id"] for item in strings}

            matched_ids: set[str] = set()
            string_hits: list[dict[str, object]] = []
            for string_def in strings:
                pattern = str(string_def["pattern"])
                if not pattern:
                    continue
                regex = re.escape(pattern)
                flags = re.IGNORECASE if bool(string_def["nocase"]) else 0
                for hit in re.finditer(regex, text, flags):
                    matched_ids.add(str(string_def["id"]))
                    if len(string_hits) < max_strings_per_match:
                        value = hit.group(0)
                        string_hits.append(
                            {
                                "offset": hit.start(),
                                "offset_hex": hex(hit.start()),
                                "identifier": str(string_def["id"]),
                                "text": value[:180],
                            }
                        )

            if not _evaluate_condition(
                condition,
                matched_ids=matched_ids,
                available_ids=available_ids,
            ):
                continue

            matches.append(
                {
                    "rule_name": rule_name,
                    "namespace": file_path.stem,
                    "severity": _severity_from_meta_or_tags(meta, tags),
                    "tags": tags,
                    "meta": _serialize_meta(meta),
                    "strings": string_hits,
                }
            )
    return matches, loaded_rule_count, warnings


def run_rule_engine(
    data: bytes,
    *,
    rules_dir: Path | None = DEFAULT_RULES_DIR,
    rule_paths: list[Path] | None = None,
    max_strings_per_match: int = 5,
) -> dict[str, object]:
    rule_files, warnings = _collect_rule_files(rules_dir=rules_dir, rule_paths=rule_paths)
    if not rule_files:
        return {
            "engine": "builtin-fallback",
            "rules_loaded": 0,
            "rule_files": [],
            "rule_matches": [],
            "warnings": warnings + ["No rule files were loaded."],
        }

    rules_loaded = sum(_count_rule_defs(path) for path in rule_files)

    if yara is not None:
        yara_matches, yara_warnings = _scan_with_yara_python(
            data,
            rule_files=rule_files,
            max_strings_per_match=max_strings_per_match,
        )
        if not yara_warnings:
            return {
                "engine": "yara-python",
                "rules_loaded": rules_loaded,
                "rule_files": [str(path) for path in rule_files],
                "rule_matches": yara_matches,
                "warnings": warnings,
            }
        warnings.extend(yara_warnings)

    builtin_matches, builtin_count, builtin_warnings = _scan_with_builtin_parser(
        data,
        rule_files=rule_files,
        max_strings_per_match=max_strings_per_match,
    )
    warnings.extend(builtin_warnings)
    return {
        "engine": "builtin-fallback",
        "rules_loaded": builtin_count if builtin_count > 0 else rules_loaded,
        "rule_files": [str(path) for path in rule_files],
        "rule_matches": builtin_matches,
        "warnings": warnings,
    }
