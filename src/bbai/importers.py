from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from bbai.tools.base import is_url_in_scope

MAX_IMPORT_RECORDS = 10000
MAX_IMPORT_BYTES = 32 * 1024 * 1024
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "note": "info",
    "info": "info",
}


@dataclass(frozen=True)
class ImportedFinding:
    title: str
    summary: str
    severity: str
    location: str
    source: str


def parse_nuclei_jsonl(content: str, scope: str) -> list[ImportedFinding]:
    findings: list[ImportedFinding] = []
    record_count = 0
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        record_count += 1
        if record_count > MAX_IMPORT_RECORDS:
            raise ValueError(f"Import exceeds the {MAX_IMPORT_RECORDS} record limit")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid nuclei JSONL at line {line_number}") from exc
        if not isinstance(record, dict):
            raise ValueError(  # noqa: TRY004
                f"Nuclei record at line {line_number} must be an object"
            )
        location = record.get("matched-at")
        info = record.get("info", {})
        if not isinstance(location, str) or not isinstance(info, dict):
            continue
        if not _location_in_scope(location, scope):
            continue
        name = info.get("name") or record.get("template-id") or "Imported nuclei result"
        severity = str(info.get("severity", "info")).lower()
        findings.append(
            ImportedFinding(
                title=str(name)[:255],
                summary=str(info.get("description") or f"Imported scanner result: {name}"),
                severity=SEVERITY_MAP.get(severity, "info"),
                location=location,
                source="nuclei",
            )
        )
    return findings


def parse_sarif(content: str, scope: str) -> list[ImportedFinding]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid SARIF JSON document") from exc
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise ValueError("SARIF document must contain a runs array")  # noqa: TRY004
    findings: list[ImportedFinding] = []
    record_count = 0
    for run in document["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise ValueError("Each SARIF run must contain a results array")  # noqa: TRY004
        rules = (
            {
                rule.get("id"): rule
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
                if isinstance(rule, dict) and isinstance(rule.get("id"), str)
            }
            if isinstance(run.get("tool"), dict)
            else {}
        )
        for result in run.get("results", []):
            record_count += 1
            if record_count > MAX_IMPORT_RECORDS:
                raise ValueError(f"Import exceeds the {MAX_IMPORT_RECORDS} record limit")
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            location = ""
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {})
                artifact = (
                    physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
                )
                uri = artifact.get("uri") if isinstance(artifact, dict) else None
                if isinstance(uri, str):
                    location = uri
            if location and not _location_in_scope(location, scope):
                continue
            rule_id = str(result.get("ruleId", "imported-result"))
            rule = rules.get(rule_id, {})
            rule_level = (
                rule.get("defaultConfiguration", {}).get("level", "warning")
                if isinstance(rule, dict)
                else "warning"
            )
            level = str(result.get("level", rule_level)).lower()
            message = result.get("message", {})
            summary = message.get("text", "") if isinstance(message, dict) else ""
            if not summary:
                summary = f"Imported SARIF result for rule {rule_id}"
            findings.append(
                ImportedFinding(
                    title=str(rule.get("name") or rule_id)[:255]
                    if isinstance(rule, dict)
                    else rule_id,
                    summary=str(summary),
                    severity=SEVERITY_MAP.get(level, "info"),
                    location=location,
                    source="sarif",
                )
            )
    return findings


def _location_in_scope(location: str, scope: str) -> bool:
    parsed = urlparse(location)
    if parsed.scheme not in {"http", "https"}:
        return (not parsed.scheme and "://" not in location) or (
            parsed.scheme == "file" and not parsed.netloc and not parsed.username
        )
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return bool(
        parsed.hostname
        and not parsed.username
        and not parsed.password
        and is_url_in_scope(parsed.hostname, port, scope)
    )
