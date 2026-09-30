from __future__ import annotations

import json

from bbai.importers import parse_nuclei_jsonl, parse_sarif


def test_nuclei_adapter_normalizes_severity_and_filters_out_of_scope() -> None:
    records = [
        {
            "info": {"name": "Reflected output", "severity": "high"},
            "matched-at": "https://api.example.com/path",
        },
        {
            "info": {"name": "Out of scope", "severity": "critical"},
            "matched-at": "https://attacker.test/path",
        },
    ]
    findings = parse_nuclei_jsonl(
        "\n".join(json.dumps(record) for record in records),
        "*.example.com",
    )
    assert [(item.title, item.severity, item.location) for item in findings] == [
        ("Reflected output", "high", "https://api.example.com/path")
    ]


def test_sarif_adapter_supports_rules_locations_and_levels() -> None:
    report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "BBAI-1", "name": "Missing header"}]}},
                "results": [
                    {
                        "ruleId": "BBAI-1",
                        "level": "error",
                        "message": {"text": "Header absent"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://example.com/account"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "OUT",
                        "message": {"text": "Outside scope"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://other.test/"}
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    findings = parse_sarif(json.dumps(report), "example.com")
    assert len(findings) == 1
    assert findings[0].title == "Missing header"
    assert findings[0].severity == "high"
    assert findings[0].summary == "Header absent"


def test_importers_reject_malformed_documents() -> None:
    try:
        parse_nuclei_jsonl("{", "example.com")
    except ValueError as exc:
        assert "line 1" in str(exc)
    else:
        raise AssertionError("malformed JSONL must fail")
    try:
        parse_sarif("{}", "example.com")
    except ValueError as exc:
        assert "runs array" in str(exc)
    else:
        raise AssertionError("invalid SARIF must fail")
