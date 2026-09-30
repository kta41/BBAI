from __future__ import annotations

import json
import os
from pathlib import Path

from bbai.audit import append_tool_audit_event


def test_tool_audit_log_contains_metadata_only_and_is_private(tmp_path: Path) -> None:
    log_path = tmp_path / ".bbai" / "audit.jsonl"
    append_tool_audit_event(
        log_path,
        tool_name="http_headers",
        status="succeeded",
        approved=True,
        duration_ms=14,
    )
    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert event["event"] == "tool_execution"
    assert event["tool"] == "http_headers"
    assert event["status"] == "succeeded"
    assert event["approved"] is True
    assert event["duration_ms"] == 14
    assert "arguments" not in event
    assert "output" not in event
    assert "target" not in event
    if os.name == "posix":
        assert log_path.parent.stat().st_mode & 0o777 == 0o700
        assert log_path.stat().st_mode & 0o777 == 0o600
