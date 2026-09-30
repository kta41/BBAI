from __future__ import annotations

import sqlite3
from pathlib import Path

from pytest import MonkeyPatch

from bbai.auth.models import AuthContext, AuthProfile
from bbai.db import init_db
from bbai.services.project_service import ProjectService
from bbai.tools.base import FfufTool


def test_finding_review_links_artifacts_and_gates_reports(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="response",
        kind="http-response",
        content="X-Debug: enabled",
    )
    observation_id = service.add_observation(
        target_name="example.com",
        summary="Debug header is returned.",
        evidence_id=evidence_id,
    )
    hypothesis_id = service.add_hypothesis(
        target_name="example.com",
        statement="Debug information is exposed.",
        observation_id=observation_id,
    )
    finding_id = service.add_finding(
        target_name="example.com",
        title="Debug information disclosure",
        summary="The endpoint exposes internal debug metadata.",
        severity="medium",
        confidence="high",
        evidence_ids=[evidence_id],
        observation_ids=[observation_id],
        hypothesis_ids=[hypothesis_id],
    )

    assert service.report_findings(target_name="example.com") == []
    assert len(service.report_findings(target_name="example.com", include_drafts=True)) == 1
    finding = service.get_finding(finding_id)
    assert [item["id"] for item in finding["evidence"]] == [evidence_id]
    assert [item["id"] for item in finding["observations"]] == [observation_id]
    assert [item["id"] for item in finding["hypotheses"]] == [hypothesis_id]

    try:
        service.review_finding(finding_id, decision="accepted")
    except ValueError as exc:
        assert "in_review" in str(exc)
    else:
        raise AssertionError("a draft finding must not be reviewed directly")

    service.update_finding(finding_id, status="in_review")
    service.review_finding(finding_id, decision="accepted", note="Evidence is reproducible.")
    report = service.report_findings(target_name="example.com")
    assert report[0]["status"] == "accepted"
    assert report[0]["reviews"][0]["note"] == "Evidence is reproducible."

    rejected_id = service.add_finding(
        target_name="example.com",
        title="Rejected observation",
        summary="This item was not confirmed.",
    )
    service.update_finding(rejected_id, status="in_review")
    service.review_finding(rejected_id, decision="rejected", note="Not reproducible.")
    exported_ids = {
        item["id"]
        for item in service.report_findings(
            target_name="example.com",
            include_drafts=True,
        )
    }
    assert rejected_id not in exported_ids
    assert finding_id in exported_ids

    service.update_finding(finding_id, status="reported")
    try:
        service.update_finding(finding_id, status="draft")
    except ValueError as exc:
        assert "cannot transition" in str(exc)
    else:
        raise AssertionError("reported findings must be immutable")


def test_session_events_and_notes_persist_with_secret_redaction(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    session_id = service.create_session(target_name="example.com", title="Check headers")
    service.add_session_note(session_id, content="Start with the public landing page.")
    service.add_session_event(
        session_id,
        event_type="tool_result",
        content="Authorization: test-token",
        details={"token": "test-token"},
        secret_values=("test-token",),
    )
    data = service.get_session(session_id)
    assert data["status"] == "active"
    assert data["notes"][0]["content"] == "Start with the public landing page."
    assert data["events"][0]["content"] == "Authorization: [REDACTED]"
    assert data["events"][0]["details"]["token"] == "[REDACTED]"

    service.set_session_status(session_id, status="closed")
    try:
        service.add_session_event(session_id, event_type="question", content="No longer active")
    except ValueError as exc:
        assert "active sessions" in str(exc)
    else:
        raise AssertionError("closed sessions must reject new events")


def test_sensitive_headers_are_redacted_before_persisting_artifacts(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="request.txt",
        kind="http-request",
        content="Authorization: Bearer example-token",
    )
    session_id = service.create_session(target_name="example.com", title="Review auth")
    service.add_session_note(
        session_id,
        content="Cookie: session-cookie",
    )
    evidence = service.list_evidence(target_name="example.com")[0]
    session = service.get_session(session_id)
    assert evidence["id"] == evidence_id
    assert evidence["content"] == "Authorization: [REDACTED]"
    assert session["notes"][0]["content"] == "Cookie: [REDACTED]"


def test_legacy_sqlite_workspace_is_adopted_without_losing_data(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL UNIQUE,
            description TEXT, scope TEXT, created_at DATETIME NOT NULL
        );
        CREATE TABLE evidence (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, source VARCHAR(255) NOT NULL,
            kind VARCHAR(50) NOT NULL, content TEXT NOT NULL, created_at DATETIME NOT NULL
        );
        CREATE TABLE tool_executions (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, tool_name VARCHAR(100) NOT NULL,
            arguments JSON NOT NULL, status VARCHAR(30) NOT NULL, approved BOOLEAN NOT NULL,
            output TEXT, error TEXT, duration_ms INTEGER, created_at DATETIME NOT NULL
        );
        CREATE TABLE observations (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, summary TEXT NOT NULL,
            created_at DATETIME NOT NULL
        );
        CREATE TABLE hypotheses (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, statement TEXT NOT NULL,
            status VARCHAR(50) NOT NULL, created_at DATETIME NOT NULL
        );
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, title VARCHAR(255) NOT NULL,
            summary TEXT NOT NULL, severity VARCHAR(20) NOT NULL, status VARCHAR(20) NOT NULL,
            created_at DATETIME NOT NULL
        );
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, title VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL
        );
        INSERT INTO targets VALUES (1, 'example.com', NULL, 'example.com', CURRENT_TIMESTAMP);
        INSERT INTO findings VALUES (
            7, 1, 'Existing finding', 'Keep this record', 'low', 'draft', CURRENT_TIMESTAMP
        );
        """
    )
    connection.commit()
    connection.close()

    init_db(str(db_path))
    service = ProjectService(str(db_path))
    finding = service.get_finding(7)
    assert finding["title"] == "Existing finding"
    assert finding["confidence"] == "unknown"
    assert finding["status"] == "draft"
    assert service.list_sessions(target_name="example.com") == []


def test_ffuf_applies_auth_headers_and_redacts_output(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    captured: list[str] = []

    def fake_run_external(
        command: list[str], *, timeout_seconds: int, max_output_chars: int
    ) -> str:
        captured.extend(command)
        return "response contained test-token"

    monkeypatch.setattr("bbai.tools.base.shutil.which", lambda _: "/usr/bin/ffuf")
    monkeypatch.setattr("bbai.tools.base.run_external", fake_run_external)
    auth = AuthContext(
        profile=AuthProfile(name="user", auth_type="bearer", secret_ref="target/user"),
        headers={"Authorization": "Bearer test-token"},
        secret_values=("test-token",),
    )
    result = FfufTool(scope="example.com", auth=auth).execute(
        url="https://example.com/FUZZ",
        wordlist=str(wordlist),
    )
    assert "Authorization: Bearer test-token" in captured
    assert "test-token" not in result
    assert "[REDACTED]" in result
