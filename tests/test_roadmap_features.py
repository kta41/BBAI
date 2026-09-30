from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bbai.services.project_service import ProjectService


def test_session_labels_and_retention_preserve_research_artifacts(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    old_session = service.create_session(target_name="example.com", title="Old session")
    service.update_session_labels(old_session, ["triage", " auth ", "triage"])
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="response",
        kind="http-response",
        content="status 200",
        session_id=old_session,
    )
    service.set_session_status(old_session, status="closed")
    current_session = service.create_session(target_name="example.com", title="Current session")
    service.update_session_labels(current_session, ["active"])

    removed = service.prune_sessions(
        before=datetime.now(UTC) + timedelta(seconds=1),
        target_name="example.com",
        statuses=("closed",),
    )

    assert removed == [old_session]
    assert service.list_evidence(target_name="example.com")[0]["id"] == evidence_id
    assert service.get_session(current_session)["labels"] == ["active"]
    assert [item["title"] for item in service.list_sessions(target_name="example.com")] == [
        "Current session"
    ]


def test_auth_profile_retains_role_and_expiration_metadata(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    expiry = datetime.now(UTC) + timedelta(hours=2)
    service.add_auth_profile(
        target_name="example.com",
        name="administrator",
        auth_type="bearer",
        secret_ref="example.com/admin",
        role="admin",
        expires_at=expiry,
    )
    profile = service.get_auth_profile(target_name="example.com", name="administrator")
    assert profile is not None
    assert profile["role"] == "admin"
    assert profile["expires_at"] is not None


def test_imported_findings_validate_batch_before_writing(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")

    with pytest.raises(ValueError, match="unsupported severity"):
        service.add_imported_findings(
            target_name="example.com",
            imported=[
                {
                    "title": "Valid scanner result",
                    "summary": "First result.",
                    "severity": "low",
                    "evidence_source": "import:nuclei:valid",
                    "evidence_kind": "scanner-nuclei",
                    "evidence_content": "First result.",
                },
                {
                    "title": "Invalid scanner result",
                    "summary": "Second result.",
                    "severity": "unknown-severity",
                    "evidence_source": "import:nuclei:invalid",
                    "evidence_kind": "scanner-nuclei",
                    "evidence_content": "Second result.",
                },
            ],
        )

    assert service.list_findings(target_name="example.com") == []
    assert service.list_evidence(target_name="example.com") == []
