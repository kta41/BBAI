from collections.abc import Mapping
from pathlib import Path

from bbai.auth.models import AuthProfile
from bbai.auth.redaction import redact_secrets
from bbai.auth.resolver import resolve_auth
from bbai.services.project_service import ProjectService
from bbai.tools.base import FfufTool, HttpHeadersTool, HttpInspectTool, SubfinderTool


def test_evidence_is_persisted_and_available_for_context(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="request.txt",
        kind="http-request",
        content="GET /api/users HTTP/1.1",
    )
    evidence = service.list_evidence(target_name="example.com")
    context = service.get_context_data(target_name="example.com")
    assert evidence_id == evidence[0]["id"]
    assert evidence[0]["kind"] == "http-request"
    assert "GET /api/users" in context["evidence"]
    assert context["scope"] == "example.com"


def test_http_tool_rejects_out_of_scope_hosts() -> None:
    tool = HttpInspectTool(scope="example.com")
    try:
        tool.execute(url="https://outside.example.net/")
    except ValueError as exc:
        assert "outside the approved scope" in str(exc)
    else:
        raise AssertionError("out-of-scope URL should be rejected")


def test_tool_contracts_validate_scope_before_external_execution() -> None:
    headers = HttpHeadersTool(scope="*.example.com")
    subfinder = SubfinderTool(scope="example.com")
    ffuf = FfufTool(scope="example.com")
    for tool, arguments in (
        (headers, {"url": "https://outside.example.net/"}),
        (subfinder, {"domain": "outside.example.net"}),
        (ffuf, {"url": "https://outside.example.net/FUZZ", "wordlist": "/missing"}),
    ):
        try:
            tool.execute(**arguments)
        except ValueError as exc:
            assert "outside the approved scope" in str(exc)
        else:
            raise AssertionError(f"{tool.name} should reject an out-of-scope target")


def test_tool_execution_is_persisted(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    execution_id = service.add_tool_execution(
        target_name="example.com",
        tool_name="http_headers",
        arguments={"url": "https://example.com/"},
        status="dry_run",
        approved=False,
        error="Dry run: tool was not executed.",
        duration_ms=2,
    )
    executions = service.list_tool_executions(target_name="example.com")
    assert execution_id == executions[0]["id"]
    assert executions[0]["status"] == "dry_run"
    assert executions[0]["approved"] is False


def test_observations_and_hypotheses_are_traced_and_in_context(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="response.txt",
        kind="http-response",
        content="X-Debug: true",
    )
    observation_id = service.add_observation(
        target_name="example.com",
        summary="The response exposes a debug header.",
        evidence_id=evidence_id,
    )
    hypothesis_id = service.add_hypothesis(
        target_name="example.com",
        statement="Debug information may be exposed to unauthenticated users.",
        observation_id=observation_id,
        confidence="medium",
    )
    context = service.get_context_data(target_name="example.com")
    assert hypothesis_id == 1
    assert "debug header" in context["observations"]
    assert "Debug information" in context["hypotheses"]


def test_phase_two_schema_is_added_to_existing_database(tmp_path: Path) -> None:
    db_path = tmp_path / "bbai.db"
    service = ProjectService(str(db_path))
    service.add_target(name="example.com", scope="example.com")
    service.add_observation(target_name="example.com", summary="Initial observation")
    reopened = ProjectService(str(db_path))
    observation_id = reopened.add_observation(
        target_name="example.com",
        summary="Observation after reopening the workspace",
    )
    assert observation_id == 2


def test_auth_profile_resolves_without_persisting_secret(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    profile_id = service.add_auth_profile(
        target_name="example.com",
        name="normal-user",
        auth_type="bearer",
        secret_ref="example.com/normal-user",
    )
    profile_data = service.get_auth_profile(target_name="example.com", name="normal-user")

    class MemoryStore:
        def set(self, reference: str, payload: Mapping[str, str]) -> None:
            return None

        def get(self, reference: str) -> dict[str, str]:
            assert reference == "example.com/normal-user"
            return {"token": "token-value-for-test"}

        def delete(self, reference: str) -> None:
            return None

    assert profile_id == 1
    assert profile_data is not None
    context = resolve_auth(
        AuthProfile(
            name="normal-user",
            auth_type="bearer",
            secret_ref=str(profile_data["secret_ref"]),
        ),
        MemoryStore(),
    )
    token = "token-" + "value-for-test"
    assert context.headers == {"Authorization": f"Bearer {token}"}
    assert redact_secrets(f"Authorization: Bearer {token}", context.secret_values) == (
        "Authorization: [REDACTED]"
    )
