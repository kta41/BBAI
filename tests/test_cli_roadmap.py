from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from pytest import MonkeyPatch
from typer.testing import CliRunner

from bbai.auth.models import AuthProfile
from bbai.auth.resolver import resolve_auth
from bbai.cli import app
from bbai.config import Settings
from bbai.services.project_service import ProjectService

runner = CliRunner()


def _init_workspace(path: Path, monkeypatch: MonkeyPatch, scope: str = "example.com") -> None:
    monkeypatch.chdir(path)
    assert runner.invoke(app, ["init", "--skip-dependency-setup"]).exit_code == 0
    assert runner.invoke(app, ["target", "add", "example.com", "--scope", scope]).exit_code == 0
    assert runner.invoke(app, ["target", "use", "example.com"]).exit_code == 0


def test_cli_session_labels_export_and_retention_preview(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _init_workspace(tmp_path, monkeypatch)
    assert runner.invoke(app, ["session", "create", "Header review"]).exit_code == 0
    labelled = runner.invoke(
        app,
        ["session", "labels", "1", "--label", "triage", "--label", "headers"],
    )
    assert labelled.exit_code == 0, labelled.stdout
    sessions = runner.invoke(app, ["session", "list"])
    assert "triage, headers" in sessions.stdout

    exported = tmp_path / "session.json"
    result = runner.invoke(app, ["session", "export", "1", "--output", str(exported)])
    assert result.exit_code == 0, result.stdout
    assert json.loads(exported.read_text(encoding="utf-8"))["labels"] == ["triage", "headers"]

    preview = runner.invoke(app, ["session", "prune", "--older-than-days", "1"])
    assert preview.exit_code == 0
    assert "rerun with --apply" in preview.stdout


def test_cli_scanner_import_creates_draft_and_skips_out_of_scope(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _init_workspace(tmp_path, monkeypatch, "*.example.com")
    input_file = tmp_path / "nuclei.jsonl"
    input_file.write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "template-id": "header-check",
                        "info": {"name": "Missing header", "severity": "medium"},
                        "matched-at": "https://api.example.com/",
                    }
                ),
                json.dumps(
                    {
                        "info": {"name": "External result", "severity": "high"},
                        "matched-at": "https://outside.test/",
                    }
                ),
            )
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["import-results", str(input_file), "--format", "nuclei-jsonl"])
    assert result.exit_code == 0, result.stdout
    assert "Imported 1 scoped result(s) as draft findings." in result.stdout
    service = ProjectService(str(Settings.load(tmp_path).db_path))
    finding = service.get_finding(1)
    assert finding["title"] == "Missing header"
    assert finding["status"] == "draft"
    assert finding["evidence"][0]["kind"] == "scanner-nuclei"


def test_cli_workspace_export_and_import_round_trip(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _init_workspace(tmp_path, monkeypatch)
    archive = tmp_path / "portable.bbai.zip"
    exported = runner.invoke(app, ["workspace", "export", str(archive)])
    assert exported.exit_code == 0, exported.stdout
    assert archive.exists()

    assert (
        runner.invoke(app, ["target", "add", "later.example", "--scope", "later.example"]).exit_code
        == 0
    )
    refused = runner.invoke(app, ["workspace", "import", str(archive)])
    assert refused.exit_code == 1
    imported = runner.invoke(app, ["workspace", "import", str(archive), "--replace"])
    assert imported.exit_code == 0, imported.stdout
    targets = runner.invoke(app, ["target", "list"])
    assert "example.com" in targets.stdout
    assert "later.example" not in targets.stdout


def test_cli_semantic_search_formats_and_filters_results(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _init_workspace(tmp_path, monkeypatch)

    def rank_semantically(
        query: str, documents: list[dict[str, object]], **_kwargs: object
    ) -> list[dict[str, object]]:
        assert query == "account access"
        assert documents
        return [
            {
                "artifact_type": "finding",
                "artifact_id": 7,
                "target_name": "example.com",
                "session_id": None,
                "status": "accepted",
                "severity": "high",
                "title": "Authorization boundary",
                "body": "Account access differs between profiles.",
                "semantic_score": 0.9,
            }
        ]

    monkeypatch.setattr("bbai.cli.rank_semantically", rank_semantically)
    result = runner.invoke(
        app,
        ["search", "account access", "--semantic", "--status", "accepted", "--severity", "high"],
    )

    assert result.exit_code == 0, result.stdout
    assert "finding:7 [example.com]" in result.stdout
    assert "Authorization boundary" in result.stdout


def test_cli_report_uses_configurable_template(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    _init_workspace(tmp_path, monkeypatch)
    service = ProjectService(str(Settings.load(tmp_path).db_path))
    finding_id = service.add_finding(
        target_name="example.com",
        title="Debug header",
        summary="A debug header is exposed.",
        severity="low",
    )
    service.update_finding(finding_id, status="in_review")
    service.review_finding(finding_id, decision="accepted")
    template = tmp_path / "report-template.md"
    template.write_text("# $title\nTarget: $target\n$summary\n", encoding="utf-8")

    result = runner.invoke(app, ["report", "--template", str(template)])

    assert result.exit_code == 0, result.stdout
    assert "# Debug header" in result.stdout
    assert "Target: example.com" in result.stdout


def test_auth_profile_expiration_and_anonymous_role(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _init_workspace(tmp_path, monkeypatch)
    created = runner.invoke(
        app,
        ["auth", "profile-add", "anon", "--role", "anonymous", "--expires-in-hours", "2"],
    )
    assert created.exit_code == 0, created.stdout
    profile = ProjectService(str(Settings.load(tmp_path).db_path)).get_auth_profile(
        target_name="example.com",
        name="anon",
    )
    assert profile is not None
    assert profile["role"] == "anonymous"
    assert profile["expires_at"] is not None

    class NoStore:
        def get(self, reference: str) -> dict[str, str]:
            raise AssertionError("anonymous profiles do not retrieve keyring secrets")

    context = resolve_auth(
        AuthProfile(name="anon", auth_type="headers", secret_ref="unused", role="anonymous"),
        NoStore(),
    )
    assert context.headers == {}
    assert context.secret_values == ()


def test_cookie_import_requires_confirmation_and_never_echoes_value(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _init_workspace(tmp_path, monkeypatch)
    secret = "private-cookie-value"
    cookie_file = tmp_path / "cookie.txt"
    cookie_file.write_text(f"Cookie: session={secret}\n", encoding="utf-8")
    saved: dict[str, dict[str, str]] = {}
    writes = 0

    def save_cookie(_self: object, reference: str, payload: dict[str, str]) -> None:
        nonlocal writes
        writes += 1
        saved[reference] = dict(payload)

    monkeypatch.setattr(
        "bbai.cli.KeyringSecretStore.set",
        save_cookie,
    )

    result = runner.invoke(
        app,
        ["auth", "cookie-import", "normal-user", str(cookie_file), "--role", "user"],
        input="y\n",
    )

    assert result.exit_code == 0, result.output
    assert secret not in result.output
    assert saved["example.com/normal-user"] == {"cookie": f"session={secret}"}
    duplicate = runner.invoke(
        app,
        ["auth", "cookie-import", "normal-user", str(cookie_file), "--role", "user"],
        input="y\n",
    )
    assert duplicate.exit_code == 1
    assert writes == 1
    profile = ProjectService(str(Settings.load(tmp_path).db_path)).get_auth_profile(
        target_name="example.com",
        name="normal-user",
    )
    assert profile is not None and profile["role"] == "user"


def test_auth_compare_performs_approved_scoped_requests(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    response_bodies: list[str] = []

    class AuthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = (
                b"authenticated"
                if self.headers.get("Authorization") == "Bearer comparison-token"
                else b"anonymous"
            )
            response_bodies.append(body.decode())
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), AuthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        _init_workspace(tmp_path, monkeypatch, f"127.0.0.1:{port}")
        service = ProjectService(str(Settings.load(tmp_path).db_path))
        service.add_auth_profile(
            target_name="example.com",
            name="anonymous",
            auth_type="headers",
            secret_ref="anonymous",
            role="anonymous",
        )
        service.add_auth_profile(
            target_name="example.com",
            name="user",
            auth_type="bearer",
            secret_ref="example.com/user",
            role="user",
        )
        monkeypatch.setattr(
            "bbai.cli.KeyringSecretStore.get",
            lambda _self, reference: {"token": "comparison-token"},
        )
        result = runner.invoke(
            app,
            [
                "auth",
                "compare",
                "--url",
                f"http://127.0.0.1:{port}/account",
                "--left",
                "anonymous",
                "--right",
                "user",
            ],
            input="y\ny\n",
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result.exit_code == 0, result.output
    assert "Responses differ." in result.output
    assert response_bodies == ["anonymous", "authenticated"]
