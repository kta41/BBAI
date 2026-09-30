from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TypedDict, TypeVar

from sqlalchemy import delete, select, text
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from bbai.auth.redaction import redact_secrets
from bbai.db import get_session_factory, init_db
from bbai.models import (
    AuthProfile,
    Evidence,
    Finding,
    FindingReview,
    Hypothesis,
    Note,
    Observation,
    SessionEvent,
    Target,
    ToolExecution,
    finding_evidence,
    finding_executions,
    finding_hypotheses,
    finding_observations,
    utc_now,
)
from bbai.models import (
    Session as InvestigationSession,
)

ModelT = TypeVar("ModelT", Evidence, Observation, Hypothesis, ToolExecution)


class EvidenceData(TypedDict):
    id: int
    source: str
    kind: str
    content: str


class ReviewData(TypedDict):
    decision: str
    note: str
    reviewer: str
    created_at: str


class FindingData(TypedDict):
    id: int
    target: str
    title: str
    summary: str
    severity: str
    confidence: str
    impact: str
    reproduction: str
    remediation: str
    status: str
    session_id: int | None
    session_title: str | None
    auth_profiles: list[str]
    evidence: list[EvidenceData]
    observations: list[dict[str, int | str]]
    hypotheses: list[dict[str, int | str]]
    executions: list[dict[str, int | str]]
    reviews: list[ReviewData]


class ImportedFindingInput(TypedDict):
    title: str
    summary: str
    severity: str
    evidence_source: str
    evidence_kind: str
    evidence_content: str


class FindingSummary(TypedDict):
    id: int
    title: str
    severity: str
    status: str
    summary: str
    confidence: str


class SessionSummary(TypedDict):
    id: int
    title: str
    status: str
    created_at: datetime
    updated_at: datetime
    labels: list[str]


class SessionNoteData(TypedDict):
    content: str
    created_at: datetime


class SessionEventData(TypedDict):
    type: str
    content: str
    details: dict[str, object]
    created_at: datetime


class SessionData(TypedDict):
    id: int
    target: str
    title: str
    status: str
    labels: list[str]
    notes: list[SessionNoteData]
    events: list[SessionEventData]


class ProjectService:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.session_factory = get_session_factory(db_path)
        init_db(db_path)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def add_target(
        self,
        *,
        name: str,
        description: str | None = None,
        scope: str | None = None,
    ) -> str:
        with self.session() as db_session:
            target = Target(name=name, description=description, scope=scope)
            db_session.add(target)
            db_session.flush()
            return name

    def list_targets(self) -> list[dict[str, str | None]]:
        with self.session() as db_session:
            targets = db_session.execute(select(Target).order_by(Target.name)).scalars().all()
            return [
                {"name": target.name, "description": target.description, "scope": target.scope}
                for target in targets
            ]

    def use_target(self, name: str) -> dict[str, str | None]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{name}' does not exist")
            return {"name": target.name, "description": target.description, "scope": target.scope}

    def get_target(self, name: str) -> dict[str, str | None] | None:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == name)
            ).scalar_one_or_none()
            if target is None:
                return None
            return {"name": target.name, "description": target.description, "scope": target.scope}

    def add_auth_profile(
        self,
        *,
        target_name: str,
        name: str,
        auth_type: str,
        secret_ref: str,
        role: str = "custom",
        expires_at: datetime | None = None,
    ) -> int:
        if role not in {"anonymous", "user", "admin", "custom"}:
            raise ValueError("Auth profile role must be anonymous, user, admin, or custom")
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValueError("Auth profile expiration must include a timezone")
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            profile = AuthProfile(
                target_id=target.id,
                name=name,
                auth_type=auth_type,
                secret_ref=secret_ref,
                role=role,
                expires_at=expires_at,
            )
            db_session.add(profile)
            db_session.flush()
            return profile.id

    def list_auth_profiles(self, *, target_name: str) -> list[dict[str, object]]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                return []
            profiles = (
                db_session.execute(
                    select(AuthProfile)
                    .where(AuthProfile.target_id == target.id, AuthProfile.enabled.is_(True))
                    .order_by(AuthProfile.name)
                )
                .scalars()
                .all()
            )
            return [
                {
                    "id": profile.id,
                    "name": profile.name,
                    "auth_type": profile.auth_type,
                    "role": profile.role,
                    "secret_ref": profile.secret_ref,
                    "expires_at": profile.expires_at,
                }
                for profile in profiles
            ]

    def get_auth_profile(self, *, target_name: str, name: str) -> dict[str, object] | None:
        with self.session() as db_session:
            profile = db_session.execute(
                select(AuthProfile)
                .join(Target)
                .where(
                    Target.name == target_name,
                    AuthProfile.name == name,
                    AuthProfile.enabled.is_(True),
                )
            ).scalar_one_or_none()
            if profile is None:
                return None
            return {
                "id": profile.id,
                "name": profile.name,
                "auth_type": profile.auth_type,
                "role": profile.role,
                "secret_ref": profile.secret_ref,
                "expires_at": profile.expires_at,
            }

    def auth_profile_exists(self, *, target_name: str, name: str) -> bool:
        with self.session() as db_session:
            profile_id = db_session.execute(
                select(AuthProfile.id)
                .join(Target)
                .where(Target.name == target_name, AuthProfile.name == name)
            ).scalar_one_or_none()
            return profile_id is not None

    def disable_auth_profile(self, *, target_name: str, name: str) -> dict[str, object]:
        with self.session() as db_session:
            profile = db_session.execute(
                select(AuthProfile)
                .join(Target)
                .where(Target.name == target_name, AuthProfile.name == name)
            ).scalar_one_or_none()
            if profile is None:
                raise ValueError(f"Authentication profile '{name}' does not exist")
            profile.enabled = False
            return {"name": profile.name, "secret_ref": profile.secret_ref}

    def add_evidence(
        self,
        *,
        target_name: str,
        source: str,
        kind: str,
        content: str,
        session_id: int | None = None,
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            self._validate_session(db_session, session_id, target.id)
            evidence = Evidence(
                target_id=target.id,
                session_id=session_id,
                source=source,
                kind=kind,
                content=redact_secrets(content),
            )
            db_session.add(evidence)
            db_session.flush()
            return evidence.id

    def list_evidence(self, *, target_name: str) -> list[dict[str, str | int]]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                return []
            evidence_items = (
                db_session.execute(
                    select(Evidence)
                    .where(Evidence.target_id == target.id)
                    .order_by(Evidence.created_at, Evidence.id)
                )
                .scalars()
                .all()
            )
            return [
                {
                    "id": item.id,
                    "source": item.source,
                    "kind": item.kind,
                    "content": item.content,
                }
                for item in evidence_items
            ]

    def add_tool_execution(
        self,
        *,
        target_name: str,
        tool_name: str,
        arguments: dict[str, object],
        status: str,
        approved: bool,
        output: str | None = None,
        error: str | None = None,
        duration_ms: int | None = None,
        session_id: int | None = None,
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            self._validate_session(db_session, session_id, target.id)
            execution = ToolExecution(
                target_id=target.id,
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
                status=status,
                approved=approved,
                output=output,
                error=error,
                duration_ms=duration_ms,
            )
            db_session.add(execution)
            db_session.flush()
            return execution.id

    def list_tool_executions(self, *, target_name: str) -> list[dict[str, object]]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                return []
            executions = (
                db_session.execute(
                    select(ToolExecution)
                    .where(ToolExecution.target_id == target.id)
                    .order_by(ToolExecution.created_at, ToolExecution.id)
                )
                .scalars()
                .all()
            )
            return [
                {
                    "id": execution.id,
                    "session_id": execution.session_id,
                    "tool_name": execution.tool_name,
                    "arguments": execution.arguments,
                    "status": execution.status,
                    "approved": execution.approved,
                    "duration_ms": execution.duration_ms,
                    "error": execution.error,
                }
                for execution in executions
            ]

    def get_context_data(self, *, target_name: str) -> dict[str, str]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            evidence_items = (
                db_session.execute(
                    select(Evidence)
                    .where(Evidence.target_id == target.id)
                    .order_by(Evidence.created_at, Evidence.id)
                )
                .scalars()
                .all()
            )
            findings = (
                db_session.execute(
                    select(Finding)
                    .where(Finding.target_id == target.id)
                    .order_by(Finding.created_at, Finding.id)
                )
                .scalars()
                .all()
            )
            observations = (
                db_session.execute(
                    select(Observation)
                    .where(Observation.target_id == target.id)
                    .order_by(Observation.created_at, Observation.id)
                )
                .scalars()
                .all()
            )
            hypotheses = (
                db_session.execute(
                    select(Hypothesis)
                    .where(Hypothesis.target_id == target.id)
                    .order_by(Hypothesis.created_at, Hypothesis.id)
                )
                .scalars()
                .all()
            )
            return {
                "target": target.name,
                "scope": target.scope or "",
                "assets": "\n".join(f"- {asset.kind}: {asset.value}" for asset in target.assets),
                "endpoints": "\n".join(
                    f"- {endpoint.method} {endpoint.url}" for endpoint in target.endpoints
                ),
                "evidence": "\n\n".join(
                    f"[{item.kind}] {item.source}\n{item.content}" for item in evidence_items
                ),
                "previous_findings": "\n".join(
                    f"- [{finding.severity}] {finding.title}: {finding.summary}"
                    for finding in findings
                ),
                "observations": "\n".join(
                    f"- O-{observation.id:03d}: {observation.summary}"
                    for observation in observations
                ),
                "hypotheses": "\n".join(
                    f"- H-{hypothesis.id:03d} [{hypothesis.status}, {hypothesis.confidence}]: "
                    f"{hypothesis.statement}"
                    for hypothesis in hypotheses
                ),
            }

    def search_artifacts(
        self,
        query: str,
        *,
        target_name: str | None = None,
        artifact_type: str | None = None,
        session_id: int | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, object]]:
        tokens = re.findall(r"[\w.-]+", query, flags=re.UNICODE)
        if not tokens:
            raise ValueError("Search query must contain at least one searchable term")
        if not 1 <= limit <= 100:
            raise ValueError("Search result limit must be between 1 and 100")
        fts_query = " AND ".join(f'"{token}"' for token in tokens)
        clauses = ["search_index MATCH :query"]
        params: dict[str, object] = {"query": fts_query, "limit": limit}
        for field, value in (
            ("target_name", target_name),
            ("artifact_type", artifact_type),
            ("session_id", session_id),
            ("status", status),
            ("severity", severity),
        ):
            if value is not None:
                clauses.append(f"search_index.{field} = :{field}")
                params[field] = value
        statement = text(
            "SELECT artifact_type, artifact_id, target_name, session_id, status, severity, "
            "title, snippet(search_index, -1, '[', ']', '…', 18) AS snippet "
            "FROM search_index WHERE "
            + " AND ".join(clauses)
            + " ORDER BY bm25(search_index) LIMIT :limit"
        )
        with self.session() as db_session:
            rows = db_session.execute(statement, params).mappings().all()
            return [
                {
                    "type": row["artifact_type"],
                    "id": row["artifact_id"],
                    "target": row["target_name"],
                    "session_id": row["session_id"],
                    "status": row["status"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "snippet": row["snippet"],
                }
                for row in rows
            ]

    def rebuild_search_index(self) -> int:
        with self.session() as db_session:
            db_session.execute(text("INSERT INTO search_index(search_index) VALUES ('rebuild')"))
            result = db_session.execute(text("SELECT count(*) FROM search_documents"))
            return int(result.scalar_one())

    def add_observation(
        self,
        *,
        target_name: str,
        summary: str,
        evidence_id: int | None = None,
        tool_execution_id: int | None = None,
        session_id: int | None = None,
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            self._validate_session(db_session, session_id, target.id)
            if evidence_id is not None and db_session.get(Evidence, evidence_id) is None:
                raise ValueError(f"Evidence E-{evidence_id:03d} does not exist")
            if (
                tool_execution_id is not None
                and db_session.get(ToolExecution, tool_execution_id) is None
            ):
                raise ValueError(f"Tool execution T-{tool_execution_id:03d} does not exist")
            observation = Observation(
                target_id=target.id,
                session_id=session_id,
                summary=summary,
                evidence_id=evidence_id,
                tool_execution_id=tool_execution_id,
            )
            db_session.add(observation)
            db_session.flush()
            return observation.id

    def list_observations(self, *, target_name: str) -> list[dict[str, object]]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                return []
            observations = (
                db_session.execute(
                    select(Observation)
                    .where(Observation.target_id == target.id)
                    .order_by(Observation.created_at, Observation.id)
                )
                .scalars()
                .all()
            )
            return [
                {
                    "id": item.id,
                    "summary": item.summary,
                    "evidence_id": item.evidence_id,
                    "tool_execution_id": item.tool_execution_id,
                }
                for item in observations
            ]

    def add_hypothesis(
        self,
        *,
        target_name: str,
        statement: str,
        status: str = "open",
        confidence: str = "unknown",
        evidence_id: int | None = None,
        observation_id: int | None = None,
        session_id: int | None = None,
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            self._validate_session(db_session, session_id, target.id)
            if evidence_id is not None and db_session.get(Evidence, evidence_id) is None:
                raise ValueError(f"Evidence E-{evidence_id:03d} does not exist")
            if observation_id is not None and db_session.get(Observation, observation_id) is None:
                raise ValueError(f"Observation O-{observation_id:03d} does not exist")
            hypothesis = Hypothesis(
                target_id=target.id,
                session_id=session_id,
                statement=statement,
                status=status,
                confidence=confidence,
                evidence_id=evidence_id,
                observation_id=observation_id,
            )
            db_session.add(hypothesis)
            db_session.flush()
            return hypothesis.id

    def list_hypotheses(self, *, target_name: str) -> list[dict[str, object]]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                return []
            hypotheses = (
                db_session.execute(
                    select(Hypothesis)
                    .where(Hypothesis.target_id == target.id)
                    .order_by(Hypothesis.created_at, Hypothesis.id)
                )
                .scalars()
                .all()
            )
            return [
                {
                    "id": item.id,
                    "statement": item.statement,
                    "status": item.status,
                    "confidence": item.confidence,
                    "evidence_id": item.evidence_id,
                    "observation_id": item.observation_id,
                }
                for item in hypotheses
            ]

    def update_hypothesis(
        self, hypothesis_id: int, *, status: str, confidence: str | None = None
    ) -> None:
        with self.session() as db_session:
            hypothesis = db_session.get(Hypothesis, hypothesis_id)
            if hypothesis is None:
                raise ValueError(f"Hypothesis H-{hypothesis_id:03d} does not exist")
            hypothesis.status = status
            if confidence is not None:
                hypothesis.confidence = confidence

    def add_finding(
        self,
        *,
        target_name: str,
        title: str,
        summary: str,
        severity: str = "info",
        status: str = "draft",
        confidence: str = "unknown",
        impact: str = "",
        reproduction: str = "",
        remediation: str = "",
        evidence_ids: list[int] | None = None,
        observation_ids: list[int] | None = None,
        hypothesis_ids: list[int] | None = None,
        execution_ids: list[int] | None = None,
        session_id: int | None = None,
    ) -> int:
        if status != "draft":
            raise ValueError("New findings must start in 'draft' and pass human review")
        if severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError(f"Unsupported severity '{severity}'")
        if confidence not in {"unknown", "low", "medium", "high"}:
            raise ValueError(f"Unsupported confidence '{confidence}'")
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            self._validate_session(db_session, session_id, target.id)
            evidence = self._related_items(
                db_session, Evidence, evidence_ids or [], target.id, "Evidence"
            )
            observations = self._related_items(
                db_session, Observation, observation_ids or [], target.id, "Observation"
            )
            hypotheses = self._related_items(
                db_session, Hypothesis, hypothesis_ids or [], target.id, "Hypothesis"
            )
            executions = self._related_items(
                db_session, ToolExecution, execution_ids or [], target.id, "Tool execution"
            )
            finding = Finding(
                target_id=target.id,
                session_id=session_id,
                title=title,
                summary=summary,
                severity=severity,
                status=status,
                confidence=confidence,
                impact=impact,
                reproduction=reproduction,
                remediation=remediation,
                evidence=evidence,
                observations=observations,
                hypotheses=hypotheses,
                executions=executions,
            )
            db_session.add(finding)
            db_session.flush()
            return finding.id

    def add_imported_findings(
        self,
        *,
        target_name: str,
        imported: list[ImportedFindingInput],
        session_id: int | None = None,
    ) -> list[int]:
        supported_severities = {"info", "low", "medium", "high", "critical"}
        if any(item["severity"] not in supported_severities for item in imported):
            raise ValueError("Imported findings contain an unsupported severity")
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            self._validate_session(db_session, session_id, target.id)
            finding_ids: list[int] = []
            for item in imported:
                evidence = Evidence(
                    target_id=target.id,
                    session_id=session_id,
                    source=item["evidence_source"],
                    kind=item["evidence_kind"],
                    content=redact_secrets(item["evidence_content"]),
                )
                finding = Finding(
                    target_id=target.id,
                    session_id=session_id,
                    title=item["title"],
                    summary=item["summary"],
                    severity=item["severity"],
                    status="draft",
                    confidence="unknown",
                    evidence=[evidence],
                )
                db_session.add(finding)
                db_session.flush()
                finding_ids.append(finding.id)
            return finding_ids

    def list_findings(self, *, target_name: str | None = None) -> list[FindingSummary]:
        with self.session() as db_session:
            statement = select(Finding)
            if target_name:
                target = db_session.execute(
                    select(Target).where(Target.name == target_name)
                ).scalar_one_or_none()
                if target is None:
                    return []
                statement = statement.where(Finding.target_id == target.id)
            statement = statement.order_by(Finding.created_at.desc())
            findings = db_session.execute(statement).scalars().all()
            return [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "summary": finding.summary,
                    "confidence": finding.confidence,
                }
                for finding in findings
            ]

    def get_finding(self, finding_id: int) -> FindingData:
        with self.session() as db_session:
            finding = db_session.get(Finding, finding_id)
            if finding is None:
                raise ValueError(f"Finding F-{finding_id:03d} does not exist")
            return self._finding_data(finding)

    def update_finding(
        self,
        finding_id: int,
        *,
        status: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
        impact: str | None = None,
        reproduction: str | None = None,
        remediation: str | None = None,
    ) -> None:
        allowed_statuses = {"draft", "in_review", "accepted", "rejected", "reported"}
        transitions = {
            "draft": {"in_review"},
            "in_review": {"draft"},
            "accepted": {"in_review", "reported"},
            "rejected": {"draft", "in_review"},
            "reported": set(),
        }
        allowed_severities = {"info", "low", "medium", "high", "critical"}
        allowed_confidence = {"unknown", "low", "medium", "high"}
        with self.session() as db_session:
            finding = db_session.get(Finding, finding_id)
            if finding is None:
                raise ValueError(f"Finding F-{finding_id:03d} does not exist")
            if status is not None:
                if status not in allowed_statuses:
                    raise ValueError(f"Unsupported finding status '{status}'")
                if status in {"accepted", "rejected"}:
                    raise ValueError("Use the human review command to accept or reject a finding")
                if status != finding.status and status not in transitions[finding.status]:
                    raise ValueError(
                        f"Finding cannot transition from '{finding.status}' to '{status}'"
                    )
                finding.status = status
            if severity is not None:
                if severity not in allowed_severities:
                    raise ValueError(f"Unsupported severity '{severity}'")
                finding.severity = severity
            if confidence is not None:
                if confidence not in allowed_confidence:
                    raise ValueError(f"Unsupported confidence '{confidence}'")
                finding.confidence = confidence
            for field, value in (
                ("impact", impact),
                ("reproduction", reproduction),
                ("remediation", remediation),
            ):
                if value is not None:
                    setattr(finding, field, value)

    def review_finding(
        self,
        finding_id: int,
        *,
        decision: str,
        note: str = "",
        reviewer: str = "human",
    ) -> None:
        if decision not in {"accepted", "rejected"}:
            raise ValueError("Review decision must be 'accepted' or 'rejected'")
        with self.session() as db_session:
            finding = db_session.get(Finding, finding_id)
            if finding is None:
                raise ValueError(f"Finding F-{finding_id:03d} does not exist")
            if finding.status != "in_review":
                raise ValueError("Finding must be in 'in_review' before it can be reviewed")
            finding.status = decision
            finding.reviews.append(
                FindingReview(
                    decision=decision,
                    note=redact_secrets(note),
                    reviewer=reviewer,
                )
            )

    def report_findings(
        self,
        *,
        target_name: str | None = None,
        finding_id: int | None = None,
        include_drafts: bool = False,
    ) -> list[FindingData]:
        with self.session() as db_session:
            statement = select(Finding).join(Target)
            if finding_id is not None:
                statement = statement.where(Finding.id == finding_id)
            if target_name is not None:
                statement = statement.where(Target.name == target_name)
            reportable_statuses = (
                ("accepted", "reported", "draft")
                if include_drafts
                else (
                    "accepted",
                    "reported",
                )
            )
            if include_drafts:
                statement = statement.where(Finding.status.in_(reportable_statuses))
            else:
                statement = statement.where(Finding.status.in_(("accepted", "reported")))
            findings = db_session.execute(statement.order_by(Finding.id)).scalars().all()
            if finding_id is not None and not findings:
                existing = db_session.get(Finding, finding_id)
                if existing is None:
                    raise ValueError(f"Finding F-{finding_id:03d} does not exist")
                if existing.status == "draft" and not include_drafts:
                    raise ValueError("Draft findings require explicit --include-drafts")
                raise ValueError(
                    "Only accepted or explicitly included draft findings can be reported"
                )
            return [self._finding_data(finding) for finding in findings]

    def create_session(self, *, target_name: str, title: str) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            session = InvestigationSession(target_id=target.id, title=title, status="active")
            db_session.add(session)
            db_session.flush()
            return session.id

    def update_session_labels(self, session_id: int, labels: list[str]) -> None:
        normalized = list(dict.fromkeys(label.strip() for label in labels if label.strip()))
        if len(normalized) > 32 or any(len(label) > 64 for label in normalized):
            raise ValueError("Sessions support up to 32 labels, each no longer than 64 characters")
        with self.session() as db_session:
            session = db_session.get(InvestigationSession, session_id)
            if session is None:
                raise ValueError(f"Session S-{session_id:03d} does not exist")
            session.labels = normalized
            session.updated_at = utc_now()

    def list_sessions(self, *, target_name: str) -> list[SessionSummary]:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            sessions = (
                db_session.execute(
                    select(InvestigationSession)
                    .where(InvestigationSession.target_id == target.id)
                    .order_by(InvestigationSession.updated_at.desc())
                )
                .scalars()
                .all()
            )
            return [
                {
                    "id": item.id,
                    "title": item.title,
                    "status": item.status,
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                    "labels": item.labels,
                }
                for item in sessions
            ]

    def get_session(self, session_id: int) -> SessionData:
        with self.session() as db_session:
            session = db_session.get(InvestigationSession, session_id)
            if session is None:
                raise ValueError(f"Session S-{session_id:03d} does not exist")
            return {
                "id": session.id,
                "target": session.target.name,
                "title": session.title,
                "status": session.status,
                "labels": session.labels,
                "notes": [
                    {"content": note.content, "created_at": note.created_at}
                    for note in session.notes
                ],
                "events": [
                    {
                        "type": event.event_type,
                        "content": event.content,
                        "details": event.details,
                        "created_at": event.created_at,
                    }
                    for event in session.events
                ],
            }

    def prune_sessions(
        self,
        *,
        before: datetime,
        target_name: str | None = None,
        statuses: tuple[str, ...] = ("closed",),
    ) -> list[int]:
        if before.tzinfo is None:
            raise ValueError("Retention cutoff must include a timezone")
        if not statuses or any(status not in {"paused", "closed"} for status in statuses):
            raise ValueError("Retention can only remove paused or closed sessions")
        cutoff = before.astimezone(UTC).replace(tzinfo=None)
        with self.session() as db_session:
            statement = select(InvestigationSession).where(
                InvestigationSession.status.in_(statuses),
                InvestigationSession.updated_at < cutoff,
            )
            if target_name is not None:
                statement = statement.join(Target).where(Target.name == target_name)
            sessions = db_session.execute(statement).scalars().all()
            removed_ids = [item.id for item in sessions]
            for item in sessions:
                for artifact_model in (
                    Evidence,
                    ToolExecution,
                    Observation,
                    Hypothesis,
                    Finding,
                ):
                    db_session.execute(
                        sa_update(artifact_model)
                        .where(artifact_model.session_id == item.id)
                        .values(session_id=None)
                    )
                db_session.execute(delete(Note).where(Note.session_id == item.id))
                db_session.execute(delete(SessionEvent).where(SessionEvent.session_id == item.id))
                for association in (
                    finding_evidence,
                    finding_executions,
                    finding_hypotheses,
                    finding_observations,
                ):
                    db_session.execute(
                        delete(association).where(
                            association.c.finding_id.in_(
                                select(Finding.id).where(Finding.session_id == item.id)
                            )
                        )
                    )
                db_session.delete(item)
            return removed_ids

    def search_corpus(
        self,
        *,
        target_name: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Search corpus limit must be between 1 and 10000")
        statement = (
            "SELECT artifact_type, artifact_id, target_name, session_id, status, severity, "
            "title, body FROM search_documents"
        )
        params: dict[str, object] = {"limit": limit}
        if target_name is not None:
            statement += " WHERE target_name = :target_name"
            params["target_name"] = target_name
        statement += " ORDER BY id LIMIT :limit"
        with self.session() as db_session:
            return [
                dict(row) for row in db_session.execute(text(statement), params).mappings().all()
            ]

    def set_session_status(self, session_id: int, *, status: str) -> None:
        if status not in {"active", "paused", "closed"}:
            raise ValueError(f"Unsupported session status '{status}'")
        with self.session() as db_session:
            session = db_session.get(InvestigationSession, session_id)
            if session is None:
                raise ValueError(f"Session S-{session_id:03d} does not exist")
            session.status = status
            session.updated_at = utc_now()

    def add_session_note(self, session_id: int, *, content: str) -> int:
        with self.session() as db_session:
            session = db_session.get(InvestigationSession, session_id)
            if session is None:
                raise ValueError(f"Session S-{session_id:03d} does not exist")
            if session.status != "active":
                raise ValueError("Notes can only be added to an active session")
            note = Note(session_id=session_id, content=redact_secrets(content))
            db_session.add(note)
            session.updated_at = utc_now()
            db_session.flush()
            return note.id

    def add_session_event(
        self,
        session_id: int,
        *,
        event_type: str,
        content: str,
        details: dict[str, object] | None = None,
        secret_values: tuple[str, ...] = (),
    ) -> int:
        from bbai.auth.redaction import redact_secrets

        with self.session() as db_session:
            session = db_session.get(InvestigationSession, session_id)
            if session is None:
                raise ValueError(f"Session S-{session_id:03d} does not exist")
            if session.status != "active":
                raise ValueError("Only active sessions can record investigation events")
            serialized_details = json.dumps(details or {}, ensure_ascii=False)
            safe_details = json.loads(redact_secrets(serialized_details, secret_values))
            event = SessionEvent(
                session_id=session_id,
                event_type=event_type,
                content=redact_secrets(content, secret_values),
                details=safe_details,
            )
            db_session.add(event)
            session.updated_at = utc_now()
            db_session.flush()
            return event.id

    @staticmethod
    def _validate_session(
        db_session: Session,
        session_id: int | None,
        target_id: int,
    ) -> None:
        if session_id is None:
            return
        session = db_session.get(InvestigationSession, session_id)
        if session is None:
            raise ValueError(f"Session S-{session_id:03d} does not exist")
        if session.target_id != target_id:
            raise ValueError("Session and artifact must belong to the same target")
        if session.status != "active":
            raise ValueError("Artifacts can only be added to an active session")

    @staticmethod
    def _related_items(
        db_session: Session,
        model: type[ModelT],
        identifiers: list[int],
        target_id: int,
        label: str,
    ) -> list[ModelT]:
        items: list[ModelT] = []
        for identifier in dict.fromkeys(identifiers):
            item = db_session.get(model, identifier)
            if item is None or item.target_id != target_id:
                raise ValueError(f"{label} {identifier} does not exist for this target")
            items.append(item)
        return items

    @staticmethod
    def _finding_data(finding: Finding) -> FindingData:
        return {
            "id": finding.id,
            "target": finding.target.name,
            "title": finding.title,
            "summary": finding.summary,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "impact": finding.impact,
            "reproduction": finding.reproduction,
            "remediation": finding.remediation,
            "status": finding.status,
            "session_id": finding.session_id,
            "session_title": finding.session.title if finding.session is not None else None,
            "auth_profiles": (
                [
                    event.content
                    for event in finding.session.events
                    if event.event_type == "auth_profile"
                ]
                if finding.session is not None
                else []
            ),
            "evidence": [
                {
                    "id": item.id,
                    "source": item.source,
                    "kind": item.kind,
                    "content": item.content,
                }
                for item in finding.evidence
            ],
            "observations": [
                {"id": item.id, "summary": item.summary} for item in finding.observations
            ],
            "hypotheses": [
                {
                    "id": item.id,
                    "statement": item.statement,
                    "status": item.status,
                    "confidence": item.confidence,
                }
                for item in finding.hypotheses
            ],
            "executions": [
                {
                    "id": item.id,
                    "tool_name": item.tool_name,
                    "status": item.status,
                }
                for item in finding.executions
            ],
            "reviews": [
                {
                    "decision": item.decision,
                    "note": item.note,
                    "reviewer": item.reviewer,
                    "created_at": item.created_at.isoformat(),
                }
                for item in finding.reviews
            ],
        }
