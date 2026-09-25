from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from bbai.db import get_session_factory, init_db
from bbai.models import (
    AuthProfile,
    Evidence,
    Finding,
    Hypothesis,
    Observation,
    Target,
    ToolExecution,
)


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
            target = db_session.execute(select(Target).where(Target.name == name)).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{name}' does not exist")
            return {"name": target.name, "description": target.description, "scope": target.scope}

    def get_target(self, name: str) -> dict[str, str | None] | None:
        with self.session() as db_session:
            target = db_session.execute(select(Target).where(Target.name == name)).scalar_one_or_none()
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
        expires_at: datetime | None = None,
    ) -> int:
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
            profiles = db_session.execute(
                select(AuthProfile)
                .where(AuthProfile.target_id == target.id, AuthProfile.enabled.is_(True))
                .order_by(AuthProfile.name)
            ).scalars().all()
            return [
                {
                    "id": profile.id,
                    "name": profile.name,
                    "auth_type": profile.auth_type,
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
                .where(Target.name == target_name, AuthProfile.name == name, AuthProfile.enabled.is_(True))
            ).scalar_one_or_none()
            if profile is None:
                return None
            return {
                "id": profile.id,
                "name": profile.name,
                "auth_type": profile.auth_type,
                "secret_ref": profile.secret_ref,
                "expires_at": profile.expires_at,
            }

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
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(select(Target).where(Target.name == target_name)).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            evidence = Evidence(
                target_id=target.id,
                source=source,
                kind=kind,
                content=content,
            )
            db_session.add(evidence)
            db_session.flush()
            return evidence.id

    def list_evidence(self, *, target_name: str) -> list[dict[str, str | int]]:
        with self.session() as db_session:
            target = db_session.execute(select(Target).where(Target.name == target_name)).scalar_one_or_none()
            if target is None:
                return []
            evidence_items = db_session.execute(
                select(Evidence)
                .where(Evidence.target_id == target.id)
                .order_by(Evidence.created_at, Evidence.id)
            ).scalars().all()
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
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            execution = ToolExecution(
                target_id=target.id,
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
            executions = db_session.execute(
                select(ToolExecution)
                .where(ToolExecution.target_id == target.id)
                .order_by(ToolExecution.created_at, ToolExecution.id)
            ).scalars().all()
            return [
                {
                    "id": execution.id,
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
            target = db_session.execute(select(Target).where(Target.name == target_name)).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            evidence_items = db_session.execute(
                select(Evidence)
                .where(Evidence.target_id == target.id)
                .order_by(Evidence.created_at, Evidence.id)
            ).scalars().all()
            findings = db_session.execute(
                select(Finding)
                .where(Finding.target_id == target.id)
                .order_by(Finding.created_at, Finding.id)
            ).scalars().all()
            observations = db_session.execute(
                select(Observation)
                .where(Observation.target_id == target.id)
                .order_by(Observation.created_at, Observation.id)
            ).scalars().all()
            hypotheses = db_session.execute(
                select(Hypothesis)
                .where(Hypothesis.target_id == target.id)
                .order_by(Hypothesis.created_at, Hypothesis.id)
            ).scalars().all()
            return {
                "target": target.name,
                "scope": target.scope or "",
                "assets": "\n".join(
                    f"- {asset.kind}: {asset.value}" for asset in target.assets
                ),
                "endpoints": "\n".join(
                    f"- {endpoint.method} {endpoint.url}" for endpoint in target.endpoints
                ),
                "evidence": "\n\n".join(
                    f"[{item.kind}] {item.source}\n{item.content}" for item in evidence_items
                ),
                "previous_findings": "\n".join(
                    f"- [{finding.severity}] {finding.title}: {finding.summary}" for finding in findings
                ),
                "observations": "\n".join(
                    f"- O-{observation.id:03d}: {observation.summary}" for observation in observations
                ),
                "hypotheses": "\n".join(
                    f"- H-{hypothesis.id:03d} [{hypothesis.status}, {hypothesis.confidence}]: "
                    f"{hypothesis.statement}"
                    for hypothesis in hypotheses
                ),
            }

    def add_observation(
        self,
        *,
        target_name: str,
        summary: str,
        evidence_id: int | None = None,
        tool_execution_id: int | None = None,
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            if evidence_id is not None and db_session.get(Evidence, evidence_id) is None:
                raise ValueError(f"Evidence E-{evidence_id:03d} does not exist")
            if tool_execution_id is not None and db_session.get(ToolExecution, tool_execution_id) is None:
                raise ValueError(f"Tool execution T-{tool_execution_id:03d} does not exist")
            observation = Observation(
                target_id=target.id,
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
            observations = db_session.execute(
                select(Observation)
                .where(Observation.target_id == target.id)
                .order_by(Observation.created_at, Observation.id)
            ).scalars().all()
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
    ) -> int:
        with self.session() as db_session:
            target = db_session.execute(
                select(Target).where(Target.name == target_name)
            ).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            if evidence_id is not None and db_session.get(Evidence, evidence_id) is None:
                raise ValueError(f"Evidence E-{evidence_id:03d} does not exist")
            if observation_id is not None and db_session.get(Observation, observation_id) is None:
                raise ValueError(f"Observation O-{observation_id:03d} does not exist")
            hypothesis = Hypothesis(
                target_id=target.id,
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
            hypotheses = db_session.execute(
                select(Hypothesis)
                .where(Hypothesis.target_id == target.id)
                .order_by(Hypothesis.created_at, Hypothesis.id)
            ).scalars().all()
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

    def update_hypothesis(self, hypothesis_id: int, *, status: str, confidence: str | None = None) -> None:
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
    ) -> Finding:
        with self.session() as db_session:
            target = db_session.execute(select(Target).where(Target.name == target_name)).scalar_one_or_none()
            if target is None:
                raise ValueError(f"Target '{target_name}' does not exist")
            finding = Finding(
                target_id=target.id,
                title=title,
                summary=summary,
                severity=severity,
                status=status,
            )
            db_session.add(finding)
            db_session.flush()
            return finding

    def list_findings(self, *, target_name: str | None = None) -> list[dict[str, str]]:
        with self.session() as db_session:
            statement = select(Finding)
            if target_name:
                target = db_session.execute(select(Target).where(Target.name == target_name)).scalar_one_or_none()
                if target is None:
                    return []
                statement = statement.where(Finding.target_id == target.id)
            statement = statement.order_by(Finding.created_at.desc())
            findings = db_session.execute(statement).scalars().all()
            return [
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "summary": finding.summary,
                }
                for finding in findings
            ]
