from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, ForeignKey, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bbai.db import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


finding_evidence = Table(
    "finding_evidence",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id"), primary_key=True),
    Column("evidence_id", ForeignKey("evidence.id"), primary_key=True),
)
finding_observations = Table(
    "finding_observations",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id"), primary_key=True),
    Column("observation_id", ForeignKey("observations.id"), primary_key=True),
)
finding_hypotheses = Table(
    "finding_hypotheses",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id"), primary_key=True),
    Column("hypothesis_id", ForeignKey("hypotheses.id"), primary_key=True),
)
finding_executions = Table(
    "finding_executions",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id"), primary_key=True),
    Column("execution_id", ForeignKey("tool_executions.id"), primary_key=True),
)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    assets: Mapped[list[Asset]] = relationship(back_populates="target")
    endpoints: Mapped[list[Endpoint]] = relationship(back_populates="target")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="target")
    observations: Mapped[list[Observation]] = relationship(back_populates="target")
    hypotheses: Mapped[list[Hypothesis]] = relationship(back_populates="target")
    findings: Mapped[list[Finding]] = relationship(back_populates="target")
    sessions: Mapped[list[Session]] = relationship(back_populates="target")
    auth_profiles: Mapped[list[AuthProfile]] = relationship(back_populates="target")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="assets")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="endpoints")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="evidence")
    session: Mapped[Session | None] = relationship(back_populates="evidence")


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    approved: Mapped[bool] = mapped_column(default=False, nullable=False)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship()
    session: Mapped[Session | None] = relationship(back_populates="tool_executions")


class AuthProfile(Base):
    __tablename__ = "auth_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(30), nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="custom", nullable=False)
    secret_ref: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="auth_profiles")


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    tool_execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("tool_executions.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="observations")
    session: Mapped[Session | None] = relationship(back_populates="observations")


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    observation_id: Mapped[int | None] = mapped_column(ForeignKey("observations.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="hypotheses")
    session: Mapped[Session | None] = relationship(back_populates="hypotheses")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reproduction: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="draft", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now, nullable=False
    )

    target: Mapped[Target] = relationship(back_populates="findings")
    session: Mapped[Session | None] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(secondary=finding_evidence)
    observations: Mapped[list[Observation]] = relationship(secondary=finding_observations)
    hypotheses: Mapped[list[Hypothesis]] = relationship(secondary=finding_hypotheses)
    executions: Mapped[list[ToolExecution]] = relationship(secondary=finding_executions)
    reviews: Mapped[list[FindingReview]] = relationship(
        back_populates="finding", order_by="FindingReview.created_at"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    labels: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    target: Mapped[Target] = relationship(back_populates="sessions")
    notes: Mapped[list[Note]] = relationship(back_populates="session")
    events: Mapped[list[SessionEvent]] = relationship(
        back_populates="session", order_by="SessionEvent.created_at"
    )
    evidence: Mapped[list[Evidence]] = relationship(back_populates="session")
    tool_executions: Mapped[list[ToolExecution]] = relationship(back_populates="session")
    observations: Mapped[list[Observation]] = relationship(back_populates="session")
    hypotheses: Mapped[list[Hypothesis]] = relationship(back_populates="session")
    findings: Mapped[list[Finding]] = relationship(back_populates="session")


class SessionEvent(Base):
    __tablename__ = "session_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    session: Mapped[Session] = relationship(back_populates="events")


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    session: Mapped[Session] = relationship(back_populates="notes")


class FindingReview(Base):
    __tablename__ = "finding_reviews"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reviewer: Mapped[str] = mapped_column(String(100), default="human", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="reviews")
