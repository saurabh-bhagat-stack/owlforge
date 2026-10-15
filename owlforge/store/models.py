"""SQLModel tables for the owlforge store.

Core domain, Phase 0: Assessment, Agent, Event, Finding, Report. JSON-ish fields are
stored as JSON columns. Project memory + tool-call tables arrive in later phases.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(UTC)


# Status / enum values are kept as plain strings (validated at the edges) so the
# schema stays flexible while the state machine is still settling.

class Assessment(SQLModel, table=True):
    """One scoped, autonomous assessment run against a target."""

    id: str = Field(primary_key=True)
    project_name: str
    target: str
    instructions: str
    scan_mode: str = "standard"  # quick | standard | deep
    status: str = "created"      # created|planning|executing|validating|reporting|completed|failed|stopped
    root_agent_id: str | None = None
    report_status: str = "pending"
    error: str | None = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None


class Agent(SQLModel, table=True):
    id: str = Field(primary_key=True)
    assessment_id: str = Field(index=True)
    parent_id: str | None = None
    name: str = ""
    task: str = ""
    skills: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    status: str = "queued"
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class Event(SQLModel, table=True):
    id: str = Field(primary_key=True)
    assessment_id: str = Field(index=True)
    agent_id: str | None = None
    type: str = "log"
    message: str = ""
    data: dict = Field(default_factory=dict, sa_column=Column(JSON))
    ts: datetime = Field(default_factory=_now)


class Finding(SQLModel, table=True):
    id: str = Field(primary_key=True)
    assessment_id: str = Field(index=True)
    title: str
    severity: str = "medium"   # critical|high|medium|low|info
    status: str = "candidate"  # candidate|validated|false_positive|accepted_risk|reported
    confidence: str = "medium"
    target: str = ""
    endpoint: str | None = None
    method: str | None = None
    technical_analysis: str = ""
    proof_of_concept: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: list[dict] = Field(default_factory=list, sa_column=Column(JSON))
    # Evidence-gated validation: the agent supplies a command that reproduces the
    # finding and a signal expected in its output. The validator re-runs it.
    repro_command: str = ""
    success_signal: str = ""
    validation_note: str = ""
    filed_by_agent_id: str | None = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class Report(SQLModel, table=True):
    assessment_id: str = Field(primary_key=True)
    status: str = "pending"
    executive_summary: str = ""
    risk_rating: str = ""
    body_markdown: str = ""
    generated_at: datetime | None = None


class SurfaceItem(SQLModel, table=True):
    """One discovered attack-surface item (endpoint + its parameters)."""

    id: str = Field(primary_key=True)
    assessment_id: str = Field(index=True)
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    source: str = "link"  # link | form | seed
    created_at: datetime = Field(default_factory=_now)
