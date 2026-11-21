from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import (
    ForeignKey, Integer, String, Text, DateTime, UniqueConstraint, Boolean,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    # SQLite persists UTC datetimes as naive values; this app treats all such values as UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(180), unique=True, nullable=False)
    client: Mapped[str] = mapped_column(String(180), nullable=False, default="Synthetic organization")
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    assessments: Mapped[list["Assessment"]] = relationship(back_populates="engagement")


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    methodology: Mapped[str] = mapped_column(String(60), nullable=False, default="Penetration test")
    assessment_type: Mapped[str] = mapped_column(String(20), nullable=False, default="Hybrid")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="In progress")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    engagement: Mapped[Engagement] = relationship(back_populates="assessments")
    batches: Mapped[list["ImportBatch"]] = relationship(back_populates="assessment")


class Owner(Base):
    __tablename__ = "owners"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(254))
    asset_memberships: Mapped[list["AssetTeam"]] = relationship(back_populates="team")
    assigned_findings: Mapped[list["Finding"]] = relationship(back_populates="assigned_owner")


class DecisionMaker(Base):
    """Registered governance approver. Not automatically the remediation team owner."""
    __tablename__ = "decision_makers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(String(120), nullable=False, default="Security reviewer")
    email: Mapped[str | None] = mapped_column(String(254))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)



class Asset(Base):
    """Organization-wide asset, independent of engagements and assessment runs."""
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_key: Mapped[str] = mapped_column(String(300), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(300), nullable=False)
    external_ref: Mapped[str | None] = mapped_column(String(160))
    hostname: Mapped[str | None] = mapped_column(String(300))  # explicitly imported or analyst-confirmed DNS name
    ip_address: Mapped[str | None] = mapped_column(String(45))  # independent of source key
    service_code: Mapped[str | None] = mapped_column(String(80))
    exposure: Mapped[str] = mapped_column(String(24), default="Review required", nullable=False)
    classification_source: Mapped[str] = mapped_column(String(20), default="automatic", nullable=False)
    classification_reason: Mapped[str] = mapped_column(String(300), default="No verified exposure evidence", nullable=False)
    memberships: Mapped[list["AssetTeam"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")


class AssetTeam(Base):
    """Asset stakeholders, never an automatic finding-remediation assignment."""
    __tablename__ = "asset_teams"
    __table_args__ = (UniqueConstraint("asset_id", "team_id", name="uq_asset_team"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    team_id: Mapped[int] = mapped_column(ForeignKey("owners.id"), nullable=False)
    asset: Mapped[Asset] = relationship(back_populates="memberships")
    team: Mapped[Owner] = relationship(back_populates="asset_memberships")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("source", "external_key", name="uq_source_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    external_key: Mapped[str] = mapped_column(String(280), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    cve: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    findings: Mapped[list["Finding"]] = relationship(back_populates="vulnerability")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    # Exactly one responsible remediation team for a tracked asset-vulnerability finding.
    assigned_owner_id: Mapped[int | None] = mapped_column(ForeignKey("owners.id"))
    assigned_owner: Mapped[Owner | None] = relationship(back_populates="assigned_findings")
    assignment_source: Mapped[str] = mapped_column(String(20), default="none", nullable=False)
    assignment_reason: Mapped[str] = mapped_column(String(320), default="No routing rule assigned a responsible team", nullable=False)
    # Governance workflow state is separate from technical finding status.
    workflow_state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending_triage")
    location: Mapped[str] = mapped_column(String(250), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    asset: Mapped[Asset] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")
    observations: Mapped[list["Observation"]] = relationship(back_populates="finding", order_by="Observation.id")
    decisions: Mapped[list["GovernanceDecision"]] = relationship(back_populates="finding", order_by="GovernanceDecision.id")


class ImportBatch(Base):
    __tablename__ = "import_batches"
    id: Mapped[int] = mapped_column(primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), nullable=False)
    assessment: Mapped[Assessment] = relationship(back_populates="batches")
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    observations: Mapped[list["Observation"]] = relationship(back_populates="batch")


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("batch_id", "row_hash", name="uq_batch_row"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    batch_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id"), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    finding: Mapped[Finding] = relationship(back_populates="observations")
    batch: Mapped[ImportBatch] = relationship(back_populates="observations")


class GovernanceDecision(Base):
    __tablename__ = "governance_decisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    decision_maker_id: Mapped[int | None] = mapped_column(ForeignKey("decision_makers.id"))
    decision_maker: Mapped[DecisionMaker | None] = relationship()
    decided_by: Mapped[str] = mapped_column(String(160), nullable=False)  # immutable display snapshot
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("user_accounts.id"))
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    review_date: Mapped[str | None] = mapped_column(String(10))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    finding: Mapped[Finding] = relationship(back_populates="decisions")



class GovernanceRole(Base):
    __tablename__ = "governance_roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(350), nullable=False, default="")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class RoutingRule(Base):
    """Global deterministic mapping; no engagement or user-defined priority."""
    __tablename__ = "routing_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("owners.id"), nullable=False)
    asset_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    asset_pattern: Mapped[str] = mapped_column(String(280), nullable=False, default="")
    finding_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    finding_pattern: Mapped[str] = mapped_column(String(280), nullable=False, default="")
    team: Mapped[Owner] = relationship()

class UserAccount(Base):
    __tablename__ = "user_accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(250), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)
    roles: Mapped[list["UserRole"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    sessions: Mapped[list["LoginSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class AccessRole(Base):
    """User-facing roles; permissions are editable, unlike hard-coded role claims."""
    __tablename__ = "access_roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(350), nullable=False, default="")
    permissions: Mapped[list["RolePermission"]] = relationship(back_populates="role", cascade="all, delete-orphan")
    users: Mapped[list["UserRole"]] = relationship(back_populates="role")


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("access_roles.id"), nullable=False)
    user: Mapped[UserAccount] = relationship(back_populates="roles")
    role: Mapped[AccessRole] = relationship(back_populates="users")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission", name="uq_role_permission"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("access_roles.id"), nullable=False)
    permission: Mapped[str] = mapped_column(String(80), nullable=False)
    role: Mapped[AccessRole] = relationship(back_populates="permissions")


class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    user: Mapped[UserAccount] = relationship(back_populates="sessions")


class GovernanceWorkItem(Base):
    """A task assigned to an account or a role, separate from the final governance decision."""
    __tablename__ = "governance_work_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # escalation / risk_approval / remediation_review
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    assignee_user_id: Mapped[int | None] = mapped_column(ForeignKey("user_accounts.id"), index=True)
    assignee_role_id: Mapped[int | None] = mapped_column(ForeignKey("access_roles.id"), index=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    finding: Mapped[Finding] = relationship()
    assignee_user: Mapped[UserAccount | None] = relationship(foreign_keys=[assignee_user_id])
    assignee_role: Mapped[AccessRole | None] = relationship(foreign_keys=[assignee_role_id])
    created_by: Mapped[UserAccount] = relationship(foreign_keys=[created_by_id])
    events: Mapped[list["GovernanceWorkEvent"]] = relationship(back_populates="work_item", cascade="all, delete-orphan", order_by="GovernanceWorkEvent.id")


class GovernanceWorkEvent(Base):
    __tablename__ = "governance_work_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    work_item_id: Mapped[int] = mapped_column(ForeignKey("governance_work_items.id"), nullable=False, index=True)
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False)
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str | None] = mapped_column(String(24))
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    work_item: Mapped[GovernanceWorkItem] = relationship(back_populates="events")
    actor: Mapped[UserAccount] = relationship()


class UserPreference(Base):
    __tablename__ = "user_preferences"
    user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), primary_key=True)
    theme: Mapped[str] = mapped_column(String(10), nullable=False, default="light")
    user: Mapped[UserAccount] = relationship()


class ObservationSourceMetadata(Base):
    """Additive source-provenance extension; no changes to legacy tables."""
    __tablename__ = "observation_source_metadata"
    observation_id: Mapped[int] = mapped_column(ForeignKey("observations.id"), primary_key=True)
    source_data: Mapped[str] = mapped_column(Text, nullable=False)
    observation: Mapped[Observation] = relationship()


class UserConnectorCredential(Base):
    """Encrypted integration credentials; organization record owned by bootstrap admin in v0.15."""
    __tablename__ = "user_connector_credentials"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_connector_per_user"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    user: Mapped[UserAccount] = relationship()

class ConnectorHealthCheck(Base):
    """Last explicit connector test, stored under organization connector identity."""
    __tablename__ = "connector_health_checks"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_connector_check_per_user"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class ServiceNowGroupMapping(Base):
    """Map an Arbitrator remediation team to an actual ServiceNow group sys_id."""
    __tablename__ = "servicenow_group_mappings"
    team_id: Mapped[int] = mapped_column(ForeignKey("owners.id"), primary_key=True)
    group_sys_id: Mapped[str] = mapped_column(String(32), nullable=False)
    group_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    group_email: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    team: Mapped[Owner] = relationship()


class ServiceNowIncidentLink(Base):
    """A finding may have one tracked ServiceNow incident, regardless of engagements."""
    __tablename__ = "servicenow_incident_links"
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    instance_url: Mapped[str] = mapped_column(String(255), nullable=False)
    sys_id: Mapped[str] = mapped_column(String(32), nullable=False)
    number: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(80), nullable=False, default="New")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    finding: Mapped[Finding] = relationship()


class ServiceNowSyncRecord(Base):
    """Track each successfully sent observation or governance note once."""
    __tablename__ = "servicenow_sync_records"
    __table_args__ = (UniqueConstraint("finding_id", "item_type", "item_id", name="uq_snow_sync_item"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    item_type: Mapped[str] = mapped_column(String(20), nullable=False)
    item_id: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("user_accounts.id"), nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
