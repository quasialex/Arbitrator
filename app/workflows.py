"""Human ownership and governance workflow. Independent of scanner/import adapters."""
from __future__ import annotations
from datetime import date
import ipaddress
import re
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models import Asset, AssetTeam, DecisionMaker, Finding, Owner, GovernanceDecision, UserAccount

EXPOSURES = {"Review required", "Internal", "External"}
ACTIONS = {
    "request_remediation": "remediation_requested",
    "escalate": "escalated",
    "accept_risk": "risk_accepted",
    "defer": "deferred",
}


def create_team(session: Session, name: str, email: str = "") -> Owner:
    name = name.strip()
    if not 2 <= len(name) <= 160:
        raise ValueError("Team name must contain 2–160 characters")
    if email and (len(email) > 254 or "@" not in email):
        raise ValueError("Provide a valid email address or leave it blank")
    if session.scalar(select(Owner).where(func.lower(Owner.name) == name.lower())):
        raise ValueError("A team with this name already exists")
    obj = Owner(name=name, email=email.strip() or None)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def create_decision_maker(session: Session, name: str, role: str, email: str = "") -> DecisionMaker:
    name, role = name.strip(), role.strip()
    if not 2 <= len(name) <= 160 or not 2 <= len(role) <= 120:
        raise ValueError("Decision maker name and role are required")
    if email and (len(email) > 254 or "@" not in email):
        raise ValueError("Provide a valid email address or leave it blank")
    if session.scalar(select(DecisionMaker).where(func.lower(DecisionMaker.name) == name.lower())):
        raise ValueError("A decision maker with this name already exists")
    obj = DecisionMaker(name=name, role=role, email=email.strip() or None)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def team_from_selection(session: Session, value: str) -> Owner | None:
    if value in ("", "unassigned", "inherit"):
        return None
    try:
        team_id = int(value)
    except (ValueError, TypeError):
        raise ValueError("Select a team from the list") from None
    obj = session.get(Owner, team_id)
    if obj is None:
        raise ValueError("Unknown team")
    return obj


def edit_asset(session: Session, asset_id: int, display_name: str, exposure: str,
               team_ids: list[int], external_ref: str = "", service_code: str = "",
               hostname: str | None = None, ip_address: str | None = None) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None: raise ValueError("Asset not found")
    display_name = display_name.strip()
    if not 1 <= len(display_name) <= 300: raise ValueError("Asset display name must contain 1–300 characters")
    if len(service_code) > 80 or len(external_ref) > 160: raise ValueError("Invalid service code or external reference")
    if exposure not in EXPOSURES: raise ValueError("Invalid network exposure classification")
    unique_ids = set(team_ids)
    if len(unique_ids) > 30: raise ValueError("Too many asset stakeholder teams")
    known = session.scalars(select(Owner).where(Owner.id.in_(unique_ids))).all() if unique_ids else []
    if len(known) != len(unique_ids): raise ValueError("An asset team does not exist")
    asset.display_name = display_name
    asset.exposure = exposure
    asset.classification_source = "manual"
    asset.classification_reason = "Explicitly classified by analyst"
    asset.external_ref = external_ref.strip() or None
    # The asset source key is immutable; enrichment never silently merges an IP and FQDN.
    if hostname is not None:
        host = hostname.strip().lower().rstrip(".")
        if host and (len(host) > 300 or not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)):
            raise ValueError("Provide a valid DNS hostname")
        asset.hostname = host or None
    if ip_address is not None:
        ip = ip_address.strip()
        if ip:
            try: ip = str(ipaddress.ip_address(ip))
            except ValueError: raise ValueError("Provide a valid IPv4 or IPv6 address") from None
        asset.ip_address = ip or None
    asset.service_code = service_code.strip().upper() or None
    for m in list(asset.memberships): asset.memberships.remove(m)
    session.flush()
    for t in known: asset.memberships.append(AssetTeam(team_id=t.id))
    session.commit()
    return asset


def assign_assets(session: Session, asset_ids: list[int], team_id: str) -> int:
    """Bulk-add a stakeholder team to assets; never assign finding ownership."""
    if not 1 <= len(set(asset_ids)) <= 250: raise ValueError("Select 1–250 assets")
    team = team_from_selection(session, team_id)
    if team is None: raise ValueError("Select a stakeholder team")
    assets = session.scalars(select(Asset).where(Asset.id.in_(set(asset_ids)))).all()
    if len(assets) != len(set(asset_ids)): raise ValueError("Unknown asset")
    for asset in assets:
        if not any(m.team_id == team.id for m in asset.memberships):
            asset.memberships.append(AssetTeam(team_id=team.id))
    session.commit()
    return len(assets)


def assign_finding(session: Session, finding_id: int, owner_id: str) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None: raise ValueError("Finding not found")
    team = team_from_selection(session, owner_id)
    finding.assigned_owner_id = team.id if team else None
    finding.assignment_source = "manual"  # no reimport can override this deliberate action
    finding.assignment_reason = "Assigned by analyst" if team else "Explicitly unassigned pending review"
    session.commit()
    return finding


def effective_owner(finding: Finding) -> Owner | None:
    """No implicit inheritance from asset stewardship."""
    return finding.assigned_owner


def record_decision(session: Session, finding_id: int, action: str, decision_maker_id: int,
                    rationale: str, review_date: str = "") -> GovernanceDecision:
    if action not in ACTIONS:
        raise ValueError("Choose a supported governance action")
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ValueError("Finding not found")
    # Explicit team assignment is prerequisite for accountable governance actions.
    team = finding.assigned_owner
    if team is None:
        raise ValueError("Assign a responsible remediation team to this finding first")
    approver = session.get(DecisionMaker, decision_maker_id)
    if approver is None or not approver.active:
        raise ValueError("Choose an active decision maker from the directory")
    rationale = rationale.strip()
    if not 10 <= len(rationale) <= 5000:
        raise ValueError("Decision rationale must contain 10–5000 characters")
    if review_date:
        try:
            review = date.fromisoformat(review_date)
        except ValueError:
            raise ValueError("Invalid review date") from None
        if review < date.today():
            raise ValueError("Review date cannot be in the past")
    if action in {"defer", "accept_risk"} and not review_date:
        raise ValueError("Deferral and risk acceptance require a review date")
    decision = GovernanceDecision(
        finding_id=finding.id, action=action, decision_maker_id=approver.id,
        decided_by=approver.name, rationale=rationale, review_date=review_date or None,
    )
    session.add(decision)
    finding.workflow_state = ACTIONS[action]
    # Technical status is not altered by governance decisions.
    session.commit()
    session.refresh(decision)
    return decision


def update_team(session: Session, team_id: int, name: str, email: str = "") -> Owner:
    obj = session.get(Owner, team_id)
    if obj is None:
        raise ValueError("Team not found")
    name, email = name.strip(), email.strip()
    if not 2 <= len(name) <= 160:
        raise ValueError("Team name must contain 2–160 characters")
    if email and (len(email) > 254 or "@" not in email):
        raise ValueError("Provide a valid email address or leave it blank")
    duplicate = session.scalar(select(Owner).where(func.lower(Owner.name) == name.lower(), Owner.id != team_id))
    if duplicate is not None:
        raise ValueError("A team with this name already exists")
    obj.name, obj.email = name, email or None
    session.commit()
    return obj


def update_decision_maker(session: Session, person_id: int, name: str, role: str,
                          email: str = "", active: bool = True) -> DecisionMaker:
    obj = session.get(DecisionMaker, person_id)
    if obj is None:
        raise ValueError("Decision maker not found")
    name, role, email = name.strip(), role.strip(), email.strip()
    if not 2 <= len(name) <= 160 or not 2 <= len(role) <= 120:
        raise ValueError("Decision maker name and role are required")
    if email and (len(email) > 254 or "@" not in email):
        raise ValueError("Provide a valid email address or leave it blank")
    duplicate = session.scalar(select(DecisionMaker).where(func.lower(DecisionMaker.name) == name.lower(),
                                                      DecisionMaker.id != person_id))
    if duplicate is not None:
        raise ValueError("A decision maker with this name already exists")
    obj.name, obj.role, obj.email, obj.active = name, role, email or None, active
    session.commit()
    return obj


def record_authenticated_decision(session: Session, finding_id:int, action:str, user_id:int,
                                  rationale:str, review_date:str="", *, commit: bool=True) -> GovernanceDecision:
    """Record a decision by the *actual signed-in actor*, never a chosen directory label."""
    if action not in ACTIONS: raise ValueError('Invalid governance action')
    finding=session.get(Finding,finding_id)
    account=session.get(UserAccount,user_id)
    if not finding: raise ValueError('Finding not found')
    if not account or not account.is_active: raise ValueError('An active signed-in user is required')
    if not finding.assigned_owner_id: raise ValueError('Assign responsible remediation team first')
    reason=rationale.strip()
    if len(reason)<10 or len(reason)>5000: raise ValueError('Provide 10–5000 characters of rationale')
    review=review_date.strip()
    if action in {'defer','accept_risk'} and not review: raise ValueError('A review date is required')
    if review:
        try: reviewed=date.fromisoformat(review)
        except ValueError: raise ValueError('Review date must be YYYY-MM-DD') from None
        if reviewed<date.today(): raise ValueError('Review date must not be in the past')
    obj=GovernanceDecision(finding_id=finding.id,action=action,decided_by=account.name,actor_user_id=account.id,
                           rationale=reason,review_date=review or None)
    finding.workflow_state=ACTIONS[action]
    session.add(obj)
    if commit: session.commit()
    else: session.flush()
    return obj
