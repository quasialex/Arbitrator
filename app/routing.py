"""Global asset+vulnerability responsibility mapping. No assessment/engagement ownership.

Only one team can own a finding. Equally specific contradictory matches fail closed.
The third-party `regex` module enforces per-match deadlines for operator-supplied regex.
"""
from __future__ import annotations
import ipaddress
import regex
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import Asset, Finding, Owner, RoutingRule

ASSET_KINDS = {"none", "cidr", "hostname_suffix", "hostname_regex", "service_code", "service_code_regex"}
FINDING_KINDS = {"none", "title_contains", "plugin_prefix", "title_regex", "plugin_regex"}
MAX_PATTERN = 180
MATCH_TIMEOUT = 0.02


def validate_rule(asset_kind: str, asset_pattern: str, finding_kind: str,
                  finding_pattern: str) -> tuple[str,str]:
    if asset_kind not in ASSET_KINDS or finding_kind not in FINDING_KINDS:
        raise ValueError("Unsupported rule criteria")
    asset_pattern = asset_pattern.strip().lower()
    finding_pattern = finding_pattern.strip().lower()
    if asset_kind == "none": asset_pattern = ""
    if finding_kind == "none": finding_pattern = ""
    if asset_kind == "none" and finding_kind == "none":
        raise ValueError("Set an asset or vulnerability condition")
    if (asset_kind != "none" and not asset_pattern) or (finding_kind != "none" and not finding_pattern):
        raise ValueError("Specify a match pattern for each selected condition")
    if len(asset_pattern) > MAX_PATTERN or len(finding_pattern) > MAX_PATTERN:
        raise ValueError(f"Patterns must have at most {MAX_PATTERN} characters")
    if asset_kind == "cidr":
        try: asset_pattern = str(ipaddress.ip_network(asset_pattern, strict=False))
        except ValueError: raise ValueError("Invalid CIDR network") from None
    elif asset_kind == "hostname_suffix":
        asset_pattern = asset_pattern.removeprefix("*.").rstrip(".")
        if not asset_pattern or any(c in asset_pattern for c in " /\\*[]()|+?^"):
            raise ValueError("Use a literal DNS suffix, or select Hostname regex")
    if asset_kind.endswith("regex"):
        _compile(asset_pattern)
    if finding_kind.endswith("regex"):
        _compile(finding_pattern)
    return asset_pattern, finding_pattern


def _compile(pattern: str):
    try: return regex.compile(pattern, flags=regex.IGNORECASE | regex.VERSION1)
    except regex.error as exc: raise ValueError(f"Invalid regular expression: {exc}") from None


def _search(pattern: str, value: str) -> bool:
    try: return bool(_compile(pattern).search(value[:400], timeout=MATCH_TIMEOUT))
    except TimeoutError: return False  # never route on a timed-out expression


def matches(rule: RoutingRule, finding: Finding) -> bool:
    asset, vuln = finding.asset, finding.vulnerability
    hostname_key = (asset.hostname or asset.identity_key).lower().rstrip(".")
    ip_key = (asset.ip_address or asset.identity_key).lower().rstrip(".")
    service_code = (asset.service_code or "").lower()
    if rule.asset_kind == "cidr":
        try:
            if ipaddress.ip_address(ip_key) not in ipaddress.ip_network(rule.asset_pattern): return False
        except ValueError: return False
    elif rule.asset_kind == "hostname_suffix":
        suffix = rule.asset_pattern
        if hostname_key != suffix and not hostname_key.endswith("." + suffix): return False
    elif rule.asset_kind == "hostname_regex":
        if not _search(rule.asset_pattern, hostname_key): return False
    elif rule.asset_kind == "service_code":
        if service_code != rule.asset_pattern: return False
    elif rule.asset_kind == "service_code_regex":
        if not _search(rule.asset_pattern, service_code): return False
    if rule.finding_kind == "title_contains" and rule.finding_pattern not in vuln.title.lower(): return False
    if rule.finding_kind == "plugin_prefix" and not vuln.external_key.lower().startswith(rule.finding_pattern): return False
    if rule.finding_kind == "title_regex" and not _search(rule.finding_pattern, vuln.title): return False
    if rule.finding_kind == "plugin_regex" and not _search(rule.finding_pattern, vuln.external_key): return False
    return True


def specificity(rule: RoutingRule) -> tuple[int,int]:
    """Computed from predicates, not an editable priority field.

    A constrained asset+vulnerability rule outranks an asset-only rule.
    A more specific literal hostname outranks a broad suffix.
    Equal ranks yielding different teams are conflicts, never arbitrary selection.
    """
    fields = int(rule.asset_kind != "none") + int(rule.finding_kind != "none")
    detail = 0
    if rule.asset_kind == "hostname_suffix": detail = len(rule.asset_pattern)
    elif rule.asset_kind == "cidr": detail = ipaddress.ip_network(rule.asset_pattern).prefixlen
    elif rule.asset_kind in {"service_code", "hostname_regex", "service_code_regex"}: detail = len(rule.asset_pattern)
    if rule.finding_kind != "none": detail += len(rule.finding_pattern)
    return fields, detail


def route_finding(session: Session, finding: Finding) -> str:
    if finding.assignment_source == "manual":
        return "Manual assignment retained"
    rules = session.scalars(select(RoutingRule).order_by(RoutingRule.id)).all()
    selected = [r for r in rules if matches(r, finding)]
    if not selected:
        finding.assigned_owner_id = None
        finding.assignment_source = "none"
        finding.assignment_reason = "No global responsibility rule matched"
        return finding.assignment_reason
    score = max(specificity(r) for r in selected)
    top = [r for r in selected if specificity(r) == score]
    owners = {r.team_id for r in top}
    if len(owners) != 1:
        finding.assigned_owner_id = None
        finding.assignment_source = "conflict"
        finding.assignment_reason = "Equally specific rules assign different teams; manual review required"
    else:
        finding.assigned_owner_id = next(iter(owners))
        finding.assignment_source = "rule"
        finding.assignment_reason = f"Matched global rule #{top[0].id}; computed specificity {score}"
    return finding.assignment_reason


def create_routing_rule(session: Session, team_id: int, asset_kind: str,
                        asset_pattern: str, finding_kind: str,
                        finding_pattern: str) -> RoutingRule:
    a, f = validate_rule(asset_kind, asset_pattern, finding_kind, finding_pattern)
    if not session.get(Owner, team_id): raise ValueError("Select a valid remediation team")
    rule = RoutingRule(team_id=team_id, asset_kind=asset_kind, asset_pattern=a,
                       finding_kind=finding_kind, finding_pattern=f)
    session.add(rule); session.commit(); return rule


def update_routing_rule(session: Session, rule_id: int, team_id: int, asset_kind: str,
                        asset_pattern: str, finding_kind: str,
                        finding_pattern: str) -> RoutingRule:
    rule = session.get(RoutingRule, rule_id)
    if rule is None: raise ValueError("Rule does not exist")
    a, f = validate_rule(asset_kind, asset_pattern, finding_kind, finding_pattern)
    if not session.get(Owner, team_id): raise ValueError("Select a valid remediation team")
    rule.team_id, rule.asset_kind, rule.asset_pattern = team_id, asset_kind, a
    rule.finding_kind, rule.finding_pattern = finding_kind, f
    session.commit(); return rule


def apply_routing(session: Session) -> dict:
    result = {"total": 0, "matched": 0, "unassigned": 0, "conflicts": 0, "preserved": 0}
    for finding in session.scalars(select(Finding)).all():
        result["total"] += 1
        if finding.assignment_source == "manual":
            result["preserved"] += 1
            continue
        route_finding(session, finding)
        if finding.assignment_source == "rule": result["matched"] += 1
        if not finding.assigned_owner_id: result["unassigned"] += 1
        if finding.assignment_source == "conflict": result["conflicts"] += 1
    session.commit()
    return result
