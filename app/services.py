from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.importers import (
    ImportValidationError, parse_source, finding_fingerprint, observation_hash,
    vulnerability_key,
)
from app.models import Asset, Vulnerability, Finding, Owner, ImportBatch, Observation, GovernanceDecision, Engagement, Assessment, ObservationSourceMetadata, utcnow
from app.classification import classify_asset, address_fields_from_source
from app.routing import route_finding


@dataclass
class ImportStats:
    batch_id: int
    rows: int
    assets_created: int = 0
    findings_created: int = 0
    reobserved: int = 0
    observations_created: int = 0
    duplicate_rows: int = 0
    previously_imported: bool = False


def create_assessment(session: Session, engagement_name: str, assessment_name: str,
                      client: str = "Synthetic organization", scope: str = "",
                      methodology: str = "Penetration test", started_on: str = "",
                      ended_on: str = "", assessment_type: str = "Hybrid") -> Assessment:
    name = engagement_name.strip()
    title = assessment_name.strip()
    if not name or len(name) > 180 or not title or len(title) > 180:
        raise ValueError("Engagement and assessment names are required (max 180 characters)")
    methods = {"Penetration test", "Web/API penetration test", "Network penetration test",
               "Vulnerability assessment", "Retest", "Security review"}
    if methodology not in methods:
        raise ValueError("Choose a supported assessment methodology")
    if assessment_type not in {"Internal", "External", "Hybrid"}:
        raise ValueError("Assessment type must be Internal, External or Hybrid")
    try:
        started_at = datetime.combine(date.fromisoformat(started_on), datetime.min.time()) if started_on else utcnow()
        ended_at = datetime.combine(date.fromisoformat(ended_on), datetime.min.time()) if ended_on else None
    except ValueError:
        raise ValueError("Dates must use YYYY-MM-DD") from None
    if ended_at and ended_at < started_at:
        raise ValueError("Assessment end date cannot be earlier than start date")
    if len(scope) > 3000:
        raise ValueError("Scope must be 3000 characters or fewer")
    engagement = session.scalar(select(Engagement).where(Engagement.name == name))
    if engagement is None:
        engagement = Engagement(name=name, client=client.strip()[:180], scope=scope.strip()[:3000])
        session.add(engagement)
        session.flush()
    assessment = Assessment(engagement_id=engagement.id, name=title, methodology=methodology,
                            assessment_type=assessment_type,
                            scope=scope.strip(), started_at=started_at, ended_at=ended_at,
                            status=("Completed" if ended_at and ended_at.date() <= date.today()
                                    else "Scheduled" if started_at.date() > date.today() else "In progress"))
    session.add(assessment)
    session.commit()
    session.refresh(assessment)
    return assessment


def import_findings(session: Session, data: bytes, filename: str, source: str,
                    assessment_id: int | None = None) -> ImportStats:
    # Validate the complete input before any writes; failures never partially import.
    records = parse_source(data, source)
    # A default synthetic assessment preserves the simple v0.1 programmatic API.
    # The web UI requires users to select an explicit assessment.
    if assessment_id is None:
        existing = session.scalar(select(Assessment).order_by(Assessment.id).limit(1))
        if existing is None:
            existing = create_assessment(session, "Demonstration engagement", "Initial assessment")
        assessment_id = existing.id
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise ImportValidationError("Select an existing assessment before importing")
    content_hash = hashlib.sha256(str(assessment_id).encode() + b"\0" + source.encode() + b"\0" + data).hexdigest()
    prior = session.scalar(select(ImportBatch).where(ImportBatch.content_hash == content_hash))
    if prior is not None:
        return ImportStats(batch_id=prior.id, rows=prior.row_count, previously_imported=True)

    clean_filename = filename.replace("\\", "/").split("/")[-1][:255] or "upload.csv"
    batch = ImportBatch(content_hash=content_hash, assessment_id=assessment_id, original_filename=clean_filename,
                        source=source, row_count=len(records))
    session.add(batch)
    session.flush()
    stats = ImportStats(batch_id=batch.id, rows=len(records))
    seen_observations: set[tuple[str, str]] = set()

    try:
        for record in records:
            # External owner labels are untrusted metadata, NOT an assignment authority.
            # Responsibility comes from approved routing rules or a human analyst.
            asset = session.scalar(select(Asset).where(Asset.identity_key == record.asset))
            if asset is None:
                classification, reason = classify_asset(record.asset)
                hostname, ip_address = address_fields_from_source(record.asset)
                asset = Asset(identity_key=record.asset, display_name=record.asset,
                              hostname=hostname, ip_address=ip_address,
                              exposure=classification, classification_reason=reason)
                session.add(asset)
                session.flush()
                stats.assets_created += 1
            # Ownership changes must be reviewed; imports do not overwrite existing ownership.

            key = vulnerability_key(record)
            vuln = session.scalar(select(Vulnerability).where(
                Vulnerability.source == source, Vulnerability.external_key == key))
            if vuln is None:
                vuln = Vulnerability(source=source, external_key=key, title=record.title,
                                     cve=record.cve or None, description=record.description or None,
                                     remediation=record.remediation or None)
                session.add(vuln)
                session.flush()
            else:
                # Preserves source importer behavior from the reference specification Plugin.find_or_create: refresh descriptive
                # plugin metadata while keeping all prior finding observations.
                if record.title: vuln.title = record.title
                if record.description: vuln.description = record.description
                if record.remediation: vuln.remediation = record.remediation
                if record.cve: vuln.cve = record.cve

            fingerprint = hashlib.sha256((str(asset.id) + "\x1f" + finding_fingerprint(source, record)).encode()).hexdigest()
            row_hash = observation_hash(record)
            pair = (fingerprint, row_hash)
            if pair in seen_observations:
                stats.duplicate_rows += 1
                continue
            seen_observations.add(pair)

            finding = session.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
            if finding is None:
                finding = Finding(fingerprint=fingerprint, asset_id=asset.id,
                                  vulnerability_id=vuln.id, severity=record.severity,
                                  location=record.location,
                                  first_seen=record.detected_at or utcnow(),
                                  last_seen=record.detected_at or utcnow())
                session.add(finding)
                session.flush()
                stats.findings_created += 1
                route_finding(session, finding)
            else:
                # Reobservation is not verified remediation nor a change of governance state.
                current = record.detected_at or utcnow()
                finding.first_seen = min(finding.first_seen, current)
                finding.last_seen = max(finding.last_seen, current)
                stats.reobserved += 1
            observation = Observation(finding_id=finding.id, batch_id=batch.id,
                row_hash=row_hash, evidence=record.evidence,
                detected_at=record.detected_at or utcnow())
            session.add(observation)
            if record.source_metadata:
                session.flush()
                session.add(ObservationSourceMetadata(observation_id=observation.id,
                    source_data=json.dumps(record.source_metadata, ensure_ascii=False, default=str)))
            stats.observations_created += 1
        session.commit()
    except Exception:
        session.rollback()
        raise
    return stats


# New UI uses app.workflows.record_decision, which requires an assigned team
# and a registered decision maker. The former free-text add_decision API was
# retired because it produced unaccountable governance records.
