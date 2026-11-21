"""Independent CSV adapters. Inputs are synthetic or appropriately authorized datasets."""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from datetime import datetime
from dataclasses import dataclass, field

MAX_ROWS = 10_000
MAX_UPLOAD_BYTES = 2 * 1024 * 1024


class ImportValidationError(ValueError):
    pass


ALIASES = {
    "asset": ("asset_id", "asset", "host", "hostname", "ip_address", "ip", "target"),
    "title": ("title", "finding", "finding_name", "name", "plugin_name", "vulnerability"),
    "severity": ("severity", "risk", "risk_level"),
    "plugin_id": ("plugin_id", "plugin", "rule_id", "finding_id", "check_id"),
    "description": ("description", "details", "synopsis"),
    "remediation": ("remediation", "recommendation", "solution", "fix"),
    "owner": ("owner", "asset_owner", "assignment_group", "champion"),
    "evidence": ("evidence", "plugin_output", "output", "proof", "technical_evidence"),
    "cve": ("cve", "cve_id"),
    "port": ("port", "service_port"),
    "protocol": ("protocol", "transport"),
    "path": ("path", "url_path", "endpoint", "location"),
}


def normalize_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def normalize_asset(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value:
        raise ImportValidationError("Asset identifier is required")
    try:
        value = str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if len(value) > 290:
        raise ImportValidationError("Asset identifier is too long")
    return value


def normalize_severity(raw: str, source: str) -> str:
    value = str(raw or "").strip().lower()
    named = {
        "critical": "Critical", "crit": "Critical", "high": "High",
        "medium": "Medium", "moderate": "Medium", "med": "Medium",
        "low": "Low", "info": "Informational", "informational": "Informational",
        "none": "Informational",
    }
    if value in {"", "unknown", "unrated", "n/a", "not set"}:
        raise ImportValidationError("Severity is required; provide Critical, High, Medium, Low or Informational")
    if value in named:
        return named[value]
    # Numeric severity 0-4 is supported for Nessus exports only.
    if source in {"nessus_csv", "nessus_html", "tenable_json"} and value in {"0", "1", "2", "3", "4"}:
        return {"0": "Informational", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}[value]
    raise ImportValidationError(f"Unsupported severity value: {raw!r}")


@dataclass(frozen=True)
class FindingInput:
    asset: str
    title: str
    severity: str
    plugin_id: str = ""
    description: str = ""
    remediation: str = ""
    owner: str = ""
    evidence: str = ""
    cve: str = ""
    port: str = ""
    protocol: str = ""
    path: str = ""
    detected_at: datetime | None = None
    source_metadata: dict = field(default_factory=dict)

    @property
    def location(self) -> str:
        port = self.port.strip()
        proto = self.protocol.strip().lower()
        path = self.path.strip()
        parts = [f"{port}/{proto}" if port and proto else (port or proto)]
        if path:
            parts.append(path)
        return " | ".join(x for x in parts if x)[:250]


def parse_csv(data: bytes, source: str = "generic_csv") -> list[FindingInput]:
    if source not in {"generic_csv", "nessus_csv"}:
        raise ImportValidationError("Unsupported import source")
    if not data:
        raise ImportValidationError("CSV file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ImportValidationError("CSV file exceeds 2 MiB limit")
    try:
        text = data.decode("utf-8-sig", "strict")
    except UnicodeDecodeError as exc:
        raise ImportValidationError("Expected UTF-8 CSV (including UTF-8 BOM)") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if reader.fieldnames is None:
        raise ImportValidationError("CSV header row is missing")
    normalized = [normalize_header(h) for h in reader.fieldnames]
    if len(normalized) != len(set(normalized)):
        raise ImportValidationError("CSV has ambiguous or duplicate column names")
    field_map = dict(zip(normalized, reader.fieldnames))
    selected = {}
    for canonical, aliases in ALIASES.items():
        selected[canonical] = next((field_map[a] for a in aliases if a in field_map), None)
    if not selected["asset"] or not selected["title"]:
        raise ImportValidationError("CSV must include an asset/host and a title/finding column")

    records = []
    for row_index, row in enumerate(reader, start=2):
        if len(records) >= MAX_ROWS:
            raise ImportValidationError(f"Too many records: maximum {MAX_ROWS}")
        if None in row:
            raise ImportValidationError(f"Malformed CSV at row {row_index}: extra fields")
        if all(not str(v or "").strip() for v in row.values()):
            continue
        def field(key: str) -> str:
            return str(row.get(selected[key]) or "").strip() if selected[key] else ""
        try:
            asset = normalize_asset(field("asset"))
            title = field("title")
            if not title:
                raise ImportValidationError("Title is required")
            if len(title) > 300:
                raise ImportValidationError("Title exceeds 300 characters")
            records.append(FindingInput(
                asset=asset, title=title, severity=normalize_severity(field("severity"), source),
                plugin_id=field("plugin_id")[:120], description=field("description")[:10_000],
                remediation=field("remediation")[:10_000], owner=field("owner")[:160],
                evidence=field("evidence")[:10_000], cve=field("cve")[:64],
                port=field("port")[:20], protocol=field("protocol")[:20],
                path=field("path")[:200],
                source_metadata={"csv_columns": {str(k): str(v or "")[:10000] for k,v in row.items()}}
                    if source == "nessus_csv" else {},
            ))
        except ImportValidationError as exc:
            raise ImportValidationError(f"Row {row_index}: {exc}") from exc
    if not records:
        raise ImportValidationError("CSV contains no findings")
    return records


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def vulnerability_key(record: FindingInput) -> str:
    if record.plugin_id:
        return "plugin:" + record.plugin_id.strip().lower()
    # Titles are a provisional identity for manual findings, not an assertion of
    # semantic equivalence across scanner vendors.
    return "title:" + digest(" ".join(record.title.lower().split()))[:24]


def finding_fingerprint(source: str, record: FindingInput) -> str:
    # Source-scoped deterministic matching avoids cross-vendor false merges.
    return digest("\x1f".join((source, record.asset, vulnerability_key(record), record.location.lower())))


def observation_hash(record: FindingInput) -> str:
    return digest("\x1f".join((record.asset, record.title, record.severity,
                              record.plugin_id, record.location, record.evidence)))


def _json_text(value: object, limit: int = 10_000) -> str:
    """Safely flatten a small JSON field for an evidence/description column."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:limit]
    import json
    return json.dumps(value, ensure_ascii=False, sort_keys=True)[:limit]


def _json_document(data: bytes):
    import json
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise ImportValidationError("JSON input is empty or exceeds 2 MiB")
    try:
        return json.loads(data.decode("utf-8-sig", "strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ImportValidationError("Invalid UTF-8 JSON input") from exc


def _asset_from_target(target: str) -> tuple[str, str]:
    """Extract normalized hostname and service path without network operations."""
    from urllib.parse import urlsplit
    target = target.strip()
    if "://" in target:
        try:
            parsed = urlsplit(target)
            if not parsed.hostname:
                raise ValueError("URL lacks host")
            hostname = normalize_asset(parsed.hostname)
            port = str(parsed.port) if parsed.port else ""
            location = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
            return hostname, ((port + "/tcp | " if port else "") + location)[:200]
        except ValueError as exc:
            raise ImportValidationError("Invalid target URL") from exc
    return normalize_asset(target), ""


def parse_nuclei_jsonl(data: bytes) -> list[FindingInput]:
    import json
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise ImportValidationError("Nuclei JSONL is empty or exceeds 2 MiB")
    try:
        text = data.decode("utf-8-sig", "strict")
    except UnicodeDecodeError as exc:
        raise ImportValidationError("Nuclei JSONL must be UTF-8") from exc
    results = []
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if len(results) >= MAX_ROWS:
            raise ImportValidationError("Nuclei JSONL exceeds 10,000 findings")
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("record must be a JSON object")
            info = event.get("info") or {}
            if not isinstance(info, dict):
                raise ValueError("info must be an object")
            template_id = str(event.get("template-id") or "").strip()
            if not template_id:
                raise ValueError("template-id is required")
            title = str(info.get("name") or template_id).strip()
            target = str(event.get("matched-at") or event.get("host") or event.get("url") or "")
            asset, path = _asset_from_target(str(event.get("host") or target))
            if "://" in target:
                match_asset, match_path = _asset_from_target(target)
                if match_asset == asset and match_path:
                    path = match_path
            classification = info.get("classification") or {}
            if not isinstance(classification, dict):
                classification = {}
            cve = classification.get("cve-id") or ""
            if isinstance(cve, list):
                cve = ", ".join(str(x) for x in cve)
            evidence = event.get("extracted-results") or event.get("matcher-name") or target
            from app.source_adapters import _when
            event_meta = {k: event.get(k) for k in (
                'template', 'template-id', 'template-url', 'matcher-name',
                'extractor-name', 'type', 'ip', 'port', 'timestamp', 'matched-at',
                'matcher-status', 'extracted-results', 'host', 'path', 'url')
                if k in event}
            event_meta['info'] = {k: info.get(k) for k in (
                'author', 'tags', 'reference', 'metadata', 'classification') if k in info}
            results.append(FindingInput(
                asset=asset, title=title[:300],
                severity=normalize_severity(info.get("severity"), "nuclei_jsonl"),
                plugin_id=template_id[:120], description=_json_text(info.get("description")),
                remediation=_json_text(info.get("remediation")),
                evidence=_json_text(evidence), cve=str(cve)[:64],
                path=path, detected_at=_when(event.get('timestamp')),
                source_metadata=event_meta,
            ))
        except (ValueError, TypeError, ImportValidationError) as exc:
            raise ImportValidationError(f"Nuclei line {index}: {exc}") from exc
    if not results:
        raise ImportValidationError("No Nuclei findings found")
    return results


def parse_plextrac_json(data: bytes) -> list[FindingInput]:
    """Documented PlexTrac finding objects, not arbitrary proprietary backups/PTRAC archives."""
    document = _json_document(data)
    findings = document.get("findings") if isinstance(document, dict) else document
    if not isinstance(findings, list):
        raise ImportValidationError("PlexTrac JSON requires a findings array or list of finding objects")
    output = []
    for index, item in enumerate(findings, 1):
        if not isinstance(item, dict):
            raise ImportValidationError(f"PlexTrac finding {index}: expected an object")
        title = str(item.get("title") or "").strip()
        if not title:
            raise ImportValidationError(f"PlexTrac finding {index}: title is required")
        severity = normalize_severity(item.get("severity"), "plextrac_json")
        assets = item.get("affected_assets")
        if isinstance(assets, dict):
            asset_objects = list(assets.values())
        elif isinstance(assets, list):
            asset_objects = assets
        else:
            raise ImportValidationError(f"PlexTrac finding {index}: affected_assets must be a mapping or list")
        if not asset_objects:
            raise ImportValidationError(f"PlexTrac finding {index}: no affected assets")
        identifiers = item.get("common_identifiers") or {}
        cves = identifiers.get("CVE") or [] if isinstance(identifiers, dict) else []
        cve = ", ".join(str(entry.get("name", "")) for entry in cves if isinstance(entry, dict))
        for asset_data in asset_objects:
            if len(output) >= MAX_ROWS:
                raise ImportValidationError("PlexTrac JSON exceeds 10,000 affected-asset observations")
            if not isinstance(asset_data, dict):
                raise ImportValidationError(f"PlexTrac finding {index}: invalid affected asset")
            asset_name = asset_data.get("asset") or asset_data.get("hostname") or asset_data.get("host_fqdn")
            if not isinstance(asset_name, str) or not asset_name.strip():
                raise ImportValidationError(f"PlexTrac finding {index}: affected asset identifier missing")
            try:
                normalized_asset = normalize_asset(asset_name)
            except ImportValidationError as exc:
                raise ImportValidationError(f"PlexTrac finding {index}: {exc}") from exc
            report = str(item.get("report_id") or "")
            flaw = str(item.get("flaw_id") or "")
            plugin_id = f"{report}:{flaw}" if report and flaw else ""
            location = str(asset_data.get("locationUrl") or asset_data.get("location") or "")[:200]
            evidence = asset_data.get("evidence") or item.get("evidence") or ""
            output.append(FindingInput(
                asset=normalized_asset, title=title[:300], severity=severity,
                plugin_id=plugin_id[:120], description=_json_text(item.get("description")),
                remediation=_json_text(item.get("recommendations") or item.get("recommendation")),
                owner=_json_text(asset_data.get("assignedTo") or asset_data.get("system_owner") or item.get("assignedTo"), 160),
                evidence=_json_text(evidence), cve=cve[:64], path=location,
            ))
    if not output:
        raise ImportValidationError("No PlexTrac affected findings found")
    return output


def parse_source(data: bytes, source: str) -> list[FindingInput]:
    if source == "generic_csv":
        try:
            return parse_csv(data, source)
        except ImportValidationError as exc:
            if str(exc) not in {"CSV must include an asset/host and a title/finding column",
                                "CSV has ambiguous or duplicate column names"}:
                raise
            from app.source_adapters import parse_consultant_csv
            return parse_consultant_csv(data)
    if source == "nessus_csv":
        return parse_csv(data, source)
    if source == "nuclei_jsonl":
        return parse_nuclei_jsonl(data)
    if source == "plextrac_json":
        from app.source_adapters import parse_plextrac_export
        return parse_plextrac_export(data)
    if source == "sec1_csv":
        from app.source_adapters import parse_consultant_csv
        return parse_consultant_csv(data)
    if source == "old_sec1_csv":
        from app.source_adapters import parse_legacy_consultant_csv
        return parse_legacy_consultant_csv(data)
    if source == "tenable_json":
        from app.source_adapters import parse_tenable_export
        return parse_tenable_export(data)
    if source == "nessus_html":
        from app.source_adapters import parse_nessus_html_report
        return parse_nessus_html_report(data)
    raise ImportValidationError("Unsupported import source")
