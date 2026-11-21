"""External assessment source normalization adapters.

Rows are emitted per affected asset for the finding/observation model.
No low or informational records are discarded. Source provenance is recorded
in the project license directory.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlsplit

from app.importers import (
    MAX_ROWS, MAX_UPLOAD_BYTES, FindingInput, ImportValidationError,
    normalize_asset, normalize_severity,
)


def _check_size(data: bytes, label: str) -> str:
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise ImportValidationError(f"{label} is empty or exceeds 2 MiB")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportValidationError(f"{label} must be UTF-8") from exc


def _md5(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def _text(raw: object, limit: int = 10000) -> str:
    if raw is None:
        return ""
    value = str(raw)
    # PlexTrac fields are often HTML; preserve readability without HTML in UI.
    if '<' in value and '>' in value:
        from bs4 import BeautifulSoup
        value = BeautifulSoup(value, 'html.parser').get_text(' ', strip=True)
    return unescape(value).strip()[:limit]


def _when(raw: object) -> datetime | None:
    if raw is None or raw == '':
        return None
    if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.isdigit()):
        num = float(raw)
        if num > 10_000_000_000:
            num /= 1000  # PlexTrac createdAt uses epoch milliseconds
        try:
            return datetime.fromtimestamp(num, timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(raw, str):
        try:
            result = datetime.fromisoformat(raw.strip().replace('Z', '+00:00'))
            return result.astimezone(timezone.utc).replace(tzinfo=None) if result.tzinfo else result
        except ValueError:
            # E.g. Nessus scan date strings; refuse ambiguous timezone assumptions.
            return None
    return None


def _plain_asset(target: str) -> tuple[str, str, str, str]:
    """Return canonical host, location, port and transport without DNS lookups."""
    val = str(target).strip()
    if not val:
        raise ImportValidationError('Affected asset is empty')
    path, port, protocol = '', '', ''
    if '://' in val:
        split = urlsplit(val)
        if not split.hostname:
            raise ImportValidationError('Malformed affected-asset URL')
        val = split.hostname
        try:
            port = str(split.port or '')
        except ValueError as exc:
            raise ImportValidationError('Invalid affected-asset port') from exc
        protocol = 'tcp' if split.scheme in ('http', 'https') else ''
        path = (split.path or '/') + (('?' + split.query) if split.query else '')
    else:
        # E.g. 192.0.2.3 (tcp 443; 80), foo.example/path, comma-separated values.
        val = re.sub(r'\s*\([^)]*\)\s*$', '', val)
        val, _, trail = val.partition('/')
        path = ('/' + trail) if trail else ''
        val, _, query = val.partition('?')
        if query:
            path += '?' + query
    return normalize_asset(val), path[:200], port, protocol


def _affected_raw(value: object) -> list[tuple[str, dict]]:
    """Handle PlexTrac findings objects and supported [id,{asset,...}] pairs."""
    if isinstance(value, dict):
        candidates = list(value.values())
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = []
    rows = []
    for node in candidates:
        if isinstance(node, (list, tuple)) and len(node) >= 2 and isinstance(node[1], dict):
            node = node[1]
        if isinstance(node, str):
            node = {'asset': node}
        if not isinstance(node, dict):
            continue
        name = node.get('asset') or node.get('host') or node.get('hostname') or node.get('host_fqdn')
        if name:
            rows.append((str(name), node))
    return rows


def _fallback_assets(item: dict) -> list[tuple[str, dict]]:
    merged = item.get('fields', {}).get('merged_assets', {}) if isinstance(item.get('fields'), dict) else {}
    merged_text = merged.get('value', '') if isinstance(merged, dict) else ''
    # Preserve reference implementation fallback order: merged field, description, recommendations,
    # then Android application marker. Explicit assets always take precedence.
    candidates = [merged_text, item.get('description'), item.get('recommendations')]
    ip = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
    fqdn = re.compile(r'(?<![\w.-])(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,}(?![\w.-])')
    for index, value in enumerate(candidates):
        if not isinstance(value, str):
            continue
        for regex in (ip, fqdn):
            matched = []
            for hit in regex.findall(_text(value)):
                if regex is ip:
                    try:
                        ipaddress.ip_address(hit)
                    except ValueError:
                        continue
                if hit not in matched:
                    matched.append(hit)
            if matched:
                return [(x, {}) for x in matched]
    if 'android' in _text(item.get('description')).lower():
        return [('Android Application', {})]
    return []


def parse_plextrac_export(data: bytes) -> list[FindingInput]:
    """Field mapping for PlexTrac `flaws_array` records.

    Supports existing Arbitrator's `findings` format too. Primary identity is
    MD5(title), same as reference implementation, and source-scoped by the caller.
    """
    text = _check_size(data, 'PlexTrac JSON')
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ImportValidationError('Invalid PlexTrac JSON') from exc
    if isinstance(doc, list):
        flaws = doc
    elif isinstance(doc, dict):
        flaws = doc.get('flaws_array', doc.get('findings'))
    else:
        flaws = None
    if not isinstance(flaws, list):
        raise ImportValidationError('PlexTrac JSON requires flaws_array or findings')
    records = []
    for i, item in enumerate(flaws, 1):
        if not isinstance(item, dict) or not str(item.get('title') or '').strip():
            raise ImportValidationError(f'PlexTrac finding {i}: missing title')
        title = str(item['title']).strip()
        severity = normalize_severity(item.get('severity'), 'plextrac_json')
        entries = _affected_raw(item.get('affected_assets')) or _fallback_assets(item)
        if not entries:
            raise ImportValidationError(f'PlexTrac finding {i}: affected_assets missing or fallback cannot identify asset')
        identifiers = item.get('common_identifiers') or {}
        cves = identifiers.get('CVE', []) if isinstance(identifiers, dict) else []
        cve = ', '.join(str(x.get('name')) for x in cves if isinstance(x, dict) and x.get('name'))
        timestamp = _when(item.get('createdAt'))
        for raw_name, asset_data in entries:
            # reference implementation splits comma-separated asset values and strips URLs to
            # the hostname while retaining the complete URL as location evidence.
            for name in re.split(r'\s*,\s*', raw_name):
                if not name.strip():
                    continue
                host, path, port, protocol = _plain_asset(name)
                annotated = re.search(r'\((tcp|udp|icmp)\s+([0-9;\s]+)\)\s*$', name, re.I)
                if annotated and not port:
                    protocol, port = annotated.group(1).lower(), annotated.group(2).split(';')[0].strip()
                ports = asset_data.get('ports') or []
                if ports and not port:
                    first_port = ports[0]
                    if isinstance(first_port, (list, tuple)) and len(first_port) > 1:
                        first_port = first_port[1]
                    if isinstance(first_port, dict):
                        port, protocol = str(first_port.get('number', '')), str(first_port.get('protocol', ''))
                explicit_location = asset_data.get('locationUrl') or asset_data.get('location')
                if explicit_location and not path:
                    path = str(explicit_location)[:200]
                metadata = {
                    'title_hash': _md5(title),
                    'source_flaw_id': item.get('flaw_id'),
                    'source_report_id': item.get('report_id'),
                    'affected_asset_raw': name,
                    'source_created_at': item.get('createdAt'),
                    'exhibits': item.get('exhibits') or [],
                    'asset_ports': ports,
                    'source_fields': item.get('fields') or {},
                }
                evidence = asset_data.get('evidence') or item.get('evidence') or ''
                if len(records) >= MAX_ROWS:
                    raise ImportValidationError('PlexTrac exceeds 10,000 asset observations')
                records.append(FindingInput(
                    asset=host, title=title[:300], severity=severity,
                    plugin_id=_md5(title), description=_text(item.get('description')),
                    remediation=_text(item.get('recommendations') or item.get('recommendation')),
                    evidence=_text(evidence), owner=_text(asset_data.get('assignedTo') or item.get('assignedTo'), 160),
                    cve=cve[:64], path=path, port=port[:20], protocol=protocol[:20],
                    detected_at=timestamp, source_metadata=metadata,
                ))
    if not records:
        raise ImportValidationError('No PlexTrac records found')
    return records


def parse_consultant_csv(data: bytes) -> list[FindingInput]:
    """Sec-1 positional CSV from reference implementation: title[0], risk[3], asset[5]."""
    rows = csv.reader(io.StringIO(_check_size(data, 'Sec-1 CSV')))
    parsed = []
    for n, row in enumerate(rows, 1):
        if not row or all(not x.strip() for x in row):
            continue
        if len(row) < 9:
            raise ImportValidationError(f'Sec-1 row {n}: expected at least 9 columns')
        if row[0].lower().strip() in {'finding', 'title', 'name'}:
            continue
        severity = normalize_severity(row[3], 'sec1_csv')
        for asset in row[5].split(','):
            if not asset.strip():
                continue
            host, path, port, proto = _plain_asset(asset)
            parsed.append(FindingInput(asset=host, title=row[0][:300], severity=severity,
                plugin_id=_md5(row[0]), description=_text(row[6]),
                remediation=(row[7] + '\n\n' + row[8]).strip()[:10000],
                evidence=row[9][:10000] if len(row) > 9 else '', path=path, port=port, protocol=proto,
                source_metadata={'original_images': row[9] if len(row) > 9 else ''}))
            if len(parsed) > MAX_ROWS:
                raise ImportValidationError('Sec-1 exceeds 10,000 records')
    if not parsed:
        raise ImportValidationError('No Sec-1 findings found')
    return parsed



def parse_legacy_consultant_csv(data: bytes) -> list[FindingInput]:
    """reference implementation legacy consultant CSV: name[1], severity[4], assets[7]."""
    rows = csv.reader(io.StringIO(_check_size(data, 'Legacy Sec-1 CSV')))
    parsed = []
    for n, row in enumerate(rows, 1):
        if not row or all(not x.strip() for x in row):
            continue
        if len(row) < 8:
            raise ImportValidationError(f'Legacy Sec-1 row {n}: expected at least 8 columns')
        if row[1].strip().lower() in {'finding', 'title', 'finding name'}:
            continue
        severity = normalize_severity(row[4].split('/')[0], 'old_sec1_csv')
        for raw_asset in row[7].split(','):
            if not raw_asset.strip():
                continue
            host, path, port, proto = _plain_asset(raw_asset)
            parsed.append(FindingInput(asset=host, title=row[1][:300], severity=severity,
                plugin_id=_md5(row[1]), description=_text(row[5]),
                remediation=_text(row[6]), path=path, port=port, protocol=proto,
                source_metadata={'legacy_source':'old_sec1'}))
            if len(parsed)>MAX_ROWS:
                raise ImportValidationError('Legacy Sec-1 exceeds 10,000 observations')
    if not parsed:
        raise ImportValidationError('No legacy Sec-1 findings found')
    return parsed


def parse_tenable_export(data: bytes) -> list[FindingInput]:
    """Field mapping for reference implementation::Vulns.format_nessus on Tenable.io vuln export chunks.

    Flatten the Tenable per-asset finding rows into observations, retaining raw
    plugin ID as provenance and MD5(raw plugin ID) as the normalized plugin key.
    """
    text = _check_size(data, 'Tenable export JSON')
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ImportValidationError('Invalid Tenable JSON') from exc
    if isinstance(doc, dict):
        doc = doc.get('vulnerabilities', doc.get('vulns', doc.get('data')))
    if not isinstance(doc, list):
        raise ImportValidationError('Tenable export requires a vulnerability array')
    output = []
    for idx, row in enumerate(doc, 1):
        if isinstance(row, list):
            row = row[0] if row else None
        if not isinstance(row, dict):
            raise ImportValidationError(f'Tenable row {idx}: expected object')
        plugin = row.get('plugin') or {}
        asset = row.get('asset') or {}
        service = row.get('port') or {}
        if isinstance(plugin, list): plugin = plugin[0] if plugin else {}
        if isinstance(asset, list): asset = asset[0] if asset else {}
        if isinstance(service, list): service = service[0] if service else {}
        if not isinstance(plugin, dict) or not isinstance(asset, dict) or not isinstance(service, dict):
            raise ImportValidationError(f'Tenable row {idx}: invalid nested fields')
        raw_id = str(plugin.get('id') or '').strip()
        if not raw_id:
            continue  # Existing mapping rule: no identity without a plugin ID
        ips = asset.get('ipv4') or asset.get('ip') or asset.get('fqdn') or asset.get('hostname')
        if isinstance(ips, list): ips = ips[0] if ips else ''
        if not ips:
            raise ImportValidationError(f'Tenable row {idx}: missing asset identity')
        severity_raw = plugin.get('risk_factor') or row.get('severity')
        if isinstance(severity_raw, int):
            severity_raw = {'0':'Informational','1':'Low','2':'Medium','3':'High','4':'Critical'}.get(str(severity_raw),str(severity_raw))
        severity = normalize_severity(severity_raw, 'tenable_json')
        time_values = [_when(row.get(k)) for k in ('first_found','indexed','last_found')]
        detected_at = min((t for t in time_values if t is not None), default=None)
        see = plugin.get('see_also') or []
        see_also = ' '.join(str(v) for v in see) if isinstance(see, list) else str(see)
        solution = _text(plugin.get('solution'))
        if see_also:
            solution = (solution + '\nAdditional info: ' + see_also).strip()[:10000]
        meta = {
            'nessus_id': raw_id, 'exploit_available': plugin.get('exploit_available'),
            'hostname': asset.get('fqdn') or asset.get('hostname') or asset.get('netbios_name'),
            'asset_uuid': asset.get('uuid'), 'tags': asset.get('tags', []),
            'first_found': row.get('first_found'), 'indexed': row.get('indexed'),
            'last_found': row.get('last_found'), 'see_also': see,
            'plugin_output': row.get('output'), 'source_port': service,
        }
        port, protocol = str(service.get('port') or ''), str(service.get('protocol') or '')
        output.append(FindingInput(
            asset=normalize_asset(str(ips)), title=_text(plugin.get('name') or f'Tenable plugin {raw_id}',300),
            severity=severity, plugin_id=_md5(raw_id), description=_text(plugin.get('description')),
            remediation=solution, evidence=_text(row.get('output')),
            port=port[:20], protocol=protocol[:20], detected_at=detected_at,
            source_metadata=meta,
        ))
        if len(output) > MAX_ROWS:
            raise ImportValidationError('Tenable export exceeds 10,000 records')
    if not output:
        raise ImportValidationError('Tenable export contains no applicable findings')
    return output


def parse_nessus_html_report(data: bytes) -> list[FindingInput]:
    """Read a Nessus HTML *report* locally; no active scanning or network calls.

    HTML is a distinct report format, not a substitute for raw Nessus CSV fields.
    The plugin header, Risk Factor and Plugin Output are faithfully extracted.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(_check_size(data, 'Nessus HTML'), 'html.parser')
    sections = soup.select('.section-wrapper')
    if not sections:
        raise ImportValidationError('No Nessus vulnerability sections in HTML')
    # Pick the host from Host Information details; no DNS probing is performed.
    hostname = ''
    for details in soup.select('.table-wrapper.details'):
        txt = details.get_text(' ', strip=True)
        match = re.search(r'DNS Name:\s*(\S+)', txt)
        if match and match.group(1) != 'N/A':
            hostname = match.group(1)
            break
        match = re.search(r'IP:\s*([0-9a-fA-F:.]+)', txt)
        if match:
            hostname = match.group(1)
            break
    if not hostname:
        raise ImportValidationError('Cannot determine report host')
    rows = []
    for index, sec in enumerate(sections, 1):
        heading = sec.find_previous_sibling('div')
        header = heading.get_text(' ', strip=True) if heading else ''
        match = re.match(r'^\s*(\d+)\s*-\s*(.+?)\s*-?\s*$', header)
        if not match:
            continue  # HTML report also has structural sections
        pid, name = match.groups()
        data_fields = {}
        for label in sec.find_all(class_='details-header', recursive=False):
            next_node = label.find_next_sibling()
            if next_node:
                data_fields[label.get_text(' ', strip=True)] = next_node.get_text(' ', strip=True)
        severity = normalize_severity(data_fields.get('Risk Factor', 'Informational'), 'nessus_html')
        output = data_fields.get('Plugin Output', '')
        service = re.search(r'\b(tcp|udp|icmp)/(\d+)(?:/[^\s]+)?',output,re.I)
        port, protocol = (service.group(2),service.group(1).lower()) if service else ('','')
        description = data_fields.get('Description') or data_fields.get('Synopsis') or ''
        evidence = output or data_fields.get('Synopsis') or ''
        rows.append(FindingInput(asset=normalize_asset(hostname),title=name[:300],
            plugin_id=pid,severity=severity,description=_text(description),
            remediation=_text(data_fields.get('Solution')),evidence=_text(evidence),
            port=port,protocol=protocol,
            source_metadata={'nessus_id':pid,'synopsis':data_fields.get('Synopsis'),
                'cvss':{k:v for k,v in data_fields.items() if k.startswith('CVSS')},
                'see_also':data_fields.get('See Also'), 'references':data_fields.get('References'),
                'plugin_information':data_fields.get('Plugin Information')},
        ))
        if len(rows) > MAX_ROWS:
            raise ImportValidationError('Nessus HTML exceeds 10,000 records')
    if not rows:
        raise ImportValidationError('No Nessus vulnerability records found in HTML')
    return rows
