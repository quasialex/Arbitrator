"""Per-user encrypted connector credentials and explicit Tenable.io export action.

Secrets never enter application logs, HTML or audit messages. Encryption key
must be configured out of band; no insecure built-in fallback key exists.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import UserConnectorCredential, ConnectorHealthCheck, utcnow
from app.importers import ImportValidationError, MAX_UPLOAD_BYTES

PROVIDER = 'tenable'
BASE = 'https://cloud.tenable.com'


class ConnectorError(ValueError):
    pass


def _fernet() -> Fernet:
    key = os.getenv('ARBITRATOR_CREDENTIAL_KEY', '')
    if not key:
        raise ConnectorError('Credential encryption is not configured on this server')
    try:
        return Fernet(key.encode('ascii'))
    except (ValueError, TypeError) as exc:
        raise ConnectorError('Server credential encryption key is invalid') from exc


def save_tenable_credentials(session: Session, user_id: int, access_key: str, secret_key: str) -> None:
    access_key, secret_key = access_key.strip(), secret_key.strip()
    if not 8 <= len(access_key) <= 300 or not 8 <= len(secret_key) <= 300:
        raise ConnectorError('Both Tenable API keys are required (8–300 characters)')
    payload = json.dumps({'access_key': access_key, 'secret_key': secret_key}).encode('utf-8')
    ciphertext = _fernet().encrypt(payload).decode('ascii')
    saved = session.scalar(select(UserConnectorCredential).where(
        UserConnectorCredential.user_id==user_id, UserConnectorCredential.provider==PROVIDER))
    if saved:
        saved.ciphertext, saved.updated_at = ciphertext, utcnow()
    else:
        session.add(UserConnectorCredential(user_id=user_id, provider=PROVIDER,ciphertext=ciphertext))
    session.commit()
    clear_connection_check(session,user_id,'tenable')


def has_tenable_credentials(session: Session, user_id: int) -> bool:
    return session.scalar(select(UserConnectorCredential.id).where(
        UserConnectorCredential.user_id==user_id,
        UserConnectorCredential.provider==PROVIDER)) is not None


def delete_tenable_credentials(session: Session, user_id: int) -> None:
    record=session.scalar(select(UserConnectorCredential).where(
        UserConnectorCredential.user_id==user_id,UserConnectorCredential.provider==PROVIDER))
    if record:
        session.delete(record); session.commit()
        clear_connection_check(session,user_id,'tenable')


def _read_credentials(session: Session, user_id: int) -> dict:
    record = session.scalar(select(UserConnectorCredential).where(
        UserConnectorCredential.user_id==user_id, UserConnectorCredential.provider==PROVIDER))
    if not record:
        raise ConnectorError('Connect your Tenable account under My Profile first')
    try:
        result=json.loads(_fernet().decrypt(record.ciphertext.encode('ascii')))
        return result
    except (InvalidToken, ValueError, TypeError) as exc:
        raise ConnectorError('Stored Tenable credentials could not be decrypted') from exc


def build_tenable_filters(*, severities=None, days=30, time_field='last_seen',
                         start_date='', end_date='', plugin_ids='', tag_category='', tag_value='',
                         states=None, vpr_min=None, tag_filters='', cidr_range='', plugin_family='', severity_modification_type=None):
    """Filter contract for Tenable VM /vulns/export; date upper bound is checked after export."""
    import re
    if time_field not in {'last_seen','last_found','indexed_at'}:
        raise ConnectorError('Invalid date field')
    if not 1 <= int(days) <= 365:
        raise ConnectorError('Days must be between 1 and 365')
    allowed={'info','low','medium','high','critical'}
    normalized=['info' if x.lower() in ('none','informational') else x.lower()
                for x in (severities if severities is not None else list(allowed))]
    if not normalized or any(s not in allowed for s in normalized):
        raise ConnectorError('Invalid severity filter')
    states=states or ['OPEN','REOPENED']
    if any(s not in {'OPEN','REOPENED','FIXED'} for s in states):
        raise ConnectorError('Invalid vulnerability state')
    now=datetime.now(timezone.utc)
    lower=now-timedelta(days=int(days))
    upper=None
    if start_date:
        try: lower=datetime.strptime(start_date,'%Y-%m-%d').replace(tzinfo=timezone.utc)
        except ValueError: raise ConnectorError('Invalid start date (YYYY-MM-DD)') from None
    if end_date:
        try: upper=datetime.strptime(end_date,'%Y-%m-%d').replace(tzinfo=timezone.utc)+timedelta(days=1)
        except ValueError: raise ConnectorError('Invalid end date (YYYY-MM-DD)') from None
        if upper <= lower: raise ConnectorError('End date must follow start date')
        if upper > now + timedelta(days=2): raise ConnectorError('End date cannot be in the distant future')
    filters={'severity':normalized,'state':states, time_field:int(lower.timestamp())}
    if cidr_range.strip():
        import ipaddress
        try:
            network=ipaddress.ip_network(cidr_range.strip(),strict=False)
        except ValueError:
            raise ConnectorError('Invalid CIDR range') from None
        filters['cidr_range']=str(network)
    if plugin_family.strip():
        families=[v.strip() for v in plugin_family.split(',') if v.strip()]
        if not families or len(families)>20 or any(len(x)>100 or any(ord(ch)<32 for ch in x) for x in families):
            raise ConnectorError('Invalid plugin family list')
        filters['plugin_family']=families
    if severity_modification_type:
        valid={'NONE','RECASTED','ACCEPTED'}
        if any(x not in valid for x in severity_modification_type):
            raise ConnectorError('Invalid severity modification type')
        filters['severity_modification_type']=severity_modification_type
    ids=[]
    if plugin_ids.strip():
        parts=[v.strip() for v in plugin_ids.split(',')]
        if len(parts)>50 or any(not v.isdigit() or not 1<=int(v)<=999999999 for v in parts):
            raise ConnectorError('Enter up to 50 comma-separated numeric plugin IDs')
        ids=list(dict.fromkeys(map(int,parts)))
        filters['plugin_id']=ids
    if tag_category or tag_value:
        if (not tag_category or not tag_value or len(tag_category)>100 or len(tag_value)>150 or
            not re.fullmatch(r'[A-Za-z0-9 _.-]+',tag_category)):
            raise ConnectorError('Provide a valid tag category and value')
        filters['tag.'+tag_category]=[tag_value]
    # Additional tags: one "Category=Value1|Value2" expression per line.
    # Different categories are ANDed; values within a category are ORed.
    if tag_filters.strip():
        lines=[line.strip() for line in tag_filters.splitlines() if line.strip()]
        if len(lines)>10: raise ConnectorError('At most 10 tag categories are supported')
        for line in lines:
            if '=' not in line: raise ConnectorError('Tag filters must use Category=Value')
            category,raw_values=line.split('=',1)
            category=category.strip()
            values=[v.strip() for v in raw_values.split('|')]
            if (not re.fullmatch(r'[A-Za-z0-9 _.-]{1,100}',category)
                or not values or len(values)>10 or
                any(not v or len(v)>150 or any(ord(ch)<32 for ch in v) for v in values)):
                raise ConnectorError('Invalid tag category or values')
            key='tag.'+category
            if key in filters:
                filters[key]=list(dict.fromkeys(filters[key]+values))
            else: filters[key]=list(dict.fromkeys(values))
    if vpr_min not in (None,''):
        try: score=float(vpr_min)
        except (TypeError,ValueError): raise ConnectorError('Invalid VPR score') from None
        if not 0<=score<=10: raise ConnectorError('VPR must be between 0 and 10')
        filters['vpr_score']={'gte':score}
    return filters, (time_field, upper)


def export_tenable_vulnerabilities(session: Session, user_id: int, *,
                                   severities: list[str] | None = None,
                                   days: int = 30, time_field: str = 'last_seen',
                                   start_date: str = '', end_date: str = '',
                                   plugin_ids: str = '', tag_category: str = '',
                                   tag_value: str = '', states: list[str] | None = None,
                                   vpr_min: str = '', tag_filters: str = '', cidr_range: str = '', plugin_family: str = '', severity_modification_type: list[str] | None = None, client: httpx.Client | None = None) -> bytes:
    """Explicit bounded synchronous export; never assume chunk identifiers are consecutive."""
    filters, end_rule=build_tenable_filters(severities=severities,days=days,
        time_field=time_field,start_date=start_date,end_date=end_date,
        plugin_ids=plugin_ids,tag_category=tag_category,tag_value=tag_value,
        states=states,vpr_min=vpr_min,tag_filters=tag_filters,cidr_range=cidr_range,plugin_family=plugin_family,severity_modification_type=severity_modification_type)
    credentials=_read_credentials(session,user_id)
    headers={'Accept':'application/json','Content-Type':'application/json',
             'X-ApiKeys':f"accessKey={credentials['access_key']};secretKey={credentials['secret_key']}"}
    own_client=client is None
    c=client or httpx.Client(base_url=BASE, headers=headers, timeout=20.0, follow_redirects=False)
    try:
        created=c.post('/vulns/export',json={'filters':filters,'num_assets':500},headers=headers)
        created.raise_for_status()
        export_id=created.json().get('export_uuid')
        if not isinstance(export_id,str) or not export_id or len(export_id)>100 or not all(x.isalnum() or x=='-' for x in export_id):
            raise ConnectorError('Tenable export did not return a valid export identifier')
        import time
        status=None
        for _ in range(10):
            res=c.get(f'/vulns/export/{export_id}/status',headers=headers)
            res.raise_for_status()
            status=res.json()
            if status.get('status')=='FINISHED': break
            if status.get('status') in ('ERROR','CANCELLED'):
                raise ConnectorError('Tenable export did not complete')
            time.sleep(.3)
        if not status or status.get('status')!='FINISHED':
            raise ConnectorError('Tenable export is still running; narrow filters or retry later')
        if status.get('chunks_failed') or status.get('chunks_cancelled'):
            raise ConnectorError('Tenable returned failed/cancelled chunks; no partial import was performed')
        chunks=status.get('chunks_available') or []
        if not isinstance(chunks,list) or len(chunks)>50:
            raise ConnectorError('Tenable response contains too many chunks')
        rows=[]
        field,upper=end_rule
        for chunk in chunks:
            if not isinstance(chunk,int) or chunk<0: raise ConnectorError('Invalid Tenable chunk ID')
            r=c.get(f'/vulns/export/{export_id}/chunks/{chunk}',headers=headers)
            r.raise_for_status()
            data=r.json()
            if not isinstance(data,list): raise ConnectorError('Unexpected Tenable chunk format')
            for obj in data:
                if upper:
                    value=obj.get(field) if isinstance(obj,dict) else None
                    if isinstance(value,(int,float)) and value>=upper.timestamp(): continue
                    if isinstance(value,str):
                        try:
                            dt=datetime.fromisoformat(value.replace('Z','+00:00'))
                            if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
                            if dt>=upper: continue
                        except ValueError: pass
                rows.append(obj)
            if len(rows)>10_000: raise ConnectorError('Tenable export exceeds 10,000 observations')
        result=json.dumps(rows).encode('utf-8')
        if len(result)>MAX_UPLOAD_BYTES:
            raise ConnectorError('Tenable export exceeds 2 MiB; narrow the filters')
        return result
    except (httpx.TimeoutException,httpx.NetworkError,httpx.HTTPStatusError,ValueError) as exc:
        if isinstance(exc,httpx.HTTPStatusError):
            raise ConnectorError(f'Tenable API returned HTTP {exc.response.status_code}') from None
        if isinstance(exc,httpx.TimeoutException):
            raise ConnectorError('Tenable request timed out') from None
        raise ConnectorError('Tenable export request failed') from None
    finally:
        if own_client: c.close()


def _connector_row(session: Session, user_id: int, provider: str):
    return session.scalar(select(UserConnectorCredential).where(
        UserConnectorCredential.user_id==user_id,UserConnectorCredential.provider==provider))


def has_servicenow_credentials(session: Session, user_id: int) -> bool:
    return _connector_row(session,user_id,'servicenow') is not None


def save_servicenow_credentials(session: Session,user_id:int,instance_url:str,username:str,password:str):
    url=instance_url.strip().rstrip('/')
    parsed=urlparse(url)
    # Narrow allowlist prevents turning this account-level feature into an SSRF proxy.
    if (parsed.scheme!='https' or parsed.username or parsed.password or parsed.port or parsed.path not in ('','/') or
        parsed.query or parsed.fragment or not parsed.hostname or
        not parsed.hostname.endswith('.service-now.com') or len(parsed.hostname)>160 or
        parsed.hostname.count('.')<2):
        raise ConnectorError('Enter a valid HTTPS instance URL ending in .service-now.com')
    if not username.strip() or not password or len(username)>160 or len(password)>400:
        raise ConnectorError('Provide a ServiceNow account name and password')
    payload=json.dumps({'instance_url':url,'username':username.strip(),'password':password}).encode()
    encrypted=_fernet().encrypt(payload).decode('ascii')
    row=_connector_row(session,user_id,'servicenow')
    if row: row.ciphertext=encrypted;row.updated_at=utcnow()
    else: session.add(UserConnectorCredential(user_id=user_id,provider='servicenow',ciphertext=encrypted))
    session.commit()
    clear_connection_check(session,user_id,'servicenow')


def read_servicenow_credentials(session: Session,user_id:int):
    row=_connector_row(session,user_id,'servicenow')
    if not row: raise ConnectorError('Configure ServiceNow under Integrations first')
    try: return json.loads(_fernet().decrypt(row.ciphertext.encode()))
    except (InvalidToken,ValueError,TypeError):
        raise ConnectorError('ServiceNow credentials cannot be decrypted') from None


def servicenow_request(session:Session,user_id:int,method:str,path:str,body=None,client:httpx.Client|None=None):
    """Restrict all calls to fixed incident endpoint paths. MockTransport-compatible."""
    import re
    if not re.fullmatch(r'/api/now/table/incident(?:/[0-9a-fA-F]{32})?',path):
        raise ConnectorError('Unsupported ServiceNow request path')
    if method not in {'GET','POST','PATCH'}: raise ConnectorError('Unsupported ServiceNow method')
    cfg=read_servicenow_credentials(session,user_id)
    own=client is None
    c=client or httpx.Client(base_url=cfg['instance_url'],auth=(cfg['username'],cfg['password']),
                             follow_redirects=False,timeout=15.0)
    try:
        res=c.request(method, path, json=body, headers={'Accept':'application/json',
                      'Content-Type':'application/json'})
        res.raise_for_status()
        obj=res.json()
        if not isinstance(obj,dict) or not isinstance(obj.get('result'),dict):
            raise ConnectorError('Invalid ServiceNow API response')
        return obj['result']
    except httpx.HTTPStatusError as exc:
        raise ConnectorError(f'ServiceNow API returned HTTP {exc.response.status_code}') from None
    except (httpx.TimeoutException,httpx.NetworkError,httpx.DecodingError):
        raise ConnectorError('ServiceNow request failed') from None
    finally:
        if own: c.close()


def check_tenable_connection(session: Session, user_id: int, client: httpx.Client | None = None) -> str:
    """Test saved API keys on a read-only, authenticated endpoint.

    A stored encrypted key is not evidence that credentials are currently valid.
    """
    keys = _read_credentials(session, user_id)
    headers={'Accept':'application/json','X-ApiKeys':f"accessKey={keys['access_key']};secretKey={keys['secret_key']}"}
    own=client is None
    c=client or httpx.Client(base_url=BASE, timeout=12.0, follow_redirects=False)
    try:
        res=c.get('/users',headers=headers)
        res.raise_for_status()
        if not isinstance(res.json(),dict):
            raise ConnectorError('Tenable returned an unexpected response')
        return 'Tenable API credentials accepted'
    except httpx.HTTPStatusError as exc:
        raise ConnectorError(f'Tenable connection rejected (HTTP {exc.response.status_code})') from None
    except (httpx.HTTPError,ValueError):
        raise ConnectorError('Tenable connection could not be verified') from None
    finally:
        if own:c.close()


def check_servicenow_connection(session: Session, user_id: int, client: httpx.Client | None = None) -> str:
    """Read-only access check using the same group table that provides assignments."""
    from app.servicenow import search_groups
    search_groups(session,user_id,'',client=client)
    return 'ServiceNow group directory accessible'


def connection_check(session:Session,user_id:int,provider:str):
    return session.scalar(select(ConnectorHealthCheck).where(
        ConnectorHealthCheck.user_id==user_id,ConnectorHealthCheck.provider==provider))


def record_connection_check(session:Session,user_id:int,provider:str,success:bool)->None:
    if provider not in {'tenable','servicenow'}:raise ConnectorError('Unknown connector provider')
    row=connection_check(session,user_id,provider)
    if row:
        row.success=success;row.checked_at=utcnow()
    else:
        session.add(ConnectorHealthCheck(user_id=user_id,provider=provider,success=success))
    session.commit()


def clear_connection_check(session:Session,user_id:int,provider:str):
    row=connection_check(session,user_id,provider)
    if row:session.delete(row);session.commit()
