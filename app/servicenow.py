"""Finding-level ServiceNow integration with explicit human-triggered synchronization."""
from __future__ import annotations
import re
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import (
    Finding, Owner, ServiceNowGroupMapping, ServiceNowIncidentLink,
    ServiceNowSyncRecord, GovernanceDecision, Observation, ImportBatch, utcnow
)
from app.connectors import ConnectorError, servicenow_request, read_servicenow_credentials


def _ident(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-fA-F0-9]{32}',value):
        raise ConnectorError('ServiceNow returned an invalid sys_id')
    return value.lower()


def configure_group(session: Session, team_id:int,group_sys_id:str,group_name:str="",group_email:str=""):
    _ident(group_sys_id)
    if not session.get(Owner,team_id): raise ConnectorError('Unknown remediation team')
    row=session.get(ServiceNowGroupMapping,team_id)
    if row:
        row.group_sys_id=group_sys_id.lower()
        row.group_name=group_name[:200]
        row.group_email=group_email[:255]
    else: session.add(ServiceNowGroupMapping(team_id=team_id,group_sys_id=group_sys_id.lower(),group_name=group_name[:200],group_email=group_email[:255]))
    session.commit()


def describe_state(value) -> str:
    if isinstance(value,dict):
        value=value.get('display_value') or value.get('value') or 'Unknown'
    return {'1':'New','2':'In Progress','3':'On Hold','6':'Resolved','7':'Closed','8':'Canceled'}.get(str(value),str(value))


def create_incident(session:Session, finding_id:int, user_id:int,client=None,credential_user_id:int|None=None):
    existing=session.get(ServiceNowIncidentLink,finding_id)
    if existing: return existing
    finding=session.get(Finding,finding_id)
    if not finding: raise ConnectorError('Finding not found')
    if not finding.assigned_owner_id: raise ConnectorError('Assign a remediation team first')
    mapping=session.get(ServiceNowGroupMapping,finding.assigned_owner_id)
    if not mapping: raise ConnectorError('Map this remediation team to a ServiceNow group under Integrations')
    asset=finding.asset
    vuln=finding.vulnerability
    urgency={'Critical':'1','High':'1','Medium':'2','Low':'3','Informational':'3'}.get(finding.severity,'3')
    description=(f"Arbitrator finding #{finding.id}\\nAsset: {asset.display_name}\\n"
        f"Severity: {finding.severity}\\nLocation: {finding.location or 'N/A'}\\n"
        f"Plugin/reference: {vuln.external_key}\\n\\n"
        f"Description:\\n{vuln.description}\\n\\nRemediation:\\n{vuln.remediation}")[:8000]
    body={'short_description':f"[Arbitrator #{finding.id}] {vuln.title}"[:160],
          'description':description,'assignment_group':mapping.group_sys_id,
          'urgency':urgency,'impact':urgency,'correlation_id':f'arbitrator-finding-{finding.id}'}
    result=servicenow_request(session,credential_user_id or user_id,'POST','/api/now/table/incident',body,client=client)
    sys_id=_ident(result.get('sys_id'))
    number=result.get('number')
    if not isinstance(number,str) or not re.fullmatch(r'[A-Za-z0-9_-]{3,40}',number):
        raise ConnectorError('ServiceNow returned an invalid incident number')
    instance=read_servicenow_credentials(session,credential_user_id or user_id)['instance_url']
    link=ServiceNowIncidentLink(finding_id=finding.id,instance_url=instance,sys_id=sys_id,
      number=number,state=describe_state(result.get('state',result.get('incident_state','New'))),
      last_checked_at=utcnow(),created_by_id=user_id)
    session.add(link);session.commit()
    return link


def refresh_incident(session:Session,finding_id:int,user_id:int,client=None,credential_user_id:int|None=None):
    link=session.get(ServiceNowIncidentLink,finding_id)
    if not link: raise ConnectorError('No linked incident')
    instance=read_servicenow_credentials(session,credential_user_id or user_id)['instance_url']
    if instance!=link.instance_url: raise ConnectorError('Your ServiceNow connection belongs to a different instance')
    result=servicenow_request(session,credential_user_id or user_id,'GET',
        f'/api/now/table/incident/{_ident(link.sys_id)}',client=client)
    link.state=describe_state(result.get('state',result.get('incident_state','Unknown')))
    link.last_checked_at=utcnow();session.commit()
    return link


def sync_finding_notes(session:Session,finding_id:int,user_id:int,client=None,only_decision_id:int|None=None,credential_user_id:int|None=None):
    link=session.get(ServiceNowIncidentLink,finding_id)
    if not link: raise ConnectorError('Create a ServiceNow incident before syncing')
    instance=read_servicenow_credentials(session,credential_user_id or user_id)['instance_url']
    if link.instance_url!=instance: raise ConnectorError('The linked incident belongs to a different instance')
    decision_stmt=select(GovernanceDecision).where(GovernanceDecision.finding_id==finding_id)
    if only_decision_id is not None:
        decision_stmt=decision_stmt.where(GovernanceDecision.id==only_decision_id)
    decisions=session.scalars(decision_stmt.order_by(GovernanceDecision.id)).all()
    observations=([] if only_decision_id is not None else session.scalars(
        select(Observation).where(Observation.finding_id==finding_id)
        .order_by(Observation.id)).all())
    count=0
    for category,records in [('observation',observations),('decision',decisions)]:
        for rec in records:
            exists=session.scalar(select(ServiceNowSyncRecord.id).where(
                ServiceNowSyncRecord.finding_id==finding_id,
                ServiceNowSyncRecord.item_type==category,
                ServiceNowSyncRecord.item_id==rec.id))
            if exists: continue
            if category=='observation':
                batch=session.get(ImportBatch,rec.batch_id)
                note=(f"Arbitrator observation #{rec.id} · {batch.source} · "
                      f"{rec.detected_at.isoformat()} UTC\\n{rec.evidence}")[:4000]
            else:
                note=(f"Arbitrator governance decision #{rec.id}: {rec.action} by {rec.decided_by} "
                      f"on {rec.created_at.isoformat()} UTC.\\n"
                      f"Rationale: {rec.rationale}\\nReview: {rec.review_date or 'N/A'}")[:4000]
            servicenow_request(session,credential_user_id or user_id,'PATCH',
                 f'/api/now/table/incident/{_ident(link.sys_id)}',
                 {'work_notes':note},client=client)
            session.add(ServiceNowSyncRecord(finding_id=finding_id,item_type=category,
                item_id=rec.id,actor_user_id=user_id))
            session.commit()
            count+=1
    return count


def search_groups(session:Session, user_id:int, term:str, client=None) -> list[dict]:
    """Bounded assignment-group name search using the ServiceNow API."""
    if len(term)>70 or any(ord(ch)<32 for ch in term) or any(ch in '^=@' for ch in term):
        raise ConnectorError('Invalid group search text')
    cfg=read_servicenow_credentials(session,user_id)
    import httpx
    own=client is None
    c=client or httpx.Client(base_url=cfg['instance_url'],auth=(cfg['username'],cfg['password']),
                             follow_redirects=False,timeout=15.0)
    try:
        query='active=true'+('^nameLIKE'+term.strip() if term.strip() else '')
        response=c.get('/api/now/table/sys_user_group',params={
            'sysparm_query':query,'sysparm_fields':'sys_id,name,email,active',
            'sysparm_limit':'25'},headers={'Accept':'application/json'})
        response.raise_for_status()
        data=response.json()
        if not isinstance(data,dict) or not isinstance(data.get('result'),list):
            raise ConnectorError('ServiceNow returned an invalid group directory')
        result=[]
        for item in data['result']:
            if not isinstance(item,dict):continue
            try: ident=_ident(item.get('sys_id'))
            except ConnectorError:continue
            name=item.get('name') or ''
            email=item.get('email') or ''
            if not isinstance(name,str) or not name.strip():continue
            result.append({'sys_id':ident,'name':name[:200],
                           'email': email[:255] if isinstance(email,str) else ''})
        return result
    except httpx.HTTPStatusError as exc:
        raise ConnectorError(f'ServiceNow group search rejected (HTTP {exc.response.status_code})') from None
    except (httpx.HTTPError,ValueError):
        raise ConnectorError('ServiceNow group directory unavailable') from None
    finally:
        if own:c.close()


def select_group(session:Session,user_id:int,team_id:int,sys_id:str,client=None):
    """Verify group remotely before persisting its sys_id and display metadata."""
    ident=_ident(sys_id)
    cfg=read_servicenow_credentials(session,user_id)
    import httpx
    own=client is None
    c=client or httpx.Client(base_url=cfg['instance_url'],auth=(cfg['username'],cfg['password']),
                             follow_redirects=False,timeout=15.0)
    try:
        response=c.get('/api/now/table/sys_user_group/'+ident,
            params={'sysparm_fields':'sys_id,name,email,active'},headers={'Accept':'application/json'})
        response.raise_for_status()
        row=response.json().get('result')
        if not isinstance(row,dict) or _ident(row.get('sys_id'))!=ident:
            raise ConnectorError('Selected ServiceNow group could not be verified')
        if row.get('active') in (False,'false','False','0'):
            raise ConnectorError('Cannot assign an inactive ServiceNow group')
        name=row.get('name')
        email=row.get('email') or ''
        if not isinstance(name,str) or not name.strip():
            raise ConnectorError('ServiceNow group has no name')
        configure_group(session,team_id,ident,name,email if isinstance(email,str) else '')
    except httpx.HTTPStatusError as exc:
        raise ConnectorError(f'ServiceNow group lookup rejected (HTTP {exc.response.status_code})') from None
    except (httpx.HTTPError,ValueError):
        raise ConnectorError('ServiceNow group lookup failed') from None
    finally:
        if own:c.close()
