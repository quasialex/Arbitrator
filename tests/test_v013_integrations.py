"""v0.13 integration contract checks. No external network required."""
import json
import os
import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, func
from app.models import (
    UserAccount, Asset, Owner, Vulnerability, Finding, Engagement, Assessment,
    ImportBatch, Observation, GovernanceDecision,
    UserConnectorCredential, ServiceNowIncidentLink, ServiceNowSyncRecord,
)
from app.connectors import (
    ConnectorError, build_tenable_filters, save_tenable_credentials,
    export_tenable_vulnerabilities, save_servicenow_credentials, servicenow_request,
)
from app.servicenow import configure_group, create_incident, refresh_incident, sync_finding_notes
from app.importers import parse_source

@pytest.fixture
def demo_account(db_session,monkeypatch):
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    acc=UserAccount(username='tester',name='Test User',email='tester@example.test',password_hash='p')
    db_session.add(acc);db_session.commit()
    return acc


def test_tenable_filter_contract_custom_fields():
    filters, (time_field, upper)=build_tenable_filters(
        severities=['informational','high'],days=14,time_field='last_seen',
        start_date='2026-10-01',end_date='2026-10-15',
        plugin_ids='104743, 19506',tag_category='Environment',tag_value='Production',vpr_min='5.5',tag_filters='Business Criticality=High|Critical')
    assert filters['severity']==['info','high']
    assert filters['plugin_id']==[104743,19506]
    assert filters['tag.Environment']==['Production']
    assert filters['tag.Business Criticality']==['High','Critical']
    assert filters['vpr_score']=={'gte':5.5}
    assert time_field=='last_seen'
    assert upper.isoformat().startswith('2026-10-16')
    assert filters['last_seen']>0


@pytest.mark.parametrize('arguments',[
 {'plugin_ids':'104743, abc'}, {'tag_category':'env/../../p','tag_value':'prod'},
 {'time_field':'invalid'}, {'start_date':'2026-11-12','end_date':'2026-10-20'},
 {'vpr_min':'100'}, {'days':366}
])
def test_tenable_filter_validation_rejects_bad_input(arguments):
    with pytest.raises(ConnectorError): build_tenable_filters(**arguments)


def test_tenable_async_chunk_export_nonsequential_and_filtered(db_session,demo_account):
    save_tenable_credentials(db_session,demo_account.id,'validAccess123','validSecret456')
    paths=[]
    def handler(req):
        paths.append(req.url.path)
        if req.url.path=='/vulns/export':
            body=json.loads(req.content)
            assert body['filters']['plugin_id']==[123]
            assert body['filters']['tag.Environment']==['Prod']
            return httpx.Response(200,json={'export_uuid':'abc123'})
        if req.url.path.endswith('/status'):
            return httpx.Response(200,json={'status':'FINISHED','chunks_available':[8,2]})
        return httpx.Response(200,json=[{
            'asset':{'ipv4':'192.0.2.8'},'plugin':{'id':123,'name':'Weak header','risk_factor':'Info'},
            'last_seen':'2026-10-12T00:00:00Z'}])
    with httpx.Client(base_url='https://cloud.tenable.com',transport=httpx.MockTransport(handler)) as c:
        result=export_tenable_vulnerabilities(db_session,demo_account.id,days=60,
            start_date='2026-10-01',end_date='2026-10-20',
            plugin_ids='123',tag_category='Environment',tag_value='Prod',client=c)
    assert len(parse_source(result,'tenable_json'))==2
    assert paths[-2:] == ['/vulns/export/abc123/chunks/8','/vulns/export/abc123/chunks/2']


def test_servicenow_instance_restriction_and_encryption(db_session,demo_account):
    with pytest.raises(ConnectorError):
        save_servicenow_credentials(db_session,demo_account.id,
            'http://127.0.0.1','robot','password')
    with pytest.raises(ConnectorError):
        save_servicenow_credentials(db_session,demo_account.id,
            'https://demo.service-now.com.attacker.test','robot','password')
    save_servicenow_credentials(db_session,demo_account.id,
        'https://demo.service-now.com','robot','test-password')
    row=db_session.scalar(select(UserConnectorCredential).where(
        UserConnectorCredential.provider=='servicenow'))
    assert row and 'test-password' not in row.ciphertext
    with pytest.raises(ConnectorError):
        servicenow_request(db_session,demo_account.id,'GET','/api/now/table/sys_user_group')


@pytest.fixture
def demo_finding(db_session):
    team=Owner(name='API Team')
    asset=Asset(identity_key='api01.example.test',display_name='api01.example.test')
    vuln=Vulnerability(source='generic_csv',external_key='weak-auth',title='Weak authentication',
        description='No rate limit',remediation='Add rate limiting')
    db_session.add_all([team,asset,vuln]);db_session.flush()
    finding=Finding(fingerprint='f'*64,asset_id=asset.id,vulnerability_id=vuln.id,
                    severity='High',assigned_owner_id=team.id)
    db_session.add(finding);db_session.commit()
    return finding,team


def test_servicenow_incident_and_idempotent_sync(db_session,demo_account,demo_finding):
    finding,team=demo_finding
    save_servicenow_credentials(db_session,demo_account.id,
        'https://demo.service-now.com','robot','test-password')
    configure_group(db_session,team.id,'a'*32)
    engagement=Engagement(name='Test engagement',client='Example')
    db_session.add(engagement);db_session.flush()
    assessment=Assessment(engagement_id=engagement.id,name='Web test')
    db_session.add(assessment);db_session.flush()
    batch=ImportBatch(assessment_id=assessment.id,source='generic_csv',original_filename='fixture.csv',
                      content_hash='e'*64)
    db_session.add(batch);db_session.flush()
    obs=Observation(finding_id=finding.id,batch_id=batch.id,row_hash='a'*64,evidence='Synthetic check')
    dec=GovernanceDecision(finding_id=finding.id,action='request_remediation',
        decided_by='Test User',actor_user_id=demo_account.id,rationale='Please remediate soon.')
    db_session.add_all([obs,dec]);db_session.commit()
    sent=[]
    def handler(req):
        sent.append((req.method,req.url.path,req.content.decode() if req.content else ''))
        if req.method=='POST':
            assert '"assignment_group":"'+('a'*32)+'"' in req.content.decode()
            return httpx.Response(201,json={'result':{'sys_id':'b'*32,'number':'INC00123','state':'1'}})
        if req.method=='PATCH': return httpx.Response(200,json={'result':{'state':'2'}})
        if req.method=='GET': return httpx.Response(200,json={'result':{'state':'2'}})
        return httpx.Response(400)
    with httpx.Client(base_url='https://demo.service-now.com',transport=httpx.MockTransport(handler)) as c:
        one=create_incident(db_session,finding.id,demo_account.id,client=c)
        again=create_incident(db_session,finding.id,demo_account.id,client=c)
        assert again.number==one.number
        assert one.state=='New'
        assert sync_finding_notes(db_session,finding.id,demo_account.id,client=c)==2
        assert sync_finding_notes(db_session,finding.id,demo_account.id,client=c)==0
        refreshed=refresh_incident(db_session,finding.id,demo_account.id,client=c)
        assert refreshed.state=='In Progress'
    assert len([m for m in sent if m[0]=='POST'])==1
    assert len([m for m in sent if m[0]=='PATCH'])==2
    assert db_session.scalar(select(func.count()).select_from(ServiceNowSyncRecord))==2


def test_servicenow_requires_responsible_team_mapping(db_session,demo_account,demo_finding):
    finding,team=demo_finding
    save_servicenow_credentials(db_session,demo_account.id,
        'https://demo.service-now.com','robot','test-password')
    with pytest.raises(ConnectorError,match='Map this remediation team'):
        create_incident(db_session,finding.id,demo_account.id)


def test_unified_generic_import_supports_consultant_csv():
    import csv,io
    row=['SQL injection','x','x','High','x','web01.example.test','desc','rec','verify','img']
    buf=io.StringIO();csv.writer(buf).writerow(row)
    parsed=parse_source(buf.getvalue().encode(),'generic_csv')
    assert len(parsed)==1
    assert parsed[0].asset=='web01.example.test'
    assert parsed[0].severity=='High'
