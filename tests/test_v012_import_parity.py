"""v0.12 Source-specific source mapping and encrypted-connector regressions."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, func

from app.importers import parse_source, ImportValidationError
from app.models import (Finding, Vulnerability, Observation,
                        ObservationSourceMetadata, UserConnectorCredential)
from app.services import import_findings
from app.connectors import (save_tenable_credentials, has_tenable_credentials,
                            delete_tenable_credentials, export_tenable_vulnerabilities,
                            ConnectorError)
from test_v06_auth import web,login_as


def test_plextrac_bulletproof_pairs_ports_url_date_and_plugin_key():
    flaw={'flaws_array': [{'title':'Access control test', 'severity':'Low',
        'createdAt':1735689600000, 'description':'<p>Access <b>control</b> issue</p>',
        'recommendations':'<p>Apply authentication controls</p>',
        'exhibits':[{'exhibitID':'proof.png', 'type':'image/png'}],
        'affected_assets': [
          [1, {'asset':'https://api.example.test/v2/admin', 'ports':[[1,{'number':443,'protocol':'tcp'}]]}],
          [2, {'asset':'192.0.2.20 (tcp 8080; 80)'}]
        ]}]}
    result=parse_source(json.dumps(flaw).encode(), 'plextrac_json')
    assert len(result)==2
    assert all(row.plugin_id==hashlib.md5(b'Access control test').hexdigest() for row in result)
    assert result[0].asset=='api.example.test'
    assert result[0].location=='443/tcp | /v2/admin'
    assert result[1].asset=='192.0.2.20'
    assert result[1].port=='8080'
    assert result[0].description=='Access control issue'
    assert result[0].detected_at==datetime(2025,1,1)
    assert result[0].source_metadata['exhibits'][0]['exhibitID']=='proof.png'


def test_plextrac_fallback_merged_assets():
    raw={'flaws_array':[{'title':'Fallback','severity':'Informational',
                         'fields':{'merged_assets':{'value':'192.0.2.19 (tcp 443)'}}}]}
    result=parse_source(json.dumps(raw).encode(),'plextrac_json')
    assert len(result)==1 and result[0].asset=='192.0.2.19'


def test_sec1_positional_csv_full_severity():
    fields=['Report finding','unused','unused','Informational','unused',
            'web01.example.test, web02.example.test','Detailed description','Fix 1','Fix 2','proof.png']
    import csv,io
    buf=io.StringIO();csv.writer(buf).writerow(fields)
    rows=parse_source(buf.getvalue().encode(),'sec1_csv')
    assert len(rows)==2
    assert rows[0].severity=='Informational'
    assert rows[0].remediation=='Fix 1\n\nFix 2'
    assert rows[0].source_metadata['original_images']=='proof.png'


def test_tenable_export_fields_timestamp_and_no_risk_filter():
    body=[{'plugin':{'id':104743,'name':'TLS weak version','description':'Detailed vuln',
                    'solution':'Disable TLSv1', 'risk_factor':'medium',
                    'see_also':['https://example.test/advisory'], 'exploit_available':False},
            'asset':{'ipv4':'192.0.2.14','fqdn':'web01.example.test','tags':[{'key':'env','value':'dev'}]},
            'port':{'port':443,'protocol':'TCP'},
            'output':'Protocol TLSv1 accepted','first_found':'2026-11-10T11:10:00Z',
            'last_found':'2026-11-16T11:10:00Z'}]
    rows=parse_source(json.dumps(body).encode(),'tenable_json')
    assert len(rows)==1
    assert rows[0].asset=='192.0.2.14'
    assert rows[0].plugin_id==hashlib.md5(b'104743').hexdigest()
    assert rows[0].location=='443/tcp'
    assert rows[0].detected_at==datetime(2026,11,10,11,10)
    assert rows[0].source_metadata['nessus_id']=='104743'
    assert 'Additional info:' in rows[0].remediation
    assert rows[0].source_metadata['tags'][0]['value']=='dev'


def test_nessus_html_report_sections():
    html='''<div class="table-wrapper details"><table><tr><td>DNS Name:</td><td>web.example.test</td></tr></table></div>
    <div id="id6">106375 - nginx HTTP Server Detection -</div>
    <div class="section-wrapper"><div class="details-header">Description</div><div>Detected nginx</div>
    <div class="details-header">Solution</div><div>Upgrade</div>
    <div class="details-header">Risk Factor</div><div>None</div>
    <div class="details-header">Plugin Output</div><div>tcp/80/www nginx 1.2.3</div></div>'''
    rows=parse_source(html.encode(),'nessus_html')
    assert len(rows)==1
    assert rows[0].asset=='web.example.test'
    assert rows[0].title=='nginx HTTP Server Detection'
    assert rows[0].severity=='Informational'
    assert rows[0].plugin_id=='106375'
    assert rows[0].location=='80/tcp'


def test_import_stores_source_metadata_and_detection_times(db_session):
    raw=json.dumps([{'plugin':{'id':'100','name':'Test issue','risk_factor':'Low'},
        'asset':{'ipv4':'192.0.2.50'},'first_found':'2026-03-17T00:00:00Z'}]).encode()
    stats=import_findings(db_session,raw,'tenable.json','tenable_json')
    assert stats.observations_created==1
    ob=db_session.scalar(select(Observation))
    assert ob.detected_at==datetime(2026,3,17)
    assert db_session.scalar(select(Finding)).first_seen==datetime(2026,3,17)
    md=db_session.get(ObservationSourceMetadata,ob.id)
    assert json.loads(md.source_data)['nessus_id']=='100'


def test_fernet_credentials_encrypt_and_delete_per_user(db_session,monkeypatch):
    from app.models import UserAccount
    user=UserAccount(username='a',name='A',email='a@demo.test',password_hash='test')
    user2=UserAccount(username='b',name='B',email='b@demo.test',password_hash='test')
    db_session.add_all([user,user2]);db_session.commit()
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    save_tenable_credentials(db_session,user.id,'safe-access-key','safe-secret-key')
    record=db_session.scalar(select(UserConnectorCredential))
    assert 'safe-access-key' not in record.ciphertext
    assert 'safe-secret-key' not in record.ciphertext
    assert has_tenable_credentials(db_session,user.id)
    assert not has_tenable_credentials(db_session,user2.id)
    delete_tenable_credentials(db_session,user.id)
    assert not has_tenable_credentials(db_session,user.id)


def test_missing_encryption_key_fails_closed(db_session,monkeypatch):
    monkeypatch.delenv('ARBITRATOR_CREDENTIAL_KEY',raising=False)
    with pytest.raises(ConnectorError, match='not configured'):
        save_tenable_credentials(db_session,99,'safe-access-key','safe-secret-key')
    assert db_session.scalar(select(func.count()).select_from(UserConnectorCredential))==0


def test_mocked_tenable_export_api_no_external_network(db_session,monkeypatch):
    from app.models import UserAccount
    user=UserAccount(username='a',name='A',email='a@demo.test',password_hash='test')
    db_session.add(user);db_session.commit()
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    save_tenable_credentials(db_session,user.id,'safe-access-key','safe-secret-key')
    calls=[]
    def handle(req):
        assert 'safe-secret-key' in req.headers['X-ApiKeys']
        calls.append(req.url.path)
        if req.url.path=='/vulns/export':
            body=json.loads(req.content)
            assert 'info' in body['filters']['severity']
            return httpx.Response(200,json={'export_uuid':'abc123'})
        if req.url.path=='/vulns/export/abc123/status':
            return httpx.Response(200,json={'status':'FINISHED','chunks_available':[0]})
        return httpx.Response(200,json=[{'asset':{'ipv4':'192.0.2.1'},
                                       'plugin':{'id':99,'name':'Check','risk_factor':'Low'}}])
    with httpx.Client(base_url='https://cloud.tenable.com',transport=httpx.MockTransport(handle)) as c:
        raw=export_tenable_vulnerabilities(db_session,user.id,days=15,client=c)
    assert len(parse_source(raw,'tenable_json'))==1
    assert len(calls)==3


def test_v012_ui_profile_import_admin_connector_navigation(web,monkeypatch):
    client,factory=web
    from app.services import create_assessment
    with factory() as db:
        create_assessment(db,'Synthetic test','Tenable check')
    token=login_as(client,'admin')
    profile=client.get('/account/profile')
    assert 'name="theme"' in profile.text
    assert 'name="access_key"' not in profile.text
    assert 'name="access_key"' in client.get('/integrations').text
    assert client.get('/imports').status_code==200
    html=client.get('/imports').text
    assert 'value="nessus_html"' not in html
    assert 'value="tenable_json"' not in html
    assert 'value="sec1_csv"' not in html
    assert 'Run Tenable export' not in html  # not configured yet
    assert client.get('/admin/connectors').status_code==200
    assert 'Organization integrations' in client.get('/admin/users').text
    login_as(client,'viewer')
    assert client.get('/admin/connectors').status_code==403
    assert client.post('/account/connectors/tenable',data={'access_key':'akey123456',
        'secret_key':'skey123456'},follow_redirects=False).status_code==422 # CSRF mandatory


def test_old_sec1_csv_positions_are_preserved():
    columns=['0','Legacy issue','2','3','High/80','Explanation','Solution','192.0.2.3, 192.0.2.4']
    import csv,io
    buf=io.StringIO();csv.writer(buf).writerow(columns)
    rows=parse_source(buf.getvalue().encode(),'old_sec1_csv')
    assert len(rows)==2
    assert rows[0].asset=='192.0.2.3'
    assert rows[0].severity=='High'
    assert rows[0].plugin_id==hashlib.md5(b'Legacy issue').hexdigest()


def test_nessus_csv_retains_original_extra_columns():
    data=b'Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output\n100,CVE-2026-1111,7.2,High,192.0.2.3,tcp,443,Weak TLS,summary,details,fix,proof\n'
    rows=parse_source(data,'nessus_csv')
    assert len(rows)==1
    assert rows[0].plugin_id=='100'
    assert rows[0].description=='details'
    assert rows[0].source_metadata['csv_columns']['CVSS']=='7.2'


def test_user_can_save_connect_and_import_mocked_tenable(web,monkeypatch):
    from app.services import create_assessment
    from app import main
    client,factory=web
    with factory() as db:
        assessment=create_assessment(db,'Test integration','Remote source')
    token=login_as(client,'admin')
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    response=client.post('/account/connectors/tenable',data={'csrf_token':token,
        'access_key':'test_access_1234','secret_key':'test_secret_5678'},follow_redirects=False)
    assert response.status_code==303
    profile=client.get('/integrations').text
    assert 'Credentials saved' in profile
    assert 'test_secret_5678' not in profile
    assert 'test_access_1234' in profile  # privileged integration manager can identify configured access key
    with factory() as db:
        assert has_tenable_credentials(db,1)
    monkeypatch.setattr(main,'export_tenable_vulnerabilities',lambda *args,**kwargs:json.dumps([
        {'plugin':{'id':123,'name':'Weak header','risk_factor':'informational'},
         'asset':{'ipv4':'192.0.2.61'}, 'output':'Synthetic proof'}]).encode())
    response=client.post('/imports/tenable',data={'csrf_token':token,'assessment_id':assessment.id,'days':30},
        follow_redirects=False)
    assert response.status_code==303
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Observation))==1
        assert db.scalar(select(Finding)).severity=='Informational'
    assert 'Connected' not in client.get('/admin/connectors').text or 'Configured' in client.get('/admin/connectors').text
