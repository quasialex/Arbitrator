"""v0.15: shared connectors, privileged presentation and scoped re-evaluation."""
from __future__ import annotations

from pathlib import Path
from cryptography.fernet import Fernet
from sqlalchemy import select
from test_v06_auth import web, login_as
from app.models import AccessRole, Finding, UserAccount
from app.services import create_assessment, import_findings
from app.workflows import create_team, assign_finding
from app.routing import create_routing_rule
from app.auth import create_user


def test_shared_tenable_credential_is_locked_and_visible_only_to_manager(web,monkeypatch):
    client,factory=web
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    token=login_as(client,'admin')
    saved=client.post('/account/connectors/tenable',data={
        'csrf_token':token,'access_key':'account_12345678','secret_key':'protected_secret_123'},follow_redirects=False)
    assert saved.status_code==303
    html=client.get('/integrations').text
    assert 'Credentials saved · Not verified' in html
    assert 'value="account_12345678" readonly' in html
    assert 'protected_secret_123' not in html
    assert 'Edit connection' in html and 'Test connection' in html and 'Disconnect' in html
    assert 'saved-credentials' in html
    login_as(client,'viewer')
    html=client.get('/integrations').text
    assert 'Credentials saved · Not verified' in html
    assert 'account_12345678' not in html
    token=client.get('/account/profile').text.split('name="csrf_token" value="')[1].split('"')[0]
    assert client.post('/account/connectors/tenable/delete',data={'csrf_token':token},follow_redirects=False).status_code==403
    assert client.post('/account/connectors/tenable',data={'csrf_token':token,
        'access_key':'attacker_key_123','secret_key':'attacker_secret_123'},follow_redirects=False).status_code==403
    login_as(client,'admin')
    assert 'account_12345678' in client.get('/integrations').text


def test_shared_servicenow_credential_masks_password_and_permissions(web,monkeypatch):
    client,factory=web
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    token=login_as(client,'admin')
    saved=client.post('/integrations/servicenow',data={
        'csrf_token':token,'instance_url':'https://sandbox.service-now.com',
        'username':'svc-arbitrator','password':'an_example_secret'},follow_redirects=False)
    assert saved.status_code==303
    html=client.get('/integrations').text
    assert 'https://sandbox.service-now.com' in html
    assert 'svc-arbitrator' in html
    assert 'an_example_secret' not in html
    assert 'Saved' in html
    login_as(client,'viewer')
    html=client.get('/integrations').text
    assert 'svc-arbitrator' not in html
    assert 'https://sandbox.service-now.com' not in html


def test_profile_password_embedded_and_old_url_compatibility(web):
    client,_=web
    login_as(client,'admin')
    html=client.get('/account/profile').text
    assert 'Profile details' in html and 'Change password' in html
    assert 'name="previous"' in html and 'name="confirm"' in html
    assert 'Appearance' in html and 'Access &amp; security' in html
    assert 'account-profile-grid' in html
    assert '<a href="/account/password">Change password</a>' not in html
    assert client.get('/account/password',follow_redirects=False).headers['location']=='/account/profile'


def test_scoped_routing_targets_one_finding_and_preserves_manual(web):
    client,factory=web
    with factory() as db:
        assessment=create_assessment(db,'Scope Lab','Web audit')
        import_findings(db,b'asset,title,severity\nweb01.corp.test,Weak TLS,High\ndb01.corp.test,Outdated DB,Medium\n',
                        'sample.csv','generic_csv',assessment.id)
        findings=db.scalars(select(Finding).order_by(Finding.id)).all()
        selected,other=findings
        team=create_team(db,'Ops','ops@example.test')
        manual=create_team(db,'Database','db@example.test')
        create_routing_rule(db,team.id,'hostname_suffix','corp.test','none','')
        selected_id,other_id=selected.id,other.id
        assign_finding(db,other_id,str(manual.id))
        team_id,manual_id=team.id,manual.id
    token=login_as(client,'admin')
    result=client.post('/ownership/routing/apply-scoped',data={
        'csrf_token':token,'scope':'finding','pattern':str(selected_id)},follow_redirects=False)
    assert result.status_code==303
    with factory() as db:
        assert db.get(Finding,selected_id).assigned_owner_id==team_id
        assert db.get(Finding,other_id).assigned_owner_id==manual_id
        assert db.get(Finding,other_id).assignment_source=='manual'
    bad=client.post('/ownership/routing/apply-scoped',data={
        'csrf_token':token,'scope':'cidr','pattern':'not-a-cidr'},follow_redirects=False)
    assert bad.status_code==303 and 'Invalid' not in (bad.headers['location'])


def test_shared_connector_management_custom_role(web,monkeypatch):
    client,factory=web
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    with factory() as db:
        manager_role=db.scalar(select(AccessRole).where(AccessRole.name=='Governance Manager'))
        manager=create_user(db,'manager','Governance Manager','manager@example.test',
             'this-is-a-manager-password',[manager_role.id])
    login=client.post('/login',data={'username':'manager','password':'this-is-a-manager-password'},follow_redirects=False)
    assert login.status_code==303
    html=client.get('/integrations').text
    assert 'Save Tenable connection' in html
    csrf=html.split('name="csrf_token" value="')[1].split('"')[0]
    result=client.post('/account/connectors/tenable',data={'csrf_token':csrf,
         'access_key':'manager_key_1234','secret_key':'manager_secret_5678'},follow_redirects=False)
    assert result.status_code==303
    login_as(client,'admin')
    assert 'manager_key_1234' in client.get('/integrations').text
