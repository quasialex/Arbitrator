"""New v0.13 page behavior and access control; requests are local TestClient only."""
import pytest
from cryptography.fernet import Fernet
from app.models import Owner
from test_v06_auth import web, login_as


def test_navigation_separates_profile_and_integrations(web):
    client,factory = web
    from app.services import create_assessment
    with factory() as db: create_assessment(db,'Demo','API check')
    token=login_as(client,'admin')
    profile=client.get('/account/profile').text
    integrations=client.get('/integrations')
    assert integrations.status_code==200
    assert 'ServiceNow' in integrations.text
    assert 'name="access_key"' in integrations.text
    assert 'name="access_key"' not in profile
    assert 'name="theme"' in profile
    assert '<a href="/integrations">Integrations</a>' in integrations.text
    page=client.get('/imports').text
    for source in ('generic_csv','nessus_csv','nuclei_jsonl','plextrac_json'):
        assert 'value="'+source+'"' in page
    for unsupported in ('old_sec1_csv','nessus_html','tenable_json','sec1_csv'):
        assert 'value="'+unsupported+'"' not in page


def test_integrations_service_now_csrf_and_admin_group_mapping(web,monkeypatch):
    client,factory=web
    token=login_as(client,'admin')
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    assert client.post('/integrations/servicenow', data={
        'instance_url':'https://example.service-now.com',
        'username':'robot','password':'good_password'},follow_redirects=False).status_code==422
    response=client.post('/integrations/servicenow', data={
        'csrf_token':token, 'instance_url':'https://example.service-now.com',
        'username':'robot','password':'good_password'},follow_redirects=False)
    assert response.status_code==303
    assert 'Credentials saved' in client.get('/integrations').text
    with factory() as db:
        owner=Owner(name='API Team',email='api@example.test')
        db.add(owner);db.commit()
        team_id=owner.id
    from app import main
    def fake_verified_selection(session,user_id,team_id,sys_id):
        from app.servicenow import configure_group
        return configure_group(session,team_id,sys_id,'API Operations','api-ops@example.test')
    monkeypatch.setattr(main,'select_group',fake_verified_selection)
    response=client.post('/integrations/servicenow/groups',data={
        'csrf_token':token,'team_id':team_id,'group_sys_id':'a'*32}, follow_redirects=False)
    assert response.status_code==303
    assert 'a'*32 in client.get('/integrations').text
    login_as(client,'viewer')
    response=client.post('/integrations/servicenow/groups', data={
        'csrf_token':'invalid','team_id':team_id,'group_sys_id':'a'*32},follow_redirects=False)
    assert response.status_code==403
