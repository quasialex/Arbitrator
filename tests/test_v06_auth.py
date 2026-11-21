"""Integration checks for local authentication, authorization, and CSRF enforcement."""
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app import main
from app.database import get_session
from app.models import Base, AccessRole, UserAccount, LoginSession, GovernanceDecision, Finding
from app.auth import (seed_roles, create_user, hash_password, verify_password,
                      update_role, assign_roles, resolve_session)
from app.services import create_assessment, import_findings
from app.workflows import create_team, assign_finding
from pathlib import Path

SAMPLE=Path(__file__).resolve().parents[1]/'sample_data'/'synthetic_campaign'/'manual_baseline.csv'

@pytest.fixture
def web(monkeypatch):
    engine=create_engine('sqlite://',poolclass=StaticPool,connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine)
    factory=sessionmaker(bind=engine,expire_on_commit=False)
    monkeypatch.setattr(main,'SessionLocal',factory)
    def sessions():
        with factory() as session: yield session
    main.app.dependency_overrides[get_session]=sessions
    with factory() as s:
        seed_roles(s)
        viewer=s.scalar(select(AccessRole).where(AccessRole.name=='Read-only Viewer'))
        analyst=s.scalar(select(AccessRole).where(AccessRole.name=='Offensive Security Analyst'))
        approver=s.scalar(select(AccessRole).where(AccessRole.name=='Governance Approver'))
        create_user(s,'admin','Admin User','admin@example.test','this-is-only-a-test-admin-password',[],superuser=True)
        create_user(s,'viewer','Viewer User','viewer@example.test','this-is-only-a-test-viewer-password',[viewer.id])
        create_user(s,'analyst','Analyst User','analyst@example.test','this-is-only-a-test-analyst-pass',[analyst.id])
        create_user(s,'approver','Approver User','approver@example.test','this-is-only-a-test-approver-pass',[approver.id])
    with TestClient(main.app) as client:
        yield client,factory
    main.app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def login_as(client,username):
    passwords={'admin':'this-is-only-a-test-admin-password','viewer':'this-is-only-a-test-viewer-password',
               'analyst':'this-is-only-a-test-analyst-pass','approver':'this-is-only-a-test-approver-pass'}
    result=client.post('/login',data={'username':username,'password':passwords[username]},follow_redirects=False)
    assert result.status_code==303
    token=client.get('/account/password').text.split('name="csrf_token" value="')[1].split('"')[0]
    return token


def test_scrypt_hashing():
    coded=hash_password('a-long-test-password')
    assert coded.startswith('scrypt$')
    assert verify_password('a-long-test-password',coded)
    assert not verify_password('wrong-pass',coded)


def test_authentication_required_and_no_default_credentials(web):
    client,_=web
    assert client.get('/assessments',follow_redirects=False).status_code==303
    assert client.post('/assessments',data={}).status_code==401
    assert 'Sign in' in client.get('/login').text
    assert 'Invalid credentials' in client.post('/login',data={'username':'admin','password':'bad'}).text


def test_login_and_read_only_denies_import_and_approval(web):
    client,_=web
    token=login_as(client,'viewer')
    assert client.get('/findings').status_code==200
    assert client.get('/admin/users').status_code==403
    response=client.post('/assessments',data={'csrf_token':token,'engagement_name':'D','assessment_name':'A'})
    assert response.status_code==403
    response=client.post('/findings/1/decisions',data={'csrf_token':token,'action':'request_remediation','rationale':'Ten chars minimum'})
    assert response.status_code==403


def test_missing_csrf_blocks_mutation(web):
    client,_=web
    login_as(client,'admin')
    response=client.post('/assessments',data={'engagement_name':'Corp','assessment_name':'Assessment'},follow_redirects=False)
    assert response.status_code==422
    response=client.post('/logout',data={},follow_redirects=False)
    assert response.status_code==422


def test_admin_create_assessment_and_roles_ui(web):
    client,_=web
    token=login_as(client,'admin')
    response=client.post('/assessments',data={'engagement_name':'Corp','assessment_name':'Test 1','csrf_token':token},follow_redirects=False)
    assert response.status_code==303
    assert client.get('/admin/roles').status_code==200
    assert 'Read-only Viewer' in client.get('/admin/users/new').text
    assert 'Create custom role' in client.get('/admin/roles').text


def test_role_permissions_are_live(web):
    client,factory=web
    login_as(client,'viewer')
    assert client.get('/findings').status_code==200
    with factory() as s:
        role=s.scalar(select(AccessRole).where(AccessRole.name=='Read-only Viewer'))
        perms=[p.permission for p in role.permissions if p.permission!='findings.read']
        update_role(s,role,role.name,role.description,perms)
    assert client.get('/findings').status_code==403


def test_assigning_user_roles_revokes_sessions(web):
    client,factory=web
    login_as(client,'viewer')
    with factory() as s:
        user=s.scalar(select(UserAccount).where(UserAccount.username=='viewer'))
        assert s.scalar(select(LoginSession).where(LoginSession.user_id==user.id))
        analyst=s.scalar(select(AccessRole).where(AccessRole.name=='Offensive Security Analyst'))
        assign_roles(s,user,[analyst.id],True)
        assert s.scalar(select(LoginSession).where(LoginSession.user_id==user.id)) is None
    assert client.get('/').url.path=='/login'


def test_custom_role_create_and_reassign_user(web):
    client,factory=web
    token=login_as(client,'admin')
    response=client.post('/admin/roles',data={'csrf_token':token,'name':'Specialist Custom',
          'description':'Can view findings and assign teams','permissions':['findings.read','findings.assign']},follow_redirects=False)
    assert response.status_code==303
    with factory() as s:
        role=s.scalar(select(AccessRole).where(AccessRole.name=='Specialist Custom'))
        assert {p.permission for p in role.permissions}=={'findings.read','findings.assign'}
        viewer=s.scalar(select(UserAccount).where(UserAccount.username=='viewer'))
        assign_roles(s,viewer,[role.id],True)
    viewer=TestClient(main.app)
    with viewer:
        viewer.post('/login',data={'username':'viewer','password':'this-is-only-a-test-viewer-password'},follow_redirects=False)
        assert viewer.get('/findings').status_code==200
        assert viewer.get('/assessments').status_code==403


def test_governance_decision_records_authenticated_actor(web):
    client,factory=web
    with factory() as s:
        a=create_assessment(s,'Atlas','Internal review')
        import_findings(s,SAMPLE.read_bytes(),'manual_baseline.csv','generic_csv',a.id)
        f=s.scalar(select(Finding))
        team=create_team(s,'Platform','platform@example.test')
        assign_finding(s,f.id,str(team.id))
        finding_id=f.id
    token=login_as(client,'approver')
    action=client.post(f'/findings/{finding_id}/decisions',data={'csrf_token':token,
       'action':'request_remediation','rationale':'Test-approved remediation request'},follow_redirects=False)
    assert action.status_code==303
    with factory() as s:
        record=s.scalar(select(GovernanceDecision).where(GovernanceDecision.finding_id==finding_id))
        user=s.scalar(select(UserAccount).where(UserAccount.username=='approver'))
        assert record.actor_user_id==user.id
        assert record.decided_by=='Approver User'


def test_invalid_csrf_rejected(web):
    client,_=web
    login_as(client,'admin')
    r=client.post('/assessments',data={'csrf_token':'wrong','engagement_name':'Corp','assessment_name':'T'},follow_redirects=False)
    assert r.status_code==403


def test_user_can_change_password_and_sessions_revoked(web):
    client,_=web
    token=login_as(client,'viewer')
    r=client.post('/account/password',data={'csrf_token':token,'previous':'this-is-only-a-test-viewer-password',
                 'password':'a-new-long-test-password','confirm':'a-new-long-test-password'},follow_redirects=False)
    assert r.status_code==303
    assert r.headers.get('location')=='/login'
    assert client.get('/').url.path=='/login'


def test_disabled_account_denied(web):
    client,factory=web
    login_as(client,'viewer')
    with factory() as s:
        user=s.scalar(select(UserAccount).where(UserAccount.username=='viewer'))
        user.is_active=False;s.commit()
    assert client.get('/').url.path=='/login'


def test_import_requires_csrf_and_uses_existing_assessment(web):
    client,factory=web
    token=login_as(client,'admin')
    with factory() as session:
        assessment=create_assessment(session,'Atlas Operations','Web API test')
        aid=assessment.id
    data={'source':'generic_csv','assessment_id':str(aid),'csrf_token':token}
    files={'uploaded':('baseline.csv',SAMPLE.read_bytes(),'text/csv')}
    bad=client.post('/imports',data={k:v for k,v in data.items() if k!='csrf_token'},files=files,follow_redirects=False)
    assert bad.status_code==422
    good=client.post('/imports',data=data,files=files,follow_redirects=False)
    assert good.status_code in {200,303}
    with factory() as session:
        assert session.scalar(select(Finding)) is not None


def test_global_assets_and_rules_web_forms(web):
    client,factory=web
    with factory() as s:
        a=create_assessment(s,'Atlas','Assessment A')
        import_findings(s,SAMPLE.read_bytes(),'baseline.csv','generic_csv',a.id)
        team=create_team(s,'Web Platform','platform@example.test')
        fid=s.scalar(select(Finding)).id
        aid=s.scalar(select(Finding)).asset_id
        team_id=team.id
    token=login_as(client,'admin')
    assert 'Engagement' not in client.get('/ownership/routing').text.split('New routing rule')[0]
    r=client.post('/ownership/routing',data={'csrf_token':token,'team_id':str(team_id),
       'asset_kind':'hostname_suffix','asset_pattern':'atlas.example.test','finding_kind':'none',
       'finding_pattern':''},follow_redirects=False)
    assert r.status_code==303
    with factory() as s:
        rule=s.scalar(select(__import__('app.models',fromlist=['RoutingRule']).RoutingRule))
        rid=rule.id
    detail=client.get(f'/ownership/routing/{rid}/edit')
    assert detail.status_code==200 and 'Save changes' in detail.text
    assert 'ENGAGEMENT' not in detail.text.split('<main class="content">')[1].split('Asset condition')[0]
    resp=client.post(f'/ownership/routing/{rid}/edit',data={'csrf_token':token,'team_id':str(team_id),
      'asset_kind':'hostname_regex','asset_pattern':r'^web\d+\.atlas\.example\.test$',
      'finding_kind':'none'},follow_redirects=False)
    assert resp.status_code==303
    applied=client.post('/ownership/routing/apply',data={'csrf_token':token},follow_redirects=False)
    assert applied.status_code==303
    with factory() as s:
        f=s.get(Finding,fid)
        assert f.asset_id==aid


def test_asset_multiple_stakeholder_form_does_not_set_finding_owner(web):
    client,factory=web
    with factory() as s:
        a=create_assessment(s,'Atlas','Assessment A')
        import_findings(s,SAMPLE.read_bytes(),'baseline.csv','generic_csv',a.id)
        team1=create_team(s,'Web','web@example.test')
        team2=create_team(s,'Linux','linux@example.test')
        f=s.scalar(select(Finding));asset_id=f.asset_id;finding_id=f.id
        id1,id2=team1.id,team2.id
    token=login_as(client,'admin')
    view=client.get(f'/assets/{asset_id}')
    assert view.status_code==200
    assert 'Global asset' in view.text or 'GLOBAL ASSET' in view.text
    response=client.post(f'/assets/{asset_id}',data={
      'csrf_token':token,'display_name':'Renamed asset','exposure':'Internal',
      'team_ids':[str(id1),str(id2)],'service_code':'WEB01','external_ref':'CMDB-001'},follow_redirects=False)
    assert response.status_code==303
    from app.models import Asset
    with factory() as s:
        asset=s.get(Asset,asset_id)
        assert {x.team_id for x in asset.memberships}=={id1,id2}
        assert s.get(Finding,finding_id).assigned_owner_id is None


def test_permission_managed_user_creation_via_ui(web):
    client,factory=web
    token=login_as(client,'admin')
    with factory() as s:
        role=s.scalar(select(AccessRole).where(AccessRole.name=='Security Specialist'))
        rid=role.id
    created=client.post('/admin/users',data={'csrf_token':token,'username':'specialist',
     'name':'Security Specialist','email':'specialist@example.test','password':'really-long-synthetic-password',
     'role_ids':[str(rid)]},follow_redirects=False)
    assert created.status_code==303
    with factory() as s:
        user=s.scalar(select(UserAccount).where(UserAccount.username=='specialist'))
        assert user and {r.role_id for r in user.roles}=={rid}
        uid=user.id
    assert client.get(f'/admin/users/{uid}/edit').status_code==200
    changed=client.post(f'/admin/users/{uid}/edit',data={'csrf_token':token,'active':'on'},follow_redirects=False)
    assert changed.status_code==303
    with factory() as s:
        user=s.get(UserAccount,uid)
        assert user.roles==[] and user.is_active


def test_team_edit_dedicated_page_and_navigation(web):
    client,factory=web
    with factory() as s:
        team=create_team(s,'Original','original@example.test')
        tid=team.id
    token=login_as(client,'admin')
    response=client.get('/ownership/teams')
    assert 'Edit' in response.text and 'Original' in response.text
    edit=client.get(f'/ownership/teams/{tid}/edit')
    assert edit.status_code==200 and 'REMEDIATION TEAMS' in edit.text
    done=client.post(f'/ownership/teams/{tid}',data={'csrf_token':token,'name':'Renamed',
      'email':'renamed@example.test'},follow_redirects=False)
    assert done.status_code==303
    with factory() as s: assert s.get(__import__('app.models',fromlist=['Owner']).Owner,tid).name=='Renamed'


def test_pagination_default_ten_and_query_parameter(web):
    client,factory=web
    token=login_as(client,'admin')
    with factory() as s:
        a=create_assessment(s,'Atlas','Test 1')
        import_findings(s,SAMPLE.read_bytes(),'baseline.csv','generic_csv',a.id)
    h=client.get('/findings').text
    assert 'value="10" selected' in h
    h=client.get('/findings?page_size=20').text
    assert 'value="20" selected' in h


def test_bad_login_lockout(web):
    client,factory=web
    for _ in range(5):
        client.post('/login',data={'username':'viewer','password':'incorrect'},follow_redirects=False)
    resp=client.post('/login',data={'username':'viewer',
          'password':'this-is-only-a-test-viewer-password'},follow_redirects=False)
    assert resp.status_code==200 and 'temporarily locked' in resp.text
    with factory() as s:
        user=s.scalar(select(UserAccount).where(UserAccount.username=='viewer'))
        assert user.locked_until is not None


def test_owner_directory_is_read_only_for_viewer(web):
    client,_=web
    token=login_as(client,'viewer')
    assert client.get('/ownership/teams').status_code==200
    bad=client.post('/ownership/teams',data={'csrf_token':token,'name':'Nope','email':'nope@example.test'},
                    follow_redirects=False)
    assert bad.status_code==403


def test_approval_not_allowed_to_analyst(web):
    client,_=web
    token=login_as(client,'analyst')
    assert client.get('/findings').status_code==200
    bad=client.post('/findings/123/decisions',data={'csrf_token':token,'action':'accept_risk',
                    'rationale':'An unauthorized decision','review_date':'2027-01-01'},follow_redirects=False)
    assert bad.status_code==403


def test_administrator_and_new_specialist_visible_and_can_login(web):
    """Account listing, persistence and login, exercising the same browser workflow as a user."""
    client, factory = web
    token = login_as(client, 'admin')
    listing = client.get('/admin/users')
    assert listing.status_code == 200
    assert '<td>admin</td>' in listing.text
    assert '<td>Admin User</td>' in listing.text
    assert 'No accounts yet.' not in listing.text
    new_page = client.get('/admin/users/new')
    assert new_page.status_code == 200
    assert 'Create account' in new_page.text
    with factory() as session:
        specialist_role = session.scalar(select(AccessRole).where(AccessRole.name == 'Security Specialist'))
        role_id = specialist_role.id
    create = client.post('/admin/users', data={
        'csrf_token': token, 'username': 'specialist02',
        'name': 'Security Specialist Two', 'email': 'specialist02@example.test',
        'password': 'correct-horse-battery-test-only',
        'role_ids': [str(role_id)],
    }, follow_redirects=False)
    assert create.status_code == 303
    assert create.headers['location'].startswith('/admin/users')
    listing = client.get('/admin/users')
    assert '<td>specialist02</td>' in listing.text
    assert '<td>Security Specialist Two</td>' in listing.text
    with factory() as session:
        new_user = session.scalar(select(UserAccount).where(UserAccount.username == 'specialist02'))
        assert new_user is not None and new_user.is_active
        assert {link.role_id for link in new_user.roles} == {role_id}
    signed_out = client.post('/logout', data={'csrf_token': token}, follow_redirects=False)
    assert signed_out.status_code == 303
    new_login = client.post('/login', data={
        'username': 'specialist02', 'password': 'correct-horse-battery-test-only',
    }, follow_redirects=False)
    assert new_login.status_code == 303
    assert client.get('/findings').status_code == 200
    assert client.get('/admin/users').status_code == 403
