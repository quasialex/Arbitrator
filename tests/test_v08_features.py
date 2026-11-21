"""v0.8 acceptance tests: sorting, work item permissions, role queues, audit, settings."""
from datetime import date, timedelta
from sqlalchemy import select
from test_v06_auth import web, login_as, SAMPLE
from app.models import (AccessRole, Finding, GovernanceWorkItem, GovernanceWorkEvent,
                        GovernanceDecision, Observation, UserAccount)
from app.services import create_assessment, import_findings
from app.workflows import create_team, assign_finding


def load_finding(factory):
    with factory() as db:
        a=create_assessment(db,'Example Client','API assessment')
        import_findings(db,SAMPLE.read_bytes(),'baseline.csv','generic_csv',assessment_id=a.id)
        f=db.scalars(select(Finding).order_by(Finding.id)).first()
        create_team(db,'Security Engineering','security@example.test')
        team=db.scalar(select(Finding).where(Finding.id==f.id)).id
        assign_finding(db, f.id, '1')
        return f.id


def test_work_item_role_inbox_and_approval_audit(web):
    client,factory=web
    fid=load_finding(factory)
    with factory() as db:
        role=db.scalar(select(AccessRole).where(AccessRole.name=='Governance Approver'))
        rid=role.id
    admin_token=login_as(client,'admin')
    due=(date.today()+timedelta(days=5)).isoformat()
    response=client.post('/work-items/create',data={'csrf_token':admin_token,'finding_id':fid,
        'kind':'risk_approval','title':'Approve temporary risk acceptance',
        'description':'Business owner requests an exception','assignee':f'role:{rid}','due_date':due},follow_redirects=False)
    assert response.status_code==303
    url=response.headers['location']
    assert '/work-items/' in url
    # Viewer sees no assigned work item; approver sees the role-targeted item.
    login_as(client,'viewer')
    assert 'Approve temporary risk acceptance' not in client.get('/work-items').text
    assert client.get(url).status_code==403
    client.post('/logout',data={'csrf_token':client.get('/account/password').text.split('name="csrf_token" value="')[1].split('"')[0]},follow_redirects=False)
    token=login_as(client,'approver')
    assert 'Approve temporary risk acceptance' in client.get('/work-items').text
    assert client.get(url).status_code==200
    without_csrf=client.post(url+'/action',data={'status':'approved','rationale':'approved with future review'},follow_redirects=False)
    assert without_csrf.status_code==422
    result=client.post(url+'/action',data={'csrf_token':token,'status':'approved',
        'rationale':'Evidence supports this limited temporary acceptance',
        'review_date':(date.today()+timedelta(days=25)).isoformat()},follow_redirects=False)
    assert result.status_code==303
    with factory() as db:
        task=db.scalars(select(GovernanceWorkItem)).first()
        events=db.scalars(select(GovernanceWorkEvent).order_by(GovernanceWorkEvent.id)).all()
        decisions=db.scalars(select(GovernanceDecision)).all()
        assert task.status=='approved'
        assert [e.event for e in events]==['created','status_changed']
        assert decisions[-1].actor_user_id==db.scalar(select(UserAccount.id).where(UserAccount.username=='approver'))


def test_work_item_role_has_to_support_kind_and_valid_transitions(web):
    client,factory=web;fid=load_finding(factory)
    token=login_as(client,'admin')
    with factory() as db:
        viewer=db.scalar(select(AccessRole).where(AccessRole.name=='Read-only Viewer'))
        viewer_id=viewer.id
    response=client.post('/work-items/create',data={'csrf_token':token,'finding_id':fid,
        'kind':'risk_approval','title':'Must not route to viewer','description':'not eligible',
        'assignee':f'role:{viewer_id}','due_date':date.today().isoformat()},follow_redirects=True)
    assert 'lacks the permission' in response.text
    with factory() as db:
        assert db.scalar(select(GovernanceWorkItem.id)) is None


def test_profile_settings_and_sorting_filters(web):
    client,factory=web;load_finding(factory)
    token=login_as(client,'admin')
    assert 'Arbitrator' in client.get('/').text
    assert client.get('/account/profile').status_code==200
    assert client.post('/account/settings',data={'csrf_token':token,'theme':'dark'},follow_redirects=False).status_code==303
    assert 'data-theme="dark"' in client.get('/account/settings').text
    assert client.post('/account/settings',data={'csrf_token':token,'theme':'invalid'},follow_redirects=False).status_code==400
    for url in ['/findings?sort=name&direction=asc&page_size=2','/assets?sort=identifier&direction=desc&page_size=2',
                '/observations?sort=assessment&direction=asc&page_size=2',
                '/assessments?sort=start&direction=asc', '/governance?sort=severity&direction=desc',
                '/ownership/teams?sort=contact&direction=asc', '/imports?sort=rows&direction=desc']:
        resp=client.get(url)
        assert resp.status_code==200,url
        assert 'sort-link' in resp.text,url
    resp=client.get('/findings?severity=High&sort=name&direction=asc&page_size=2')
    assert resp.status_code==200
    assert 'name="severity" value="High"' in resp.text or 'value="High" selected' in resp.text
    assert 'sort=name' in resp.text and 'page_size=2' in resp.text


def test_manager_reassignment_and_approval_blocked_for_viewer(web):
    client,factory=web;fid=load_finding(factory)
    with factory() as db:
        manager=db.scalar(select(AccessRole).where(AccessRole.name=='Governance Manager'))
        mid=manager.id
        approver=db.scalar(select(AccessRole).where(AccessRole.name=='Governance Approver'))
        aid=approver.id
    token=login_as(client,'admin')
    response=client.post('/work-items/create',data={'csrf_token':token,'finding_id':fid,
        'kind':'escalation','title':'Investigate security escalation', 'description':'Follow up',
        'assignee':f'role:{mid}','due_date':date.today().isoformat()},follow_redirects=False)
    assert response.status_code==303
    path=response.headers['location']
    assert client.post(path+'/reassign',data={'csrf_token':token,'assignee':'user:3',
            'due_date':date.today().isoformat(),'note':'Delegated to technical analyst'},follow_redirects=False).status_code==303
    with factory() as db:
        item=db.scalar(select(GovernanceWorkItem))
        assert item.assignee_user_id==3
        assert [e.event for e in db.scalars(select(GovernanceWorkEvent).order_by(GovernanceWorkEvent.id)).all()]==['created','reassigned']
    login_as(client,'viewer')
    assert client.post(path+'/reassign',data={'csrf_token':token,'assignee':f'role:{aid}',
      'due_date':date.today().isoformat(),'note':'Viewer should be blocked'},follow_redirects=False).status_code==403
