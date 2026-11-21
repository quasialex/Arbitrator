"""v0.15.1: targeted routing UX, consistent panels, and matching role editors."""
from sqlalchemy import select

from test_v06_auth import web, login_as
from app.models import AccessRole, Finding
from app.services import create_assessment, import_findings
from app.workflows import create_team
from app.routing import create_routing_rule


def test_edit_role_uses_same_capability_grid_as_create(web):
    client, factory = web
    login_as(client, 'admin')
    create = client.get('/admin/roles').text
    with factory() as db:
        role = db.scalar(select(AccessRole).where(AccessRole.name == 'Governance Approver'))
        role_id = role.id
    edit = client.get(f'/admin/roles/{role_id}/edit')
    assert edit.status_code == 200
    assert 'admin-form-grid' in create and 'admin-form-grid' in edit.text
    assert 'stakeholder-options permission-choices' in create
    assert 'stakeholder-options permission-choices' in edit.text
    assert 'grid-template-columns:repeat(auto-fit' not in edit.text
    assert 'max-width:900px' not in edit.text
    assert 'governance.tasks.approve' in edit.text
    assert 'Save role permissions' in edit.text


def test_paired_panels_stretch_on_every_requested_page(web):
    client, _ = web
    login_as(client, 'admin')
    for url, first, second in (
        ('/assessments', 'Create an assessment', 'How these records relate'),
        ('/ownership/teams', 'Add team', 'Ownership model'),
        ('/ownership/routing', 'Add global responsibility rule', 'Re-evaluate findings'),
    ):
        page = client.get(url)
        assert page.status_code == 200
        assert 'two-col balanced-grid below-register' in page.text, url
        assert first in page.text and second in page.text
        assert 'two-col align-start below-register' not in page.text


def test_scoped_routing_has_suggestions_and_separate_all_action(web):
    client, factory = web
    with factory() as db:
        assessment = create_assessment(db, 'Example', 'Web check')
        import_findings(db, b'asset,title,severity\napi.corp.test,Old TLS,High\n',
                        'check.csv', 'generic_csv', assessment.id)
        team = create_team(db, 'Platform Ops', 'platform@example.test')
        asset = db.get(Finding, 1).asset
        asset.service_code = 'WEB001'
        db.commit()
    login_as(client, 'admin')
    page = client.get('/ownership/routing').text
    assert '<option value="all">' not in page
    assert '<option value="finding">Single finding ID</option>' in page
    assert 'route-finding-options' in page and 'route-hostname-options' in page
    assert 'route-service-options' in page and 'route-cidr-options' in page
    assert 'value="api.corp.test"' in page
    assert 'value="WEB001"' in page
    assert f'<option value="{team.id}">Platform Ops</option>' in page
    assert 'action="/ownership/routing/apply-scoped"' in page
    assert 'action="/ownership/routing/apply"' in page
    assert 'Re-evaluate all findings' in page
    assert 'Re-evaluate selected findings' in page


def test_scoped_route_rejects_all_instead_of_accidentally_routing_everything(web):
    client, factory = web
    with factory() as db:
        assessment = create_assessment(db, 'Example', 'Check')
        import_findings(db, b'asset,title,severity\nweb.corp.test,Weak TLS,High\n',
                        'check.csv', 'generic_csv', assessment.id)
        team = create_team(db, 'Platform Ops', 'platform@example.test')
        create_routing_rule(db, team.id, 'hostname_suffix', 'corp.test', 'none', '')
        finding_id = db.scalar(select(Finding.id))
    csrf = login_as(client, 'admin')
    rejected = client.post('/ownership/routing/apply-scoped', data={
        'csrf_token': csrf, 'scope': 'all', 'pattern': ''}, follow_redirects=False)
    assert rejected.status_code == 303
    assert 'error=' in rejected.headers['location']
    with factory() as db:
        assert db.get(Finding, finding_id).assigned_owner_id is None
    full = client.post('/ownership/routing/apply', data={'csrf_token': csrf}, follow_redirects=False)
    assert full.status_code == 303
    with factory() as db:
        assert db.get(Finding, finding_id).assigned_owner_id == team.id


def test_scoped_route_validates_finding_id_before_routing(web):
    client, factory = web
    with factory() as db:
        assessment = create_assessment(db, 'Example', 'Check')
        import_findings(db, b'asset,title,severity\nweb.corp.test,Weak TLS,High\n',
                        'check.csv', 'generic_csv', assessment.id)
    csrf = login_as(client, 'admin')
    for invalid in ('abc', '9999999', ''):
        result = client.post('/ownership/routing/apply-scoped', data={
            'csrf_token': csrf, 'scope': 'finding', 'pattern': invalid}, follow_redirects=False)
        assert result.status_code == 303
        assert 'error=' in result.headers['location']
