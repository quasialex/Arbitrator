"""v0.16.2: self-contained demo loading, no destructive migration, and account editor UX."""
from sqlalchemy import func, select
from test_v06_auth import web, login_as
from app.models import Assessment, Asset, Finding, Observation, GovernanceWorkItem, UserAccount
from app.services import create_assessment


def test_sample_campaign_can_be_loaded_from_browser_once(web):
    client, factory = web
    csrf = login_as(client, 'admin')
    initial = client.get('/admin/sample-data')
    assert initial.status_code == 200
    assert 'Load sample campaign' in initial.text
    assert 'Load sample campaign' in client.get('/').text
    r = client.post('/admin/sample-data', data={'csrf_token': csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert '/admin/sample-data?notice=' in r.headers['location']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Assessment)) == 6
        assert db.scalar(select(func.count()).select_from(Asset)) == 14
        assert db.scalar(select(func.count()).select_from(Finding)) == 27
        assert db.scalar(select(func.count()).select_from(Observation)) == 39
        assert db.scalar(select(func.count()).select_from(GovernanceWorkItem)) == 3
        # Existing user accounts remain intact.
        assert db.scalar(select(func.count()).select_from(UserAccount)) == 4
    assert 'Atlas Labs' in client.get('/assessments').text
    assert 'Weak security headers' in client.get('/findings').text
    assert 'Load sample campaign' not in client.get('/admin/sample-data').text
    r2 = client.post('/admin/sample-data', data={'csrf_token': csrf}, follow_redirects=False)
    assert r2.status_code == 303
    assert 'error=' in r2.headers['location']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 27


def test_sample_loader_rejects_existing_data_without_modifying_it(web):
    client, factory = web
    with factory() as db:
        create_assessment(db, 'Existing', 'Critical client assessment')
    csrf = login_as(client, 'admin')
    view = client.get('/admin/sample-data')
    assert 'Load sample campaign' not in view.text
    assert 'existing data' in view.text
    r = client.post('/admin/sample-data', data={'csrf_token': csrf}, follow_redirects=False)
    assert 'error=' in r.headers['location']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Assessment)) == 1
        assert db.scalar(select(func.count()).select_from(Finding)) == 0


def test_sample_loader_needs_admin_and_csrf(web):
    client, factory = web
    login_as(client, 'viewer')
    assert client.get('/admin/sample-data').status_code == 403
    assert client.post('/admin/sample-data', data={}).status_code == 403
    csrf = login_as(client, 'admin')
    assert client.post('/admin/sample-data', data={'csrf_token': 'invalid'}).status_code == 403
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Assessment)) == 0
    assert 'Manage sample data' in client.get('/imports').text


def test_user_editor_has_compact_password_input_and_balanced_panels(web):
    client, factory = web
    login_as(client, 'admin')
    with factory() as db:
        uid = db.scalar(select(UserAccount.id).where(UserAccount.username == 'admin'))
    html = client.get(f'/admin/users/{uid}/edit').text
    assert 'admin-user-editor' in html
    assert 'admin-password-form' in html
    assert 'admin-password-field' in html
    assert 'admin-reset-password' in html
    assert 'Reset password and revoke sessions' in html
    assert 'type="password"' in html
    assert 'admin-password-form' in ( __import__('pathlib').Path(__file__).resolve().parents[1]/'app/static/site.css').read_text()
