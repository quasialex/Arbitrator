"""v0.9 regression checks for UI semantics and role-scoped dashboard preview."""
from datetime import date, timedelta
from pathlib import Path
from sqlalchemy import select
from test_v06_auth import web, login_as
from test_v08_features import load_finding
from app.models import AccessRole, GovernanceWorkItem
from app.governance_tasks import create_work_item

ROOT = Path(__file__).resolve().parents[1]


def test_sidebar_order_and_provisional_brand(web):
    client, _ = web
    login_as(client, 'admin')
    response = client.get('/')
    assert response.status_code == 200
    html = response.text
    assert 'Arbitrator' in html
    assert 'FindingHarbor' not in html
    assert html.index('href="/work-items" class="nav-link') < html.index('href="/assessments" class="nav-link')
    assert 'My work' in html
    assert 'class="focus-bar"' not in html
    assert '<a href="/findings?severity=Critical"' in html


def test_table_unsorted_has_clean_double_caret_and_preserves_filter(web):
    client, _ = web
    login_as(client, 'admin')
    response = client.get('/findings?severity=High&page_size=10')
    assert response.status_code == 200
    assert 'sort-unsorted' in response.text
    assert 'sort-caret' in response.text
    assert '↕' not in response.text
    response = client.get('/findings?severity=High&sort=name&direction=asc&page_size=10')
    assert response.status_code == 200
    assert 'Sort by FINDING, currently ascending' in response.text or 'currently ascending' in response.text
    assert 'severity=High' in response.text
    assert 'page_size=10' in response.text


def test_own_work_preview_only_shows_assigned_work(web):
    client, factory = web
    fid = load_finding(factory)
    with factory() as db:
        role = db.scalar(select(AccessRole).where(AccessRole.name == 'Governance Approver'))
        due = (date.today() + timedelta(days=3)).isoformat()
        item = create_work_item(db, finding_id=fid, kind='risk_approval',
            title='Review governance exception before deadline', description='Review synthetic request',
            assignee_role_id=role.id, assignee_user_id=None,
            created_by_id=1, due_date=due)
        item_id = item.id
    login_as(client, 'admin')
    admin_html = client.get('/').text
    assert 'Review governance exception before deadline' not in admin_html
    login_as(client, 'viewer')
    # Read-only viewers see the work section but not an approver's private queue.
    viewer_html = client.get('/').text
    assert 'Review governance exception before deadline' not in viewer_html
    login_as(client, 'approver')
    approver_html = client.get('/').text
    assert 'Review governance exception before deadline' not in approver_html
    assert 'href="/work-items?bucket=mine" class="dashboard-queue-metric"><strong>1</strong>' in approver_html
    assert client.get(f'/work-items/{item_id}').status_code == 200


def test_superuser_role_display_and_dark_alert_contrast(web):
    client, _ = web
    token = login_as(client, 'admin')
    profile = client.get('/account/profile')
    assert profile.status_code == 200
    assert 'Administrator · Full access' in profile.text
    assert 'No access roles assigned' not in profile.text
    client.post('/account/settings', data={'csrf_token': token, 'theme': 'dark'}, follow_redirects=False)
    appearance = client.get('/account/settings?notice=Updated')
    assert 'data-theme="dark"' in appearance.text
    assert 'class="alert success"' in appearance.text
    css = (ROOT / 'app/static/site.css').read_text()
    assert '[data-theme="dark"] .alert.success' in css
    assert 'font-family:inherit' in css
    assert '.account-layout' in css


def test_cog_settings_icon_is_present_and_link_is_authorized(web):
    client, _ = web
    login_as(client, 'admin')
    html = client.get('/').text
    assert '/static/icons.svg#settings' in html
    assert client.get('/admin/users').status_code == 200
    sprite = (ROOT / 'app/static/icons.svg').read_text()
    assert 'id="settings"' in sprite
    assert '<circle cx="12" cy="12" r="3"/>' in sprite
