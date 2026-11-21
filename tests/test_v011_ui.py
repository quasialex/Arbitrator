"""Focused v0.11 regressions for the counter-only overview and readable work details."""
from datetime import date, timedelta
from pathlib import Path
from sqlalchemy import select
from test_v06_auth import web, login_as
from test_v08_features import load_finding
from app.models import AccessRole
from app.governance_tasks import create_work_item

ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_three_clickable_work_counters_without_preview(web):
    client, factory = web
    fid = load_finding(factory)
    with factory() as db:
        role = db.scalar(select(AccessRole).where(AccessRole.name == 'Governance Approver'))
        create_work_item(db, finding_id=fid, kind='risk_approval',
                         title='Private risk review title', description='Sensitive synthetic note',
                         assignee_role_id=role.id, assignee_user_id=None, created_by_id=1,
                         due_date=(date.today() + timedelta(days=3)).isoformat())
    login_as(client, 'approver')
    html = client.get('/').text
    assert html.count('class="dashboard-queue-metric"') == 3
    assert 'href="/work-items?bucket=mine" class="dashboard-queue-metric"><strong>1</strong>' in html
    assert 'href="/work-items?bucket=approvals" class="dashboard-queue-metric"><strong>1</strong>' in html
    assert 'href="/work-items?bucket=overdue" class="dashboard-queue-metric"><strong>0</strong>' in html
    assert 'dashboard-queue-items' not in html
    assert 'Private risk review title' not in html
    assert html.index('dashboard-queue') < html.index('Findings by severity')


def test_work_item_detail_layout_and_audit_continuity(web):
    client, factory = web
    fid = load_finding(factory)
    with factory() as db:
        item = create_work_item(db, finding_id=fid, kind='remediation_review',
                                title='Verify long-form evidence', description='Review synthetic test details.',
                                assignee_user_id=1, assignee_role_id=None, created_by_id=1,
                                due_date=(date.today() + timedelta(days=4)).isoformat())
        item_id = item.id
    token = login_as(client, 'admin')
    client.post(f'/work-items/{item_id}/action', data={'csrf_token': token,
                 'status': 'in_progress', 'rationale': 'Validated the evidence chain and recorded supporting details.'},
                follow_redirects=False)
    html = client.get(f'/work-items/{item_id}').text
    assert 'class="work-detail-layout"' in html
    assert html.index('id="work-assignment-title"') < html.index('id="work-reassign-title"')
    assert html.index('id="work-status-title"') < html.index('id="work-audit-title"')
    assert 'class="work-timeline"' in html
    assert 'Validated the evidence chain and recorded supporting details.' in html
    assert 'class="history-item"' not in html
    assert 'event' in html


def test_title_case_branding_and_editable_gavel_logo(web):
    client, _ = web
    login_as(client, 'admin')
    html = client.get('/').text
    assert '<span class="brand-name">Arbitrator</span>' in html
    assert '<footer>Arbitrator</footer>' in html
    assert '/static/icons.svg#gavel' in html
    assert '/static/favicon.svg' in html
    sprite = (ROOT/'app/static/icons.svg').read_text()
    assert '<symbol id="gavel"' in sprite
    assert (ROOT/'app/static/favicon.svg').exists()
    assert 'ARBITRATOR' not in html


def test_work_item_styles_are_not_constrained_by_legacy_history_grid():
    css = (ROOT/'app/static/site.css').read_text()
    assert '.work-detail-layout{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))' in css
    assert '.work-event{display:grid;grid-template-columns:15px minmax(0,1fr)' in css
    assert '.work-event-note{' in css
    assert 'overflow-wrap:anywhere' in css
