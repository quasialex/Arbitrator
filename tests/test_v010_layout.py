"""UI-level regression checks for v0.10, preserving v0.9 behavior."""
from datetime import date, timedelta
from pathlib import Path
from sqlalchemy import select
from test_v06_auth import web, login_as
from test_v08_features import load_finding
from app.models import Asset, AccessRole
from app.governance_tasks import create_work_item

ROOT = Path(__file__).resolve().parents[1]


def test_overview_layout_and_branding(web):
    client, _ = web
    login_as(client, 'admin')
    html = client.get('/').text
    assert 'Arbitrator' in html
    assert 'VulnDocket' not in html
    assert '<h1>Security assessment intelligence</h1>' in html
    assert '+ New assessment' not in html
    assert 'class="panel dashboard-queue"' in html
    assert html.index('UNASSIGNED FINDINGS') < html.index('class="panel dashboard-queue"')
    assert html.index('class="panel dashboard-queue"') < html.index('Findings by severity')
    assert html.index('Findings by severity') < html.index('Latest findings')
    assert 'View my work' in html
    assert 'My next actions' not in html
    assert client.get('/assessments').status_code == 200
    assert '+ New assessment' in client.get('/assessments').text


def test_role_scoped_tasks_still_respect_permissions_in_dashboard(web):
    client, factory = web
    fid = load_finding(factory)
    with factory() as db:
        role = db.scalar(select(AccessRole).where(AccessRole.name == 'Governance Approver'))
        create_work_item(db, finding_id=fid, kind='risk_approval',
                         title='Review risk exception', description='Fixture',
                         assignee_role_id=role.id, assignee_user_id=None,
                         created_by_id=1, due_date=(date.today()+timedelta(days=2)).isoformat())
    login_as(client, 'viewer')
    assert 'Review risk exception' not in client.get('/').text
    login_as(client, 'approver')
    html = client.get('/').text
    assert 'Review risk exception' not in html
    assert 'href="/work-items?bucket=mine" class="dashboard-queue-metric"><strong>1</strong>' in html
    assert html.index('dashboard-queue') < html.index('Findings by severity')


def test_governance_create_action_on_right_and_work_items_link(web):
    client,_=web
    login_as(client, 'admin')
    html=client.get('/governance').text
    assert 'class="heading"' in html
    assert 'href="/work-items/new" class="button primary"' in html
    assert 'class="governance-utility"' in html
    assert 'href="/work-items"' in html
    assert html.index('href="/work-items/new"') < html.index('class="governance-utility"')


def test_assets_show_findings_not_stakeholder_team_editor(web):
    client, factory=web
    fid=load_finding(factory)
    login_as(client,'admin')
    with factory() as db:
        a=db.scalar(select(Asset))
        aid=a.id
    listing=client.get('/assets').text
    detail=client.get(f'/assets/{aid}').text
    assert 'Asset inventory' in listing
    assert 'STAKEHOLDER TEAMS' not in listing
    assert 'Bulk-add stakeholder team' not in listing
    assert 'Asset details' in detail
    assert 'Stakeholder teams (multiple allowed' not in detail
    assert 'Vulnerabilities affecting this asset' in detail
    assert 'RESPONSIBLE TEAM' in detail
    assert 'Assets</a>' in listing


def test_settings_icon_is_actual_gear(web):
    client,_=web
    login_as(client,'admin')
    html=client.get('/').text
    sprite=(ROOT/'app/static/icons.svg').read_text()
    assert '/static/icons.svg#settings' in html
    assert '<symbol id="settings"' in sprite
    assert 'circle cx="12" cy="12"' in sprite
    assert 'M10 2h4l' in sprite


def test_editing_asset_identity_does_not_silently_delete_legacy_associations(web):
    from app.models import AssetTeam
    from app.workflows import create_team
    client, factory = web
    load_finding(factory)
    with factory() as db:
        asset=db.scalar(select(Asset))
        team=create_team(db,'Legacy inventory team','inventory@example.test')
        asset.memberships.append(AssetTeam(team_id=team.id))
        db.commit()
        asset_id=asset.id
        team_id=team.id
    token=login_as(client,'admin')
    response=client.post(f'/assets/{asset_id}',data={
        'csrf_token':token,'display_name':'New display name','exposure':'Internal',
        'external_ref':'CMDB-01','service_code':'WEB001',
    },follow_redirects=False)
    assert response.status_code==303
    with factory() as db:
        asset=db.get(Asset,asset_id)
        assert asset.display_name=='New display name'
        assert [m.team_id for m in asset.memberships]==[team_id]
