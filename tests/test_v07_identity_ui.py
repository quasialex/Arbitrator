"""v0.7: identity fields, service-code policy, navigation and header behavior."""
from sqlalchemy import select
from app.models import Asset, Finding
from app.classification import address_fields_from_source, service_code_from_identifier
from app.services import create_assessment, import_findings
from app.workflows import edit_asset
from app.routing import create_routing_rule, apply_routing
from app.workflows import create_team
from tests.test_v06_auth import web, login_as, SAMPLE


def test_ip_and_hostname_are_independent_evidence(db_session):
    assert address_fields_from_source('192.0.2.10') == (None, '192.0.2.10')
    assert address_fields_from_source('web01.example.test') == ('web01.example.test', None)
    assert service_code_from_identifier('web01.example.test') is None
    a = create_assessment(db_session, 'Research', 'Infrastructure')
    import_findings(db_session, b'asset,title,severity\n192.0.2.10,TLS disabled,High\nweb01.example.test,Weak cookie,Medium\n', 'test.csv', 'generic_csv', a.id)
    ip = db_session.scalar(select(Asset).where(Asset.identity_key == '192.0.2.10'))
    web = db_session.scalar(select(Asset).where(Asset.identity_key == 'web01.example.test'))
    assert ip.ip_address == '192.0.2.10' and ip.hostname is None and ip.service_code is None
    assert web.hostname == 'web01.example.test' and web.ip_address is None and web.service_code is None


def test_manual_enrichment_does_not_merge_asset_identities(db_session):
    a = create_assessment(db_session,'Research','Infrastructure')
    import_findings(db_session, b'asset,title,severity\n192.0.2.10,Header,High\n', 'test.csv', 'generic_csv', a.id)
    asset = db_session.scalar(select(Asset))
    edit_asset(db_session,asset.id,asset.display_name,'Review required',[],service_code='ADM001',
               hostname='admin.example.test',ip_address='192.0.2.10')
    assert asset.identity_key == '192.0.2.10'
    assert asset.hostname == 'admin.example.test'
    assert asset.service_code == 'ADM001'
    t=create_team(db_session,'Ops','ops@example.test')
    create_routing_rule(db_session,t.id,'hostname_suffix','example.test','none','')
    assert apply_routing(db_session)['matched']==1
    assert db_session.scalar(select(Finding)).assigned_owner_id==t.id


def test_account_menu_in_top_bar_and_nested_breadcrumb(web):
    client,_=web
    login_as(client,'admin')
    response=client.get('/account/password')
    assert response.status_code==200
    html=response.text
    assert 'class="account-menu"' in html
    assert 'Change password' in html and 'Sign out' in html
    assert html.index('class="account-menu"') < html.index('<main class="content">')
    assert 'class="sidebar-bottom"' not in html
    # Templates can render nested levels within the last breadcrumb segment.
    response=client.get('/ownership/teams')
    assert response.status_code==200
    assert '<nav class="breadcrumb"' in response.text
    assert 'Security Operations' in response.text


def test_asset_form_accepts_and_persists_dns_ip_service_code(web):
    client,factory=web
    with factory() as s:
        assessment=create_assessment(s,'Corp','Assessment')
        import_findings(s,SAMPLE.read_bytes(),'sample.csv','generic_csv',assessment.id)
        asset=s.scalar(select(Asset))
        asset_id=asset.id
    token=login_as(client,'admin')
    page=client.get(f'/assets/{asset_id}')
    assert 'DNS hostname' in page.text
    assert 'Organizational service code' in page.text
    resp=client.post(f'/assets/{asset_id}',data={'csrf_token':token,'display_name':'Asset A',
        'exposure':'Internal','hostname':'srv01.corp.example', 'ip_address':'10.0.0.7',
        'service_code':'ORA001','external_ref':'CMDB-0007'},follow_redirects=False)
    assert resp.status_code==303
    with factory() as s:
        asset=s.get(Asset,asset_id)
        assert (asset.hostname,asset.ip_address,asset.service_code)==('srv01.corp.example','10.0.0.7','ORA001')
