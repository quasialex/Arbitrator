import re
from pathlib import Path
from sqlalchemy import select, func
from app.classification import service_code_from_identifier, classify_asset
from app.models import Asset, AssetTeam, Finding, Observation, RoutingRule
from app.services import create_assessment, import_findings
from app.routing import create_routing_rule, update_routing_rule, apply_routing, matches, validate_rule
from app.workflows import create_team, assign_finding, edit_asset

DATA=Path(__file__).resolve().parents[1]/'sample_data'/'synthetic_campaign'


def load(session,eng='Research 2026',filename='manual_baseline.csv'):
    assess=create_assessment(session,eng,'Assessment '+eng)
    stats=import_findings(session,(DATA/filename).read_bytes(),filename,'generic_csv',assess.id)
    return assess,stats


def test_assets_global_across_engagements(db_session):
    a,s1=load(db_session,'Q4 2026')
    b,s2=load(db_session,'Q1 2027')
    assert s1.assets_created==7
    assert s2.assets_created==0
    assert s2.findings_created==0
    assert s2.reobserved==8
    assert db_session.scalar(select(func.count(Asset.id)))==7
    assert db_session.scalar(select(func.count(Finding.id)))==8
    assert db_session.scalar(select(func.count(Observation.id)))==16
    assert a.engagement_id!=b.engagement_id


def test_asset_schema_not_bound_to_engagement(db_session):
    asset=Asset(identity_key='web01.example.test',display_name='web01',service_code='WEB01')
    db_session.add(asset);db_session.commit()
    assert not hasattr(asset,'engagement_id')


def test_finding_single_responsible_team(db_session):
    load(db_session)
    t1=create_team(db_session,'OS Team','os@example.test')
    t2=create_team(db_session,'App Team','app@example.test')
    finding=db_session.scalar(select(Finding))
    assign_finding(db_session,finding.id,str(t1.id))
    assert finding.assigned_owner_id==t1.id
    assign_finding(db_session,finding.id,str(t2.id))
    assert finding.assigned_owner_id==t2.id
    assert not hasattr(finding,'stakeholders')


def test_asset_can_have_multiple_stakeholder_teams(db_session):
    load(db_session)
    t1=create_team(db_session,'OS Team','os@example.test')
    t2=create_team(db_session,'App Team','app@example.test')
    asset=db_session.scalar(select(Asset))
    edit_asset(db_session,asset.id,asset.display_name,'Internal',[t1.id,t2.id])
    assert {m.team_id for m in asset.memberships}=={t1.id,t2.id}
    finding=db_session.scalar(select(Finding).where(Finding.asset_id==asset.id))
    assert finding.assigned_owner_id is None


def test_service_code_not_inferred_from_dns_label():
    assert service_code_from_identifier('sso01.corp.example') is None
    assert service_code_from_identifier('192.0.2.1') is None
    assert service_code_from_identifier('db01.example.com') is None


def test_exposure_hostname_requires_evidence():
    assert classify_asset('web01.example.test')[0]=='Review required'
    assert classify_asset('10.2.3.4')[0]=='Internal'
    assert classify_asset('192.0.2.1')[0]=='Review required'


def test_global_rules_work_across_assessments(db_session):
    a,_=load(db_session,'One')
    b,_=load(db_session,'Two')
    team=create_team(db_session,'Platform','platform@example.test')
    create_routing_rule(db_session,team.id,'hostname_suffix','atlas.example.test','none','')
    report=apply_routing(db_session)
    assert report['total']==8
    assert report['matched']>0
    assert all(f.assigned_owner_id==team.id for f in db_session.scalars(select(Finding)).all())


def test_vulnerability_specific_routing_overrides_generic_asset_mapping(db_session):
    load(db_session)
    web=create_team(db_session,'Web','web@example.test')
    os=create_team(db_session,'OS','os@example.test')
    create_routing_rule(db_session,web.id,'hostname_suffix','atlas.example.test','none','')
    create_routing_rule(db_session,os.id,'hostname_suffix','atlas.example.test','title_contains','tls')
    apply_routing(db_session)
    tls=db_session.scalars(select(Finding)).all()
    for f in tls:
      assert f.assigned_owner_id==(os.id if 'tls' in f.vulnerability.title.lower() else web.id)


def test_conflicting_equally_specific_rules_fail_closed(db_session):
    load(db_session)
    a=create_team(db_session,'Blue','blue@example.test')
    b=create_team(db_session,'Red','red@example.test')
    create_routing_rule(db_session,a.id,'hostname_suffix','atlas.example.test','none','')
    create_routing_rule(db_session,b.id,'hostname_suffix','atlas.example.test','none','')
    report=apply_routing(db_session)
    assert report['conflicts']>0
    assert any(f.assignment_source=='conflict' and f.assigned_owner_id is None for f in db_session.scalars(select(Finding)))


def test_rule_edit_not_toggle(db_session):
    a=create_team(db_session,'Blue','blue@example.test')
    b=create_team(db_session,'Red','red@example.test')
    rule=create_routing_rule(db_session,a.id,'service_code_regex',r'^web\d+$','none','')
    changed=update_routing_rule(db_session,rule.id,b.id,'service_code_regex',r'^sso\d+$','none','')
    assert changed.team_id==b.id and changed.asset_pattern==r'^sso\d+$'
    assert not hasattr(changed,'priority')
    assert not hasattr(changed,'engagement_id')
    assert not hasattr(changed,'active')


def test_regex_matches_service_code_and_vulnerability(db_session):
    load(db_session)
    for asset in db_session.scalars(select(Asset)).all():
        if asset.hostname and asset.hostname.startswith("web"):
            asset.service_code = "WEB001"
    db_session.commit()
    t=create_team(db_session,'Web','web@example.test')
    rule=create_routing_rule(db_session,t.id,'service_code_regex',r'^web\d+$','title_regex',r'cookie|cors')
    apply_routing(db_session)
    rows=db_session.scalars(select(Finding)).all()
    target=[f for f in rows if f.asset.service_code and f.asset.service_code.startswith('WEB') and any(p in f.vulnerability.title.lower() for p in ['cookie','cors'])]
    assert target and all(f.assigned_owner_id==t.id for f in target)


def test_invalid_regex_rejected(db_session):
    team=create_team(db_session,'Web','web@example.test')
    import pytest
    with pytest.raises(ValueError,match='regular expression'):
        create_routing_rule(db_session,team.id,'hostname_regex','[', 'none','')


def test_no_condition_rule_rejected():
    import pytest
    with pytest.raises(ValueError,match='asset or vulnerability'):
        validate_rule('none','','none','')


def test_manual_routing_is_preserved(db_session):
    load(db_session)
    a=create_team(db_session,'Blue','blue@example.test')
    b=create_team(db_session,'Red','red@example.test')
    create_routing_rule(db_session,a.id,'hostname_suffix','atlas.example.test','none','')
    f=db_session.scalar(select(Finding));assign_finding(db_session,f.id,str(b.id))
    apply_routing(db_session)
    assert f.assigned_owner_id==b.id and f.assignment_source=='manual'
