"""Reproducible fictional multi-engagement campaign. No real client data."""
from pathlib import Path
from datetime import date, timedelta
from sqlalchemy import select
from app.database import SessionLocal, init_db
from app.models import Asset, Finding, Engagement
from app.services import create_assessment, import_findings
from app.routing import create_routing_rule, apply_routing
from app.workflows import create_team, create_decision_maker, record_decision

DATA = Path(__file__).resolve().parents[1] / 'sample_data' / 'synthetic_campaign'
PLAN = [
    ('Baseline web/API penetration test', 'manual_baseline.csv','generic_csv','2026-09-01','2026-09-03'),
    ('Manual retest', 'manual_retest.csv','generic_csv','2026-10-06','2026-10-06'),
    ('Infrastructure assessment', 'nessus_infrastructure.csv','nessus_csv','2026-10-12','2026-10-13'),
    ('Nuclei web scan', 'nuclei_web.jsonl','nuclei_jsonl','2026-10-20','2026-10-21'),
    ('Consultant report', 'plextrac_findings.json','plextrac_json','2026-11-02','2026-11-05'),
]

def seed_campaign(session):
    if session.scalar(select(Engagement).where(Engagement.name=='Atlas Labs — 2026 Research')):
        print('Synthetic campaign already present; nothing changed')
        return
    t={name: create_team(session,name,name.lower().replace(' ','-')+'@example.test')
       for name in ['API Team','Web Platform','OS Operations','Infrastructure','Identity Team','Data Services']}
    # Global rules: no engagement ID, priority, or owner from imported report.
    mappings=[('hostname_suffix','api01.atlas.example.test','API Team'),
              ('hostname_suffix','api02.atlas.example.test','API Team'),
              ('hostname_suffix','web01.atlas.example.test','Web Platform'),
              ('hostname_suffix','web02.atlas.example.test','Web Platform'),
              ('hostname_suffix','sso01.atlas.example.test','Identity Team'),
              ('hostname_suffix','db01.atlas.example.test','Data Services'),
              ('hostname_suffix','cdn01.atlas.example.test','Infrastructure'),
              ('cidr','192.0.2.0/24','Infrastructure')]
    for kind,pattern,team in mappings:
        create_routing_rule(session,t[team].id,kind,pattern,'none','')
    # This 2-criterion rule outranks the broader hostname-only rule.
    create_routing_rule(session,t['OS Operations'].id,'hostname_suffix','atlas.example.test','title_contains','TLS')
    for title,filename,src,start,end in PLAN:
        assessment=create_assessment(session, 'Atlas Labs — 2026 Research',title,
                     'Atlas Labs (fictional)','Authorized fictional assets only',
                     started_on=start, ended_on=end)
        stats=import_findings(session,(DATA/filename).read_bytes(),filename,src,assessment.id)
        print(f'{title}: {stats.rows} records, {stats.findings_created} new findings, {stats.reobserved} reobservations')
    # Fictional, explicitly curated service codes; no DNS-label guessing.
    codes = {"admin": "ADM001", "web01": "WEB001", "web02": "WEB002",
             "api01": "API001", "api02": "API002", "sso01": "SSO001",
             "db01": "ORA001", "cdn01": "CDN001"}
    for asset in session.scalars(select(Asset)).all():
        if asset.hostname:
            asset.service_code = codes.get(asset.hostname.split(".")[0])
    session.commit()
    # Same assets, separate engagement, shared findings: proves global identity model.
    revalidation=create_assessment(session,'Atlas Labs — 2027 Follow-up','Independent revalidation',
                                   'Atlas Labs (fictional)','Same global assets, distinct engagement',
                                   started_on='2027-01-12',ended_on='2027-01-12')
    stats=import_findings(session,(DATA/'manual_baseline.csv').read_bytes(),'revalidation.csv','generic_csv',revalidation.id)
    print(f'Cross-engagement revalidation: {stats.findings_created} new, {stats.reobserved} reobserved')
    print('Routing:',apply_routing(session))
    web=session.scalar(select(Asset).where(Asset.identity_key=='web01.atlas.example.test'))
    if web:
        web.exposure='External';web.classification_source='manual'
        web.classification_reason='Synthetic scope-owner verification, not inferred from DNS'
    db=session.scalar(select(Asset).where(Asset.identity_key=='db01.atlas.example.test'))
    if db:
        db.exposure='Internal';db.classification_source='manual'
        db.classification_reason='Synthetic network access review'
    session.commit()
    security_lead=create_decision_maker(session,'Avery Morgan','Security lead')
    risk_approver=create_decision_maker(session,'Jordan Reid','Risk approver')
    create_decision_maker(session,'Sam Taylor','Business service representative')
    owned=[f for f in session.scalars(select(Finding).order_by(Finding.id)).all() if f.assigned_owner_id]
    if len(owned)>=2:
        record_decision(session,owned[0].id,'request_remediation',security_lead.id,'Fictional remediation ownership acknowledged')
        record_decision(session,owned[1].id,'defer',risk_approver.id,'Fictional temporary deferral pending review',
                        (date.today()+timedelta(days=40)).isoformat())
    print('Demo data ready: global assets persist across two engagements and six assessments.')


def main():
    init_db()
    with SessionLocal() as session:
        seed_campaign(session)

if __name__=='__main__': main()
