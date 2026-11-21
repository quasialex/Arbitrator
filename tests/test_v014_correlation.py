"""Cross-source candidate associations are conservative and human reviewed."""
from app.models import Asset,Vulnerability,Finding
from app.correlation import find_candidates


def test_same_asset_and_cve_suggests_cross_source_not_merge(db_session):
    asset=Asset(identity_key='api.example.test',display_name='API')
    other_asset=Asset(identity_key='api2.example.test',display_name='Other API')
    one=Vulnerability(source='nessus_csv',external_key='1234',title='Outdated TLS lib',cve='CVE-2026-12345')
    two=Vulnerability(source='nuclei_jsonl',external_key='test-tls',title='Outdated TLS library',cve='CVE-2026-12345')
    three=Vulnerability(source='plextrac_json',external_key='mock',title='Other weakness',cve='CVE-2026-99999')
    db_session.add_all([asset,other_asset,one,two,three]);db_session.flush()
    f1=Finding(fingerprint='a'*64,asset_id=asset.id,vulnerability_id=one.id,severity='High',location='443/tcp')
    f2=Finding(fingerprint='b'*64,asset_id=asset.id,vulnerability_id=two.id,severity='High',location='443/tcp')
    f3=Finding(fingerprint='c'*64,asset_id=other_asset.id,vulnerability_id=two.id,severity='High',location='443/tcp')
    f4=Finding(fingerprint='d'*64,asset_id=asset.id,vulnerability_id=three.id,severity='High')
    db_session.add_all([f1,f2,f3,f4]);db_session.commit()
    candidates=find_candidates(db_session,f1.id)
    assert [(c.finding.id,c.confidence) for c in candidates]==[(f2.id,'High')]
    assert 'CVE-2026-12345' in candidates[0].reason
    assert db_session.get(Finding,f1.id) and db_session.get(Finding,f2.id)


def test_without_strong_evidence_no_match(db_session):
    asset=Asset(identity_key='192.0.2.2',display_name='Host')
    a=Vulnerability(source='nuclei_jsonl',external_key='n1',title='Header issue')
    b=Vulnerability(source='nessus_csv',external_key='n2',title='A different issue')
    db_session.add_all([asset,a,b]);db_session.flush()
    f1=Finding(fingerprint='a'*64,asset_id=asset.id,vulnerability_id=a.id,severity='Low')
    f2=Finding(fingerprint='b'*64,asset_id=asset.id,vulnerability_id=b.id,severity='High')
    db_session.add_all([f1,f2]);db_session.commit()
    assert find_candidates(db_session,f1.id)==[]
