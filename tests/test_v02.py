from pathlib import Path
import pytest
from sqlalchemy import func, select
from app.importers import ImportValidationError, parse_source
from app.models import Asset, Assessment, Engagement, Finding, ImportBatch, Observation, Vulnerability
from app.services import create_assessment, import_findings

FILES = Path(__file__).resolve().parents[1] / 'sample_data' / 'synthetic_campaign'

def number(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_nuclei_parser_reads_template_and_location():
    records = parse_source((FILES / 'nuclei_web.jsonl').read_bytes(), 'nuclei_jsonl')
    assert len(records) == 6
    assert records[0].asset == 'web01.atlas.example.test'
    assert records[0].plugin_id == 'atlas-exposed-git'
    assert '/.git/config' in records[0].location
    assert records[0].cve == 'CVE-2025-12345'


def test_plextrac_multiple_affected_assets_and_no_cve():
    records = parse_source((FILES / 'plextrac_findings.json').read_bytes(), 'plextrac_json')
    assert len(records) == 5
    assert records[0].title == records[1].title
    assert records[0].asset != records[1].asset
    assert records[0].severity == 'Critical'
    assert records[0].cve == ''


def test_invalid_jsonl_is_atomic(db_session):
    assessment = create_assessment(db_session, 'Example', 'Test')
    content = b'{"template-id": "test", "host": "https://web.example.test", "info": {"severity": "low"}}\n{bad json'
    with pytest.raises(ImportValidationError, match='line 2'):
        import_findings(db_session, content, 'bad.jsonl', 'nuclei_jsonl', assessment_id=assessment.id)
    assert number(db_session, Finding) == 0
    assert number(db_session, ImportBatch) == 0


def test_plextrac_requires_valid_assets():
    with pytest.raises(ImportValidationError, match='affected_assets'):
        parse_source(b'{"findings":[{"title":"Missing asset","severity":"High"}]}', 'plextrac_json')


def test_assessment_history_and_global_asset_reuse(db_session):
    baseline = create_assessment(db_session, 'Atlas Labs', 'Baseline')
    retest = create_assessment(db_session, 'Atlas Labs', 'Retest')
    other = create_assessment(db_session, 'Another engagement', 'Baseline')
    raw_baseline = (FILES / 'manual_baseline.csv').read_bytes()
    raw_retest = (FILES / 'manual_retest.csv').read_bytes()
    one = import_findings(db_session, raw_baseline, 'base.csv', 'generic_csv', assessment_id=baseline.id)
    two = import_findings(db_session, raw_retest, 'retest.csv', 'generic_csv', assessment_id=retest.id)
    assert (one.findings_created, two.reobserved, two.findings_created) == (8, 4, 2)
    assert number(db_session, Finding) == 10
    assert number(db_session, Observation) == 14
    independent = import_findings(db_session, raw_baseline, 'base.csv', 'generic_csv', assessment_id=other.id)
    assert independent.findings_created == 0
    assert independent.reobserved == 8
    assert number(db_session, Finding) == 10
    assert number(db_session, Asset) == 7  # same global assets, independent assessment provenance
    again = import_findings(db_session, raw_baseline, 'base.csv', 'generic_csv', assessment_id=baseline.id)
    assert again.previously_imported
    assert number(db_session, ImportBatch) == 3


def test_plextrac_same_vuln_multiple_assets_not_merged(db_session):
    a = create_assessment(db_session, 'Atlas Labs', 'PlexTrac import')
    stats = import_findings(db_session, (FILES/'plextrac_findings.json').read_bytes(), 'p.json', 'plextrac_json', assessment_id=a.id)
    assert (stats.rows, stats.findings_created) == (5, 5)
    assert number(db_session, Vulnerability) == 3
    assert number(db_session, Finding) == 5


def test_nuclei_cross_run_idempotency(db_session):
    a = create_assessment(db_session, 'Atlas Labs', 'Nuclei baseline')
    b = create_assessment(db_session, 'Atlas Labs', 'Nuclei retest')
    raw = (FILES/'nuclei_web.jsonl').read_bytes()
    first = import_findings(db_session, raw, 'out.jsonl', 'nuclei_jsonl', assessment_id=a.id)
    again = import_findings(db_session, raw, 'out.jsonl', 'nuclei_jsonl', assessment_id=b.id)
    assert first.findings_created == 6
    assert again.findings_created == 0
    assert again.reobserved == 6
    assert number(db_session, Observation) == 12
