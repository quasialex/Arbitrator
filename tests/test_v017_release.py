"""v0.17 release controls: bounded benchmark, restore evidence and compact UI."""
import sqlite3
from pathlib import Path
from scripts.benchmark_correlation import generate_fixtures, evaluate
from scripts.verify_sqlite_backup import verify
from app.models import Base
from sqlalchemy import create_engine


def test_synthetic_benchmark_reproducible_truth_and_metrics(tmp_path):
    a, b, truth = generate_fixtures(100)
    assert len(truth) == 50
    assert len(a.splitlines()) == len(b.splitlines()) == 51
    metrics = evaluate(100, output_dir=tmp_path)
    assert metrics['records'] == 100
    assert metrics['confusion'] == {'tp': 35, 'fp': 5, 'fn': 5, 'tn': 5}
    assert metrics['precision'] == metrics['recall'] == metrics['f1'] == 0.875
    assert (tmp_path/'ground_truth.json').is_file()


def test_benchmark_size_is_bounded():
    import pytest
    for invalid in (0, 1, 99, 101, 5001):
        with pytest.raises(ValueError):
            generate_fixtures(invalid)


def test_sqlite_backup_restores_tables_without_touching_source(tmp_path):
    path = tmp_path / 'test.sqlite3'
    engine = create_engine('sqlite:///' + str(path))
    Base.metadata.create_all(engine)
    engine.dispose()
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO engagements (name,client,scope,created_at) VALUES ('Sample','Test','',CURRENT_TIMESTAMP)")
    before = path.read_bytes()
    result = verify(path)
    assert result['restored'] and result['foreign_key_violations'] == 0
    assert result['table_row_counts']['engagements'] == 1
    assert path.read_bytes() == before


def test_compact_remediation_selector_replaces_stretched_input():
    root = Path(__file__).resolve().parents[1]
    html = (root/'app/templates/finding_detail.html').read_text()
    css = (root/'app/static/site.css').read_text()
    assert 'finding-remediation-panel' in html and 'remediation-form' in html
    assert '.finding-detail-grid .finding-remediation-panel > form.remediation-form' in css
    assert 'max-height:44px' in css


def test_fixture_generation_is_byte_reproducible():
    one = generate_fixtures(200)
    two = generate_fixtures(200)
    assert one == two
    assert len(one[2]) == 100
