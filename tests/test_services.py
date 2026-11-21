from pathlib import Path
from sqlalchemy import select, func
from app.models import Asset, Vulnerability, Finding, Observation, ImportBatch, Owner, GovernanceDecision
from app.services import import_findings
from app.workflows import record_decision, create_team, create_decision_maker, assign_finding

SAMPLES = Path(__file__).resolve().parents[1] / "sample_data"


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_initial_import_creates_normalized_relations(db_session):
    raw = (SAMPLES / "manual_assessment_01.csv").read_bytes()
    stats = import_findings(db_session, raw, "manual_assessment_01.csv", "generic_csv")
    assert (stats.rows, stats.assets_created, stats.findings_created, stats.observations_created) == (3, 2, 3, 3)
    assert count(db_session, Owner) == 0  # import source owners never establish accountability
    assert count(db_session, Asset) == 2
    assert count(db_session, Vulnerability) == 3
    assert count(db_session, Finding) == 3
    assert count(db_session, Observation) == 3


def test_same_file_reimport_is_idempotent(db_session):
    raw = (SAMPLES / "manual_assessment_01.csv").read_bytes()
    import_findings(db_session, raw, "01.csv", "generic_csv")
    second = import_findings(db_session, raw, "new_name.csv", "generic_csv")
    assert second.previously_imported
    assert count(db_session, ImportBatch) == 1
    assert count(db_session, Observation) == 3


def test_second_import_preserves_finding_history(db_session):
    raw1 = (SAMPLES / "manual_assessment_01.csv").read_bytes()
    raw2 = (SAMPLES / "manual_assessment_02.csv").read_bytes()
    import_findings(db_session, raw1, "01.csv", "generic_csv")
    stats = import_findings(db_session, raw2, "02.csv", "generic_csv")
    assert stats.findings_created == 1
    assert stats.reobserved == 2
    assert count(db_session, Finding) == 4
    assert count(db_session, Observation) == 6


def test_duplicate_rows_within_batch(db_session):
    data = b"Host,Name,Severity,Plugin ID,Output\nweb.test,Example,Low,123,proof\nweb.test,Example,Low,123,proof\n"
    stats = import_findings(db_session, data, "duplicate.csv", "generic_csv")
    assert stats.duplicate_rows == 1
    assert count(db_session, Observation) == 1


def test_validation_failure_is_atomic(db_session):
    import pytest
    from app.importers import ImportValidationError
    bad_data = b"Host,Name,Risk\nserver.test,Example,High\nserver2.test,Example,INVALID\n"
    with pytest.raises(ImportValidationError):
        import_findings(db_session, bad_data, "bad.csv", "generic_csv")
    assert count(db_session, Asset) == 0
    assert count(db_session, ImportBatch) == 0


def test_governance_decisions_append_and_do_not_close_finding(db_session):
    raw = b"Host,Name,Severity\nweb.test,Test finding,High\n"
    import_findings(db_session, raw, "01.csv", "generic_csv")
    f = db_session.scalar(select(Finding))
    team = create_team(db_session, "Web Team")
    approver = create_decision_maker(db_session, "Morgan Demo", "Security lead")
    assign_finding(db_session, f.id, str(team.id))
    record_decision(db_session, f.id, "defer", approver.id, "Pending approved change window", "2028-01-15")
    record_decision(db_session, f.id, "request_remediation", approver.id, "Please schedule a remediation plan")
    assert count(db_session, GovernanceDecision) == 2
    assert db_session.get(Finding, f.id).status == "open"
    assert db_session.get(Finding, f.id).workflow_state == "remediation_requested"
