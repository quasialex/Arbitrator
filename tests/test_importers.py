import pytest
from app.importers import (
    parse_csv, ImportValidationError, normalize_asset, normalize_severity,
    finding_fingerprint, FindingInput,
)


def test_generic_headers_and_optional_plugin_id():
    raw = b"Host,Finding,Risk,Owner\nWeb01.Example.TEST.,Access control gap,High,AppSec\n"
    records = parse_csv(raw)
    assert len(records) == 1
    assert records[0].asset == "web01.example.test"
    assert records[0].title == "Access control gap"
    assert records[0].severity == "High"
    assert records[0].plugin_id == ""


def test_nessus_numeric_severity():
    raw = b"Host,Plugin ID,Name,Risk\n192.0.2.3,10001,TLS configuration,3\n"
    records = parse_csv(raw, "nessus_csv")
    assert records[0].severity == "High"
    assert records[0].plugin_id == "10001"


def test_empty_asset_rejected_with_row_number():
    with pytest.raises(ImportValidationError, match="Row 2"):
        parse_csv(b"Host,Name,Severity\n,Example,Low\n")


def test_malformed_csv_rejected():
    with pytest.raises(ImportValidationError, match="extra fields"):
        parse_csv(b"Host,Name\nserver,Example,extra\n")


def test_non_utf8_rejected():
    with pytest.raises(ImportValidationError, match="UTF-8"):
        parse_csv(b"Host,Name\nserver,\xff\n")


def test_invalid_severity_not_silently_mapped():
    with pytest.raises(ImportValidationError, match="Unsupported severity"):
        parse_csv(b"Host,Name,Risk\nserver,Example,7\n")


def test_same_plugin_different_asset_finding_not_merged():
    left = FindingInput(asset="web01.test", title="Vulnerability", severity="High", plugin_id="100")
    right = FindingInput(asset="web02.test", title="Vulnerability", severity="High", plugin_id="100")
    assert finding_fingerprint("nessus_csv", left) != finding_fingerprint("nessus_csv", right)


def test_same_plugin_different_port_not_merged():
    left = FindingInput(asset="web01.test", title="Vulnerability", severity="High", plugin_id="100", port="80", protocol="tcp")
    right = FindingInput(asset="web01.test", title="Vulnerability", severity="High", plugin_id="100", port="443", protocol="tcp")
    assert finding_fingerprint("nessus_csv", left) != finding_fingerprint("nessus_csv", right)


def test_source_scoped_fingerprints():
    record = FindingInput(asset="web01.test", title="Vulnerability", severity="High", plugin_id="100")
    assert finding_fingerprint("nessus_csv", record) != finding_fingerprint("generic_csv", record)


def test_normalize_ipv6():
    assert normalize_asset("2001:0DB8:0:0::2") == "2001:db8::2"
