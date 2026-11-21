# Arbitrator

**Open-source vulnerability management and risk governance.**

Arbitrator is a Python/FastAPI application for consolidating security assessment results, assigning remediation responsibility and recording risk-governance decisions. It supports multi-source evidence, traceable finding histories, role-based access controls and governance work items.

> **Status:** v0.18.0 — an open-source development release. Suitable for local demonstration and authorized test data. Not independently security-audited or production-hardened. Tenable and ServiceNow connectors have automated mocked tests but still require live-environment validation.

## Features

- Import generic penetration-test CSV, Nessus CSV, Nuclei JSONL and PlexTrac PTRAC exports.
- Track global assets, vulnerability findings and repeated observations across assessments without assigning assets to engagements.
- Assign **one accountable remediation team per finding** with deterministic organization-wide routing and manual overrides.
- Record governance decisions, approvals, escalations, deadlines and audit history.
- Manage user accounts, configurable RBAC roles and per-account display preferences.
- Optional encrypted Tenable API export and ServiceNow incident/group integration.
- Sortable, filterable registers with pagination; local synthetic campaign and benchmark fixtures.

## Quick start

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m scripts.create_admin
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Open <http://127.0.0.1:8001/>. The administrator setup prompts for a password; the project ships **no default credentials**. Run **Accounts & permissions → New account** to create additional users.

The default SQLite database filename remains `assessment_v015.sqlite3` for upgrade compatibility. Use `ASSESSMENT_DB_URL` to configure another database location. Back up your database and preserve its URL when upgrading; **do not** create a new administrator against an existing populated database.

## Explore sample data

Open **Import center → Manage sample data** to load the fictional Atlas Labs campaign into an empty assessment workspace (6 assessments, 14 assets, 27 findings, 39 observations). Loading is opt-in, and existing workspaces are not overwritten.

For a disposable test environment, specify a separate database before creating an administrator:

```bash
mkdir -p local_data
export ASSESSMENT_DB_URL="sqlite:///$PWD/local_data/sample.sqlite3"
python -m scripts.create_admin
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

To reset **only this disposable database**, stop the server and remove `local_data/sample.sqlite3`; creating a new database also removes all accounts and governance records held there. Do not delete an active database to clear example findings. See [Data management](docs/DATA_MANAGEMENT.md).

## Verify

```bash
python -m pytest -q
bash scripts/run_coverage.sh
python -m scripts.benchmark_correlation --records 1000 --runs 1
python -m scripts.verify_sqlite_backup
```

Synthetic benchmark results do not measure real-world vulnerability-detection accuracy. Cross-source candidate correlation is advisory and **never merges findings automatically**.

## Integrations and security

Tenable and ServiceNow connections are optional. To enable encrypted credential storage, supply a persistent Fernet key via `ARBITRATOR_CREDENTIAL_KEY` from a secret manager or protected environment:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Never commit credentials, access tokens or production scan data. A saved connector is not evidence that authentication has been tested. Use only authorized endpoints. See [Architecture](docs/ARCHITECTURE.md) for security boundaries.

## Documentation

- [Architecture and data model](docs/ARCHITECTURE.md)
- [Importer formats](docs/IMPORT_FORMATS.md)
- [Data management, backup and restore](docs/DATA_MANAGEMENT.md)
- [Validation approach](docs/VALIDATION.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and testing conventions and [SECURITY.md](SECURITY.md) for responsible vulnerability reporting. Arbitrator is distributed under the [MIT License](LICENSE).
