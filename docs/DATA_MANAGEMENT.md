# Data management and safe sample reset

## What the sample loader does

`/admin/sample-data` is an opt-in, administrator-only loader. It requires empty domain tables, preserves authentication/authorization records, and adds fictional Atlas Labs assessments, imports, assets, findings, observations, routing records, risk decisions and synthetic work items. It does **not** run on application startup.

## Unloading sample records

There is deliberately **no bulk-delete feature** for domain data. Findings have foreign-key relationships to observations, decisions, work items and external incident links. Removing individual tables without understanding these relationships risks destroying unrelated work.

For disposable demonstrations only:

1. Stop the local server on port 8001.
2. Verify the SQLite file path is the *dedicated sample database*, e.g. `local_data/sample.sqlite3`, **not** the default existing workspace or a real database.
3. If you need to preserve it, make a SQLite backup before deleting the file. The backup is sensitive if accounts or integrations were configured.
4. Remove **only the disposable sample SQLite file**. Recreate its admin account (`python -m scripts.create_admin`) and select **Load sample campaign** on the clean workspace.

For persistent installations: retain the database and use a separate environment for experimentation. **Never delete the real assessment database** to clear an example.

## Backup and restore validation

For an existing SQLite database, the non-destructive command below copies it to a temporary location using SQLite's native backup API, restores that snapshot into memory, and checks logical dump digest, integrity and foreign keys. It does not print row contents or save a persistent backup.

```bash
python -m scripts.verify_sqlite_backup --database /absolute/path/to/workspace.sqlite3
```

For a safe, synthetic demonstration, simply run `python -m scripts.verify_sqlite_backup` without arguments. The system must be backed up separately using a durable, protected backup policy before upgrading.

## Synthetic benchmark

Two generated CSV fixtures contain up to 1,000 findings total. For a UI test, create two assessments, import `baseline_generic.csv` and `followup_nessus.csv` as their respective formats and inspect the findings register. This is **not** the 27-finding Atlas Labs web demo; it is a separate, controlled scalability/accuracy fixture. Always import it into a separate empty assessment workspace.
