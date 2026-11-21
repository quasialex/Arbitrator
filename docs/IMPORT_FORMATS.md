# Import formats and field interpretation

| Input | Primary fields | Notes |
|---|---|---|
| Generic consultant CSV | Asset/Host, Finding/Title, Severity | Optional plugin/rule ID, CVE, evidence, description, remediation, port, protocol, path; supports common consultant column layouts |
| Nessus CSV | Host/IP, plugin/title, risk/severity | Numeric risk 0–4 recognized for Nessus; source columns retained in observation metadata |
| Nuclei JSONL | `template-id`, `info.name`, `info.severity`, `host`/`matched-at` | URL location and template metadata retained where available |
| PlexTrac PTRAC (JSON content) | `flaws_array` or `findings`, title, severity, affected assets | Multiple affected assets yield separate observations; not all vendor-specific backup formats are supported |
| Tenable API export | Plugin, asset, severity, detection information | Uses configured credentials, filters and chunked export; live service validation remains outstanding |

Each parsed row becomes a source-scoped vulnerability definition (plugin ID or stable fallback), a global asset record when new, a tracked finding instance, and an observation linked to the selected assessment/import batch. Imported owner labels are metadata, not trustworthy assignment authority. No low/informational records are silently dropped. Validation rejects missing severity rather than silently creating an `Unknown` severity.

Additional legacy input parsers may exist internally for backward compatibility but are **not public UI formats**.
