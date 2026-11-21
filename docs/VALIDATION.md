# Validation methodology

## What was measured

- `pytest` exercises importers, domain workflows, access control, UI routes, mocked integrations, sample loader and error handling. Coverage is a separate measure from correlation accuracy.
- Earlier local runs of v0.17 passed 136 tests, and batched pytest-cov measured 81% line coverage. Run the current suite and coverage script locally or in CI for up-to-date results; these are code execution metrics, not exploit-detection accuracy.
- `scripts.evaluate_core` benchmarks baseline/retest import idempotency and reobservations on tiny synthetic fixtures using in-memory SQLite.
- `scripts.benchmark_correlation` constructs **1,000** synthetic CSV finding instances, divided into two named assessment sources, with **500 labeled paired comparisons**. The synthetic evaluation deliberately includes identical issue/service matches, same-CVE different-service candidates, unresolved asset aliases, and unrelated findings. Timing excludes database initialization.
- `scripts.verify_sqlite_backup` demonstrates non-destructive SQLite backup and restore validation using the native online backup API and content integrity checks.

## Measured synthetic results (three local runs)

| Measure | Result |
|---|---:|
| Finding instances imported | 1,000 |
| Labeled comparisons | 500 |
| True positive / false positive | 350 / 50 |
| False negative / true negative | 50 / 50 |
| Candidate precision | 0.875 |
| Candidate recall | 0.875 |
| Candidate F1 | 0.875 |
| Import elapsed (median across 3 local runs) | 2,696 ms |
| Candidate evaluation (median across 3 local runs) | 398 ms |
| Synthetic database backup restored | Yes — 27 tables, integrity check OK |

The commands above can reproduce synthetic benchmarks and backup checks. CI uploads current results as build artifacts.

## Interpretation and limitations

These ratios are **designed fixture properties**, not representative field accuracy. A same-CVE match on distinct ports is intentionally flagged for human review; the metric counts it as a candidate false positive against strict underlying-issue labels. An alternate hostname for the same underlying asset that is not explicitly reconciled becomes a false negative. **The application never auto-merges candidates.** Runtime will vary by host, Python version, storage, and background load. No production claims can be made from repeated runs on a synthetic truth set.

Before production use, complete independent validation, security review, accessibility testing and recovery exercises.
