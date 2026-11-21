# Synthetic 1,000-record importer/correlation fixture

- `baseline_generic.csv`: 500 baseline manual CSV observations.
- `followup_nessus.csv`: 500 follow-up Nessus-style CSV observations.
- `ground_truth.json`: 500 labeled cross-source comparison pairs.

The records are entirely fictional. Test domains use `.example.test`, deliberately do not correspond to real hosts, and do not demonstrate scanner capabilities or security reachability. To reproduce the labels and CSV exports, run `python -m scripts.benchmark_correlation --records 1000 --dataset-dir sample_data/benchmark_1000`.

**Import UI procedure:** create two assessments in an isolated workspace, upload each CSV with its corresponding format, inspect the 1,000 tracked finding records, and apply filters or pagination. Do not mix these fixtures with real assessment data.
