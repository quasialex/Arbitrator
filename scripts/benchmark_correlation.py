"""Deterministic synthetic cross-source evaluation; no external calls or real hosts."""
from __future__ import annotations
import argparse
import csv
import io
import json
import statistics
import time
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, joinedload

from app.correlation import find_candidates
from app.models import Base, Finding, Vulnerability
from app.services import create_assessment, import_findings

FIELDS = ('Asset', 'Finding', 'Severity', 'Plugin ID', 'CVE', 'Port', 'Protocol')


def generate_fixtures(size: int) -> tuple[bytes, bytes, list[dict]]:
    """Produce size records in two import batches plus labeled pairwise truth.

    Every tenth comparison: 7 true matching services, 1 CVE match at a
    different service endpoint (negative), 1 confirmed asset alias that our
    conservative identity matching misses, 1 unrelated finding (negative).
    An alias is not automatically reconciled: source identity is authoritative.
    """
    if size % 20 or not 100 <= size <= 1000:
        raise ValueError('size must be a multiple of 20 from 100 through 1000')
    source_a, source_b, cases = [], [], []
    for i in range(size // 2):
        kind = ('true_match' if i % 10 <= 6 else
                'different_service' if i % 10 == 7 else
                'asset_alias' if i % 10 == 8 else 'unrelated')
        asset = f'node{i:04d}.example.test'
        cve = f'CVE-2026-{10000+i}'
        title = f'Synthetic service security issue {i:04d}'
        source_a.append([asset, title, 'High', f'a-{i:04d}', cve, '443', 'tcp'])
        peer_asset = f'alias-node{i:04d}.example.test' if kind == 'asset_alias' else asset
        peer_cve = f'CVE-2026-{30000+i}' if kind == 'unrelated' else cve
        peer_title = f'Unrelated synthetic finding {i:04d}' if kind == 'unrelated' else title
        peer_port = '8443' if kind == 'different_service' else '443'
        source_b.append([peer_asset, peer_title, 'High', f'b-{i:04d}', peer_cve, peer_port, 'tcp'])
        cases.append({'baseline_plugin': f'plugin:a-{i:04d}',
                      'candidate_plugin': f'plugin:b-{i:04d}', 'case': kind,
                      'same_underlying_issue': kind in {'true_match', 'asset_alias'}})

    def encode(rows):
        output = io.StringIO(newline='')
        writer = csv.writer(output, lineterminator='\n')
        writer.writerow(FIELDS)
        writer.writerows(rows)
        return output.getvalue().encode('utf-8')

    return encode(source_a), encode(source_b), cases


def evaluate(size: int = 1000, runs: int = 1, output_dir: Path | None = None) -> dict:
    a_data, b_data, cases = generate_fixtures(size)
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / 'baseline_generic.csv').write_bytes(a_data)
        (output_dir / 'followup_nessus.csv').write_bytes(b_data)
        (output_dir / 'ground_truth.json').write_text(json.dumps(cases, indent=2) + '\n')
    trials = []
    for _ in range(runs):
        engine = create_engine('sqlite://')
        Base.metadata.create_all(engine)
        with Session(engine, expire_on_commit=False) as db:
            baseline = create_assessment(db, 'Synthetic benchmark', 'Baseline')
            followup = create_assessment(db, 'Synthetic benchmark', 'Follow-up')
            start = time.perf_counter()
            first = import_findings(db, a_data, 'baseline_generic.csv', 'generic_csv', baseline.id)
            second = import_findings(db, b_data, 'followup_nessus.csv', 'nessus_csv', followup.id)
            import_ms = (time.perf_counter()-start)*1000
            # Exact identifier lookup avoids relying on auto-incremented IDs.
            findings = db.scalars(select(Finding).join(Finding.vulnerability).options(
                joinedload(Finding.vulnerability))).all()
            ids = {(f.vulnerability.source, f.vulnerability.external_key): f.id for f in findings}
            tp = fp = tn = fn = 0
            start = time.perf_counter()
            for case in cases:
                reference_id = ids[('generic_csv', case['baseline_plugin'])]
                candidate_id = ids[('nessus_csv', case['candidate_plugin'])]
                predicted = any(c.finding.id == candidate_id for c in find_candidates(db, reference_id))
                actual = case['same_underlying_issue']
                if predicted and actual: tp += 1
                elif predicted: fp += 1
                elif actual: fn += 1
                else: tn += 1
            correlation_ms = (time.perf_counter()-start)*1000
            trials.append(dict(tp=tp, fp=fp, fn=fn, tn=tn, import_ms=import_ms,
                               correlation_ms=correlation_ms, rows=first.rows+second.rows,
                               unique_findings=first.findings_created+second.findings_created))
        engine.dispose()
    v = trials[-1]
    precision = v['tp'] / (v['tp']+v['fp']) if v['tp']+v['fp'] else 0
    recall = v['tp'] / (v['tp']+v['fn']) if v['tp']+v['fn'] else 0
    result = {'fixture': 'Deterministic synthetic pairwise truth; candidate suggestions, not automatic merges',
              'records': size, 'labeled_pairs': len(cases), 'runs': runs,
              'confusion': {k:v[k] for k in ('tp','fp','fn','tn')},
              'precision': round(precision, 4), 'recall': round(recall, 4),
              'f1': round(2*precision*recall/(precision+recall), 4) if precision+recall else 0,
              'median_import_ms': round(statistics.median(t['import_ms'] for t in trials), 2),
              'median_candidate_eval_ms': round(statistics.median(t['correlation_ms'] for t in trials), 2),
              'limitations': ('Artificially constructed case ratios; asset aliases intentionally remain unresolved, '
                              'same-CVE different-service suggestions are not auto-merges. '
                              'No claim of real-world classification accuracy or service-scale performance.')}
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--records', type=int, default=1000)
    p.add_argument('--runs', type=int, default=1)
    p.add_argument('--output', type=Path)
    p.add_argument('--dataset-dir', type=Path)
    args = p.parse_args()
    if not 1 <= args.runs <= 5: p.error('runs must be 1..5')
    try:
        metrics = evaluate(args.records, args.runs, args.dataset_dir)
    except ValueError as exc:
        p.error(str(exc))
    report = json.dumps(metrics, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report)
    print(report)


if __name__ == '__main__':
    main()
