"""Reproducible Unit 5 evidence: measure actual importer/correlation behavior.

Use: python -m scripts.evaluate_core --output docs/evidence/core_metrics.json
Runs entirely against ephemeral in-memory SQLite with synthetic, licensed fixtures.
"""
from __future__ import annotations
import argparse
import json
import statistics
import time
from pathlib import Path
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.models import Base, Asset, Finding, Observation
from app.services import create_assessment, import_findings

SAMPLES=Path(__file__).resolve().parents[1]/'sample_data'


def evaluate_once() -> dict:
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        a=create_assessment(session,'Evaluation engagement','Baseline')
        b=create_assessment(session,'Evaluation engagement','Retest')
        baseline=(SAMPLES/'manual_assessment_01.csv').read_bytes()
        retest=(SAMPLES/'manual_assessment_02.csv').read_bytes()
        start=time.perf_counter()
        first=import_findings(session,baseline,'baseline.csv','generic_csv',assessment_id=a.id)
        elapsed_first=time.perf_counter()-start
        duplicate=import_findings(session,baseline,'baseline.csv','generic_csv',assessment_id=a.id)
        start=time.perf_counter()
        second=import_findings(session,retest,'retest.csv','generic_csv',assessment_id=b.id)
        elapsed_second=time.perf_counter()-start
        metrics={
            'baseline_rows': first.rows,
            'retest_rows': second.rows,
            'new_findings_baseline':first.findings_created,
            'new_findings_retest':second.findings_created,
            'reobserved_retest':second.reobserved,
            'exact_file_idempotent':duplicate.previously_imported,
            'assets':session.scalar(select(func.count()).select_from(Asset)),
            'tracked_findings':session.scalar(select(func.count()).select_from(Finding)),
            'observations':session.scalar(select(func.count()).select_from(Observation)),
            'baseline_duration_ms':round(elapsed_first*1000,3),
            'retest_duration_ms':round(elapsed_second*1000,3),
            'baseline_observations_per_second':round(first.observations_created/max(elapsed_first,0.000001),1),
        }
    engine.dispose()
    if not metrics['exact_file_idempotent']:
        raise AssertionError('Same-assessment duplicate import was not idempotent')
    if metrics['observations'] != first.observations_created+second.observations_created:
        raise AssertionError('Unexpected observation count')
    return metrics


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runs',type=int,default=5)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not 1 <= args.runs <= 50:parser.error('runs must be between 1 and 50')
    measurements=[evaluate_once() for _ in range(args.runs)]
    summary={k:v for k,v in measurements[-1].items() if not k.endswith(('_ms','_second'))}
    for key in ('baseline_duration_ms','retest_duration_ms','baseline_observations_per_second'):
        summary[key+'_median']=round(statistics.median(m[key] for m in measurements),3)
    report={'sample':'Synthetic, local, labeled baseline and retest CSVs',
            'run_count':args.runs,'method':'Fresh in-memory SQLite instance per run; performance excludes DB initialization',
            'results':summary,
            'limitations':'Small synthetic inputs; not a representative production-scale benchmark; no externally validated matching truth set.'}
    rendered=json.dumps(report,indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(rendered)
    print(rendered)

if __name__=='__main__': main()
