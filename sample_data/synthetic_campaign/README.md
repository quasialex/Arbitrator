# Fully synthetic assessment campaign

All organizations, systems, assets, tests, and evidence are invented. `atlas.example.test` is used for documentation only. `192.0.2.0/24` is a reserved documentation network.

Recommended walkthrough:
1. Engagement: `Atlas Labs — Q4 Research`; Assessment: `Baseline manual penetration test`. Import `manual_baseline.csv` as Generic CSV.
2. Same engagement; Assessment: `Manual retest`. Import `manual_retest.csv` as Generic CSV. Four findings reappear with new evidence and two are new; two absent baseline findings **must not** be marked fixed.
3. Same engagement; Assessment: `Infrastructure vulnerability assessment`. Import `nessus_infrastructure.csv` as Nessus CSV.
4. Same engagement; Assessment: `Web scanning`. Import `nuclei_web.jsonl` as Nuclei JSONL.
5. Same engagement; Assessment: `Consultant report`. Import `plextrac_findings.json` as PlexTrac finding-object JSON. One finding maps to two affected assets; those instances stay separate.

When different source tools report similar problems, the platform currently keeps them separate rather than claiming an automatically validated cross-tool match.
