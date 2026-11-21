#!/usr/bin/env bash
# Split tracing into deterministic test batches. A single full-suite pytest-cov
# pass can stall under resource-constrained interpreters during coverage finalization.
set -euo pipefail
python -m pytest -q \
  tests/test_importers.py tests/test_services.py tests/test_v02.py \
  tests/test_v06_domain.py tests/test_v012_import_parity.py \
  tests/test_v014_correlation.py tests/test_v017_release.py \
  --cov=app --cov-report=
python -m pytest -q \
  tests/test_v06_auth.py tests/test_v08_features.py tests/test_v09_polish.py \
  --cov=app --cov-append --cov-report=
python -m pytest -q \
  tests/test_v010_layout.py tests/test_v011_ui.py \
  tests/test_v013_integrations.py tests/test_v013_web.py \
  --cov=app --cov-append --cov-report=
python -m pytest -q \
  tests/test_v014_integrations.py tests/test_v0151_ui.py \
  tests/test_v015_workflows.py tests/test_v0162_demo.py \
  tests/test_v07_identity_ui.py \
  --cov=app --cov-append --cov-report=term-missing --cov-report=xml
