# Contributing

Use a topic branch off `development`. Include regression tests and documentation for any change to parser mappings, RBAC, governance transitions or asset ownership. Format code clearly, avoid unnecessary dependencies, and keep the entity relationships described in `docs/ARCHITECTURE.md` intact.

Run `python -m pytest -q` and the synthetic benchmark before opening a pull request. Do not submit client scan results, authentication keys, live API responses, names/emails of real customers or system inventory. Use synthetic fixtures and redact logs.

Changes involving automatic merging, risk acceptance, data deletion, access-control widening or remote API side effects require explicit review and focused tests.
