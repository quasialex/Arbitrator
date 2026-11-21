# Security policy

**Arbitrator v0.18.0 is a research prototype, not an audited production service.** Run locally or only in trusted, access-controlled test environments. It handles sensitive data and API credentials, so test it with synthetic/authorized inputs only.

For vulnerabilities, use a private disclosure channel with the repository maintainer rather than posting details or credentials in a public issue. The public repository maintainer should configure a GitHub security advisory contact before publication.

Never commit real `ASSESSMENT_DB_URL` data files, `.env` secrets, scans or `ARBITRATOR_CREDENTIAL_KEY`. A saved Tenable/ServiceNow connection is not proof of authorization or successful connection. Review RBAC, CSRF, HTTPS/TLS termination, credential rotation, audit retention, database backups and upload size limits before any production deployment.
