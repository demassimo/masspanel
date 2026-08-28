# Security model

MassPanel is a privileged hosting control plane. A server owner can create system users, publish Nginx and DNS configuration, manage databases and mail, request certificates, inspect services and impersonate customer interfaces for support. Compromise of an owner account should be treated as compromise of the server and hosted customer data.

The web API runs as an unprivileged service account. Privileged operations pass through a root-owned helper with an explicit operation allow-list. Nginx is the public entry point. The installer and updater run separately as root because they replace service files and packages; update manifests and artifacts are verified with the bundled public signing key before application, and failed health checks trigger rollback.

Customer, reseller and owner authorization must be checked by the API and again when resolving filesystem, website, database, DNS and mailbox targets. File operations must remain inside the account's allowed roots. Support impersonation must be deliberate, visible and recorded in the audit log.

Secrets belong in root-controlled files under `/etc/masspanel` or in the service-specific credential store. Frontend bundles, source releases, logs and API responses must never contain plaintext credentials. Public source archives contain public verification keys only.
