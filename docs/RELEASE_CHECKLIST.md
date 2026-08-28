# Public release checklist

## Source and legal notices

- [ ] Version and release tag match.
- [ ] `LICENSE`, `NOTICE`, `THIRD_PARTY.md` and `SOURCE_OFFER.md` are current.
- [ ] Every bundled dependency has a declared source, version and licence.
- [ ] Modified AGPL components identify changed files and corresponding source.
- [ ] Compliance report passes and undeclared archives are rejected.

## Secret and privacy gate

- [ ] Scan source, built frontend, archives and Git history for secrets.
- [ ] Confirm no Cloudflare token, SSH credential, signing key or customer data.
- [ ] Confirm only public verification keys are distributed.
- [ ] Remove caches, logs, dumps and machine-specific configuration.

## Verification

- [ ] Install on a clean Ubuntu 24.04 LTS virtual machine.
- [ ] Verify successful installation closes port 8080.
- [ ] Test owner, reseller and customer permissions.
- [ ] Test website, DNS, database, app, certificate and backup workflows.
- [ ] Test SMTP, IMAP, webmail, EWS, ActiveSync, quarantine and mail flow.
- [ ] Test signed update, failed-update rollback and backup restoration.
- [ ] Verify panel and mail source URLs without authentication.
- [ ] Record known issues and checksums in release notes.

## Publication

- [ ] Publish only after the sanitization gate passes.
- [ ] Create a signed version tag and attach the verified archive.
- [ ] Link source pages to the matching tag while retaining the exact installed source download.
- [ ] Mark the release clearly as public beta.
