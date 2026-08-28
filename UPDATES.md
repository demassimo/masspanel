# Independent signed updates

MassPanel updates are handled by a separate root-owned service. It does not
import the panel application, use the panel virtual environment, or require the
panel database/API to be operational.

```bash
sudo masspanel-update check
sudo masspanel-update apply
sudo masspanel-update status
sudo masspanel-update rollback
```

The six-hour systemd timer checks the signed beta manifest. Automatic
installation is disabled by default; set `automatic_updates` to `true` in
`/etc/masspanel-updater/config.json` to opt in.

Every release manifest is signed with Ed25519. The private key remains on the
release machine; installations contain only the public verification key. An
update is extracted only after its signature, declared size and SHA-256 digest
all verify. Unsafe archive paths and links are rejected.

Before applying a release, the updater stores a root-only rollback snapshot in
`/var/lib/masspanel-updater/backups`. If independent Python, Nginx, systemd,
API and frontend health checks fail, it restores the snapshot automatically.

Build a release on the trusted release machine:

```bash
python tools/build-update-release.py \
  --package deploy-package \
  --private-key /secure/path/masspanel-update-signing-private.pem \
  --base-url https://masspanel.masscomputing.co.za/releases/beta \
  --channel beta \
  --output outputs/beta
```

Upload the generated artifact and `manifest.json` only after staging tests pass.
Never upload or copy the private signing key to a MassPanel server.
