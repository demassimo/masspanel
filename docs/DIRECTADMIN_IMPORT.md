# DirectAdmin import into MassPanel

The administrator-only **Imports** page inspects native DirectAdmin `.tar.gz`
and `.tar.zst` account backups, then runs a root-owned background restore job.
This is a staged migration: the source stays online and public DNS is not
changed automatically. Test on a disposable destination before production use.

## Prerequisites

- Ubuntu 24.04, the updated MassPanel backend/helper, and the Python requirements.
- Enough MassPanel domain capacity for every selected domain. The importer uses
  the same signed entitlement check as ordinary domain creation.
- A configured Grommunio/Gromox mail system with sufficient mailbox capacity.
  No destination Dovecot installation is required.
- Every source PHP version installed and explicitly mapped in root-owned
  `/etc/masspanel/directadmin-import.json`, for example:
  `{"php_versions":{"1":"8.3","4":"7.4"},"homeserver":0}`.
- A verified independent backup and sufficient disk space for staged archives,
  extraction, restored files, databases and mail.

Transfer completed native account backups into
`/var/lib/masspanel-imports/directadmin/incoming/`, owned by root, mode 0600.
Do not place private backups, passwords, identity exports or migration logs in
the application checkout or a public web directory.

Native backups omit the password records for default mailboxes. Run
`deploy/export-directadmin-identities.py OUTPUT.json` as root on the source,
then securely copy its output to
`/var/lib/masspanel-imports/directadmin/source-inventory.json` (root, 0600).
This preserves current hosting and mailbox hashes, including default mailboxes
whose password differs from their hosting account password. Refresh this export
and inspect again after source password changes. The export also records primary
and subdomain document roots, including URL-encoded DirectAdmin overrides.
Imported roots are restricted to the owning account's domains directory and
recorded in root-owned `/etc/masspanel/imported-webroots.json`.

## Read-only mail connection

Install `deploy/directadmin-imap-source.py` as
`/usr/local/libexec/masspanel-da-imap-source` on the source (root, 0700).
Create `/root/directadmin-migration/imap-allowlist`, one approved full mailbox
address per line, root-owned and private. Use a dedicated destination SSH key
whose source authorized_keys entry has `restrict`, a destination-IP `from=`,
and `command="/usr/local/libexec/masspanel-da-imap-source"` restrictions.
Pin the verified source host key in a dedicated known_hosts file.

Create `/etc/masspanel/directadmin-source.json` on the destination (root, 0600):

```json
{
  "host": "source.example.com",
  "identity_file": "/root/directadmin-migration/source-imap",
  "known_hosts": "/root/directadmin-migration/known_hosts",
  "target_hostname": "mail.example.com"
}
```

The source broker uses the existing DirectAdmin Dovecot installation for
read-only IMAP access. It changes SELECT to EXAMINE and rejects STORE, APPEND,
EXPUNGE and other mutations. Suspended accounts are read without unsuspending
them. The temporary destination PREAUTH bridge accepts only root-owned local
connections, enforced by a short-lived nftables rule.

Run `sudo python3 deploy/install-directadmin-imapsync.py` on the destination.
It installs a SHA-256-verified, pinned imapsync revision and a small Gromox
compatibility adjustment. Gromox can reject custom keywords during large
APPEND requests; the adjustment sends supported APPEND flags, then applies the
original flags with STORE using `--syncflagsaftercopy --nofilterflags`. If an
immediate post-APPEND FETCH returns no flags, the known destination UID is
still updated with STORE; a STORE failure remains a transfer error.
Original and modified source and notices are installed under
`/usr/share/masspanel/source/imapsync`.

## Preservation and verification

- Hosting usernames, supported SHA-512-crypt passwords, and suspension status
  are retained. Successful panel login upgrades the stored hash to Argon2
  without changing the user's password.
- Original database names, supported mysql_native_password hashes, access
  hosts and database grants are retained. SQL is restored using a temporary
  database-scoped account, not root SQL privileges.
- Website files, matching TLS certificate/key pairs and DNS zone contents are
  restored. DNS addresses remain unchanged until an explicit cutover. Zones
  with records the editor cannot represent are protected from editor rewrites.
- Mail folders, subscriptions, messages, flags and internal dates are copied
  through IMAP. No delete or expunge option is enabled. Passwords are changed
  temporarily only on the staged destination and restored in a finally block.
- Every copied mailbox is checked against the source using imapsync UID
  mappings: source-message coverage, flags (excluding session-only Recent),
  internal dates and RFC822 sizes must agree. Private verification reports
  identify mismatches and stop the job; a successful copy alone is insufficient.

Some Gromox versions derive IMAP INTERNALDATE from the Received header. Messages
without that header can expose an incorrect date after APPEND. The importer
detects this and stops for review; it does not silently rewrite message headers.
The optional revision-pinned fix in [Gromox INTERNALDATE](GROMOX_INTERNALDATE.md)
uses the stored delivery timestamp without changing message content.
Concurrent source deliveries or flag changes can also require another delta
and verification pass before cutover.

## Review, restore and cutover

Select staged archives in **Imports**, inspect them, review the compatibility
warnings, then start the restore. Replacing an existing initial `admin` password
requires the explicit admin-merge checkbox. Preflight checks domain capacity,
identity completeness, archive fingerprints, conflicts, PHP mappings, database
credentials, disk space and mail capacity before changing destination accounts.

Jobs and private plans are under
`/var/lib/masspanel-imports/directadmin/jobs/JOB_ID`. A SQLite snapshot is saved
before restore. Completed accounts are checkpointed; a partially restored
account requires operator review before retrying. The importer deliberately
does not overwrite unknown existing resources. The snapshot is not a complete
filesystem or mail-store rollback: retain the native backups and VM backups.

systemd cleanup restores temporary mailbox passwords after worker failure.
After a power loss, run the worker's `cleanup` phase before enabling destination
mail access. Keep the destination closed to customers throughout staging.

Before cutover, verify website routing and application behavior, database grants,
TLS, DNS, inbound/outbound mail, client authentication and per-folder metadata.
Run a final mail delta during a controlled source-write pause, verify again, then
change DNS/MX and provider reverse DNS as appropriate. Keep the old server and
backups until the migration is accepted. Remove migration SSH keys afterwards.

## Settings requiring separate migration review

This importer does not claim that every DirectAdmin feature has an equivalent.
Cron jobs, domain pointers, OpenLiteSpeed or
Apache rewrite rules, autoresponders/vacation rules, spam rules, DKIM settings,
webmail contacts/preferences and application-management registrations require
separate review. Their original data remains in the source/native backups.
Links to DirectAdmin's shared AWStats program directories are omitted during
extraction; the account's statistics data files are retained.
Unsupported catch-all, pipe and file aliases block restore. Ordinary address
forwarders are restored. A Unix mailbox without an associated domain remains in
the restored home and requires a chosen destination mailbox.

See [Grommunio Community customization](GROMMUNIO_COMMUNITY.md) for the optional
local Community capacity and EMSMDB configuration script.
