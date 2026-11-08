# Optional Grommunio Community source customization

`deploy/configure-grommunio-community.py --users 1000 --restart` adjusts the
installed Admin API's local Community default capacity and sets:

```ini
emsmdb_max_obh_per_session = 1000
emsmdb_max_cxh_per_user = 300
```

These are resource ceilings, not a promise of improved performance. Size and
monitor the host for its workload. The script restarts the affected services
when requested; a full host reboot is unnecessary for these settings.

The AST-checked change only updates the literal default user count in
`_defaultLicense`. Signed certificate processing remains unchanged. This is a
local source modification, not a commercial subscription or an issued license.
It does not alter MassPanel's own domain entitlement checks.

The script backs up original files with checksums under
`/var/backups/masspanel/grommunio-community/` and installs original/modified
preferred source plus notices under
`/usr/share/masspanel/source/grommunio-community-customization/`. Preserve all
upstream notices and make the modified corresponding source available to users
of the deployed service. Package updates can replace the change; review and
rerun the script against the updated package rather than editing arbitrary
occurrences of `users=`. Unexpected source layouts stop the script.
