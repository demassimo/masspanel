# Third-party software, licences and modifications

Original MassPanel code is source-available under the MassPanel Hosting License
1.0. This licence does not apply to separately licensed upstream components
or add restrictions to their licences. MassPanel is not affiliated
with or endorsed by any upstream project listed below. Product names identify
compatible software only. Complete licence texts are retained in
`third_party/licenses`, and pinned source is in `third_party/source-archives`.

| Component | Pinned version | How it is used | Licence | Source and notices |
|---|---:|---|---|---|
| Gromox | runtime commit `e85e712` / reference 3.9 | Primary mailbox store, IMAP, POP3 and EWS backend | AGPL-3.0-or-later | Runtime and reference source archives; Gromox AGPL text |
| grommunio Web | runtime commit `f26f375c3` / reference 4.5.1 | Primary webmail and groupware UI; **modified by MassPanel** | AGPL-3.0-or-later | Runtime and reference source archives; deployed patch in `deploy/runtime-patches`; grommunio Web AGPL text |
| grommunio Admin API | runtime commit `9f1ba46` / reference 1.20 | Mail domain and mailbox management | AGPL-3.0 | Runtime and reference source archives |
| grommunio Sync | runtime commit `0d70954` / reference 2.5 | Exchange ActiveSync | AGPL-3.0 | Runtime and reference source archives |
| grommunio DAV | runtime commit `752697a` / reference 1.7 | CalDAV and CardDAV | AGPL-3.0 | Runtime and reference source archives |
| SnappyMail | 2.38.2 | Optional legacy webmail installer | AGPL-3.0 | Unmodified upstream archive containing its licence |
| AdminNeo | 5.7.0 | MariaDB browser with separate MassPanel authentication configuration | Apache-2.0 or GPL-2.0 | Upstream archive plus Apache-2.0 text |
| FileBrowser Quantum | 1.5.3-stable | Per-account file manager using proxy authentication | Apache-2.0 | Exact upstream binary plus Apache-2.0 text |
| WordPress | Stable selected by WP-CLI | Optional per-domain CMS | GPL-2.0-or-later | Downloaded from WordPress with upstream notices intact |
| WP-CLI | Pinned installer release | WordPress lifecycle manager | MIT | Upstream PHAR |
| React / React DOM | 19.3.1 | MassPanel browser interface | MIT | Package lock and included MIT texts |
| Lucide | 1.8.0 | Interface icons | ISC | Vendored source with ISC text |
| Flask | 3.1.2 | HTTP API | BSD-3-Clause | Exact private-environment requirement |
| Argon2-cffi | 25.1.0 | Password hashing | MIT | Exact private-environment requirement |
| Gunicorn | 23.0.0 | WSGI server | MIT | Exact private-environment requirement |
| psutil | 7.0.0 | Resource metrics | BSD-3-Clause | Exact private-environment requirement |
| cryptography | 45.0.6 | Signature verification | Apache-2.0 or BSD-3-Clause | Exact private-environment requirement |
| dnspython | 2.8.0 | Imported DNS zone parsing | ISC | Exact private-environment requirement |
| imapsync | 2.314 / commit `8895966244fb161cc68f2c8427a8f6326a7f2ab0` | Optional verified mail migration; modified APPEND flag handling | NLPL | Pinned hash in installer; original and modified source and notices installed with the tool |

## MassPanel modifications to AGPL software

MassPanel modifies
`grommunio-web/server/includes/core/class.webappauthentication.php`. The
modification was made on 2026-08-28 and adds administrator-assisted mailbox
access and suspended-mailbox handling. The modified preferred source is
`deploy/runtime-patches/class.webappauthentication.php`; its exact unmodified
base is `third_party/source-archives/runtime-grommunio-web-f26f375c3.tar.gz`.

The updater installs that patch from source. Webmail users receive a prominent
link to `/masspanel-source`, where the complete release source and licences can
be downloaded without authentication or charge. The optional
`deploy/configure-grommunio-community.py` script also modifies the Admin API's
local Community default capacity, preserving certificate verification and
upstream notices. It installs original and modified source with notices;
see `docs/GROMMUNIO_COMMUNITY.md`. The optional Gromox correction is documented
below. MassPanel does not modify Sync or DAV source. The optional imapsync
installer retains the upstream NLPL notice and publishes its APPEND
compatibility adjustment with the installed source.

## Redistribution rules

- Preserve upstream copyright, licence, SPDX and attribution notices.
- Do not release unless every included archive matches `sources.lock.json`.
- Do not distribute `gromox-container-0.0.4.tar.gz`; it contains no licence file
  and the release builder expressly excludes it.
- Publish the corresponding-source archive beside every binary installer.
- Commercial use and paid support are permitted. AGPL/GPL recipients retain
  their rights to copy, inspect, change and redistribute covered software.

### Optional Gromox INTERNALDATE correction

`deploy/patch-gromox-internaldate.py` changes only the transient midb response
digest in Gromox revision `01cda79696b5ce97c4283a1868dc4dddfa7b3987`.
It reports the stored delivery timestamp as IMAP INTERNALDATE, retaining exact
RFC822 message bytes. The modified file retains its upstream copyright and
SPDX `GPL-2.0-only WITH linking exception` notice. The complete source tree
contains additional component-specific notices, all retained. Build details and
source-offer requirements are in `docs/GROMOX_INTERNALDATE.md`.
