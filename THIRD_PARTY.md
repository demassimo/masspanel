# Third-party software, licences and modifications

MassPanel is an independent AGPL-3.0-or-later project. It is not affiliated
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
| React / React DOM | 19.1.1 | MassPanel browser interface | MIT | Package lock and included MIT texts |
| Lucide | 1.8.0 | Interface icons | ISC | Vendored source with ISC text |
| Flask | 3.1.2 | HTTP API | BSD-3-Clause | Exact private-environment requirement |
| Argon2-cffi | 25.1.0 | Password hashing | MIT | Exact private-environment requirement |
| Gunicorn | 23.0.0 | WSGI server | MIT | Exact private-environment requirement |
| psutil | 7.0.0 | Resource metrics | BSD-3-Clause | Exact private-environment requirement |
| cryptography | 45.0.6 | Signature verification | Apache-2.0 or BSD-3-Clause | Exact private-environment requirement |

## MassPanel modifications to AGPL software

MassPanel modifies
`grommunio-web/server/includes/core/class.webappauthentication.php`. The
modification was made on 2026-08-28 and adds administrator-assisted mailbox
access and suspended-mailbox handling. The modified preferred source is
`deploy/runtime-patches/class.webappauthentication.php`; its exact unmodified
base is `third_party/source-archives/runtime-grommunio-web-f26f375c3.tar.gz`.

The updater installs that patch from source. Webmail users receive a prominent
link to `/masspanel-source`, where the complete release source and licences can
be downloaded without authentication or charge. MassPanel does not currently
modify Gromox, Admin API, Sync or DAV source.

## Redistribution rules

- Preserve upstream copyright, licence, SPDX and attribution notices.
- Do not release unless every included archive matches `sources.lock.json`.
- Do not distribute `gromox-container-0.0.4.tar.gz`; it contains no licence file
  and the release builder expressly excludes it.
- Publish the corresponding-source archive beside every binary installer.
- Commercial use and paid support are permitted. AGPL/GPL recipients retain
  their rights to copy, inspect, change and redistribute covered software.
