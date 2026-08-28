# MassPanel

MassPanel is a self-hosted web-hosting control panel for Ubuntu 24.04 LTS. It manages customers, websites, DNS, databases, applications, certificates, backups, mail and groupware from one owner and customer interface.

> **Public beta:** MassPanel is not yet recommended for irreplaceable production workloads. Test installation, backup and restore procedures before hosting customer data. Keep an independent off-server backup.

## Included services

- Nginx, PHP-FPM and MariaDB website hosting
- BIND authoritative DNS and optional Cloudflare synchronization
- Gromox and grommunio Web mail/groupware integration
- Rspamd, ClamAV, mail tracking and quarantine controls
- Let's Encrypt certificate management
- FileBrowser and AdminNeo administration tools
- WordPress and additional application installers
- Account packages, resellers, suspension, support tickets and audit activity
- A separately running, signed, rollback-capable root updater

## Install

Use a new Ubuntu 24.04 LTS server with a public static IPv4 address. Read [INSTALL.md](INSTALL.md), prepare DNS and PTR records, extract a versioned release, and run `sudo ./setup.sh`. The command prints a one-time setup URL on port 8080. The port is closed after installation succeeds.

## Public demo

Try the read-only demonstration at [panel.masscomputing.co.za](https://panel.masscomputing.co.za/).

| View | Username | Password |
| --- | --- | --- |
| Server owner | `demo-admin` | `MassPanelDemo!2026` |
| Hosting customer | `demo-client` | `MassPanelDemo!2026` |

The demo contains only reserved example domains and sample records. Changes,
uploads, impersonation and email actions are disabled. SMTP is unavailable, so
the example mailboxes cannot send or receive messages. Do not enter real
credentials or customer data into the demo.

## Cloudflare credentials

MassPanel does not ship with a Cloudflare account, token or Account ID. Each server owner optionally adds their own restricted API token in **Domains & DNS**. Connections belong to that MassPanel installation and can be removed by its owner. See [docs/CLOUDFLARE.md](docs/CLOUDFLARE.md).

## Source and licences

MassPanel is licensed under `AGPL-3.0-or-later`. Commercial hosting, paid support and charging for copies are permitted, while recipients and network users retain the rights provided by the AGPL. Official builds may apply a 20-domain product tier; that policy does not remove anyone's AGPL right to inspect, modify and redistribute the source.

MassPanel is independent and is not an official grommunio product. It deploys a documented modification to grommunio Web. See [NOTICE](NOTICE), [THIRD_PARTY.md](THIRD_PARTY.md), [SOURCE_OFFER.md](SOURCE_OFFER.md), and [LICENSING.md](LICENSING.md).

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [SUPPORT.md](SUPPORT.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Do not report vulnerabilities in public issues.
