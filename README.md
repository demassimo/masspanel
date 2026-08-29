# MassPanel — Open-Source Hosting Control Panel

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Latest beta](https://img.shields.io/github/v/release/demassimo/masspanel?include_prereleases&label=public%20beta)](https://github.com/demassimo/masspanel/releases)
[![Ubuntu 24.04 LTS](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?logo=ubuntu&logoColor=white)](INSTALL.md)
[![Live demo](https://img.shields.io/badge/demo-live-0878f9)](https://demo.masscomputing.co.za/)

MassPanel is a free, self-hosted web-hosting control panel for Ubuntu 24.04
LTS. It is an open-source alternative for people evaluating cPanel,
DirectAdmin, Plesk, CyberPanel, HestiaCP or ISPConfig. MassPanel manages hosting
customers, websites, domains, DNS, databases, applications, TLS certificates,
backups, email and groupware from a single owner and customer portal.

MassPanel is an independent project. It is not affiliated with, endorsed by or
a drop-in clone of any product named above.

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

## Why MassPanel?

- **No mandatory subscription:** self-host the AGPL-licensed source.
- **Web and groupware together:** website hosting plus Gromox and grommunio Web.
- **Owner and customer portals:** packages, account limits, support and visible impersonation.
- **DNS flexibility:** built-in authoritative DNS or optional per-server Cloudflare connections.
- **Safer operations:** signed updates, rollback checks, firewall controls and audit activity.
- **Modern application tools:** WordPress management, additional app installers, file management and database browsing.

### Comparing hosting panels

| If you are searching for… | MassPanel approach |
| --- | --- |
| Open-source cPanel alternative | AGPL source, customer accounts, websites, DNS, email, databases and backups |
| DirectAdmin alternative | Owner/customer workflow, packages, domain limits and reseller-oriented management |
| CyberPanel alternative | Nginx-based hosting, application installation, TLS and firewall tools |
| Plesk alternative | Unified website, mail, DNS, database and customer administration |
| HestiaCP or ISPConfig alternative | Ubuntu-focused, self-hosted control plane with a modern React interface |

Feature names describe MassPanel's own capabilities and do not imply exact
compatibility or feature parity with another product.

## Install

Use a new Ubuntu 24.04 LTS server with a public static IPv4 address. Read [INSTALL.md](INSTALL.md), prepare DNS and PTR records, extract a versioned release, and run `sudo ./setup.sh`. The command prints a one-time setup URL on port 8080. The port is closed after installation succeeds.

Download the newest signed package from [GitHub Releases](https://github.com/demassimo/masspanel/releases). MassPanel is currently a public beta; begin with a clean test server and maintain independent backups.

## Public demo

Try the read-only demonstration at [demo.masscomputing.co.za](https://demo.masscomputing.co.za/).

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

## Keywords

`hosting control panel` · `open-source cPanel alternative` · `DirectAdmin alternative` · `CyberPanel alternative` · `Plesk alternative` · `web hosting panel` · `Ubuntu hosting control panel` · `Nginx control panel` · `mail server control panel` · `Gromox` · `grommunio Web`
