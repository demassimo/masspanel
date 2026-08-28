# Install MassPanel on Ubuntu 24.04 LTS

Use a clean server with a public IPv4 address. Create unproxied DNS `A` records
for the panel and mail hostnames before starting. The mail hostname should also
be the server IP's PTR/rDNS name.

```bash
mkdir masspanel-2026.08.28 && cd masspanel-2026.08.28
tar -xzf ../masspanel-2026.08.28.tar.gz
sudo ./setup.sh
```

The command prints a one-time URL on port `8080`. Open it in a browser and enter
the panel hostname, mail hostname, administrator account and certificate email.
The wizard installs and checks:

- MassPanel API and web interface
- Nginx, PHP 8.3, MariaDB and application tooling
- BIND authoritative DNS
- Grommunio Web, Gromox, DAV, ActiveSync and SMTP authentication
- Rspamd, ClamAV and mail tracking/quarantine integration
- AdminNeo and the isolated FileBrowser service
- Let's Encrypt certificates for both the panel and mail hostnames

After all checks pass, port `8080` is removed from the firewall, the installer
service disables itself, and the browser receives the final HTTPS panel URL.

Installer logs are available during setup in the browser and through:

```bash
journalctl -u masspanel-installer -f
```

Do not expose a saved copy of `/etc/masspanel/installer.env`; it contains the
single-use setup token.
