# Security policy

## Supported versions

During the public beta, only the newest signed beta release receives security fixes. Installations should use the built-in update page and keep Ubuntu security updates enabled.

## Reporting a vulnerability

Do not open a public issue containing a vulnerability, credential, customer record, mailbox content or server log with personal data. Contact the security address published by the project owner in the repository security policy. Until that address is configured, use the private contact method listed on the project's GitHub profile.

Include the affected MassPanel version, component, reproduction steps and impact. Remove passwords, API tokens, session cookies, private keys and customer data. The public beta has no contractual response time or warranty.

## Operator responsibilities

- Use unique administrator passwords and SSH keys.
- Restrict SSH and administrative access with the firewall.
- Use least-privilege API tokens and rotate them after suspected exposure.
- Keep encrypted backups on another system and test restoration.
- Protect `/etc/masspanel`, database credentials and signing material.
- Never copy private update or licence signing keys into a release.
- Review audit, firewall, mail-security and update logs regularly.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for trust boundaries.
