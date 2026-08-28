# Cloudflare integration

Cloudflare synchronization is optional and disabled by default. Each MassPanel server owner creates and enters their own API token. MassPanel does not provide a shared token and release packages must never contain one. Multiple connections are supported for zones held in different Cloudflare accounts.

Use the smallest possible token scope:

- Zone / Zone / Read
- Zone / DNS / Edit
- Restrict Zone Resources to only the zones managed by this server

Account-owned tokens beginning with `cfat_` also require their 32-character Account ID. Standard user API tokens can leave the Account ID blank. MassPanel verifies the token with Cloudflare before saving it and does not return the token through its public status API.

Tokens are stored locally in `/etc/masspanel/cloudflare-connections.json` and must be readable only by the privileged MassPanel helper. They are installation secrets: exclude them from third-party backups, diagnostics, source archives and Git repositories. Remove or rotate a connection after exposure or when no longer required.
