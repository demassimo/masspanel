# PMG mail-feature coverage requirement

## Capability

The server owner requires the complete mail-security feature scope of Proxmox
Mail Gateway, administered through MassPanel, with customer mail review integrated
into Grommunio. A spam score, small tracking table and release button are not
sufficient completion criteria. The current implementation is a staged subset;
**full PMG feature coverage has not been implemented or verified**.

Baseline reviewed on 2026-11-08: the official
[PMG feature catalogue](https://www.proxmox.com/en/products/proxmox-mail-gateway/features)
and [administration guide](https://pmg.proxmox.com/pmg-docs/pmg-admin-guide.html).
These are moving documents; record the installed PMG release/API version when
integration testing starts. Do not imply identical behavior across releases.

## Fixed constraints

- No public cutover until the owner explicitly authorizes it. Keep destination
  mail listeners private, outbound delivery held and customer schedules disabled.
- Keep Grommunio/Gromox as the mailbox service and preserve migration data,
  original credentials, dates and supported flags. No destination Dovecot.
- Spam-learning corrections must be isolated by destination mailbox. Importing
  historical Junk or automatically classifying mail is not user feedback.
- Keep the Ollama connector optional, unconfigured and disabled. No external
  model or automatic model download; owner configuration and content approval
  remain necessary before customer text is sent.
- An administrator may act for a customer, but a customer session may access only
  its authorized mailboxes. Enforce this on the server for every action.
- An accepted message must have a durable custodian. Track each recipient
  independently and distinguish rejection, quarantine and delivery uncertainty.
- Installing packages, adding a UI, configuring a feature and proving that it
  works are separate statuses. Do not claim coverage based on UI presence alone.

## Coverage register

`Staged` means code is present with synthetic tests; it does not mean active mail
flow has been verified. `Partial` means some underlying pieces exist. `Open`
means the requested capability has no completed implementation in this patch.
The reference column identifies the documentation area used for each category.

| Required capability | Current state | Evidence needed before completion | PMG reference |
| --- | --- | --- | --- |
| Inbound and outbound filtering | Partial: staged inbound handoff; outbound remains held | Both directions traverse policy exactly once, including local submissions; no open relay | Features: filtering; guide: deployment |
| Spam scoring and network reputation | Partial: installed Rspamd, staged score integration | Controlled positive/negative fixtures and unavailable-check behavior | Features: detection, DNSBL, SURBL |
| Antivirus and signature lifecycle | Partial: verdict handling; operational coverage unverified | Detection, update freshness, scanner failure and encrypted/oversized content policy | Features: virus scanning |
| Recipient verification, SPF, SMTP/HELO tests, greylisting | Partial: mail services exist; no unified controls | Reject invalid recipients before acceptance, legitimate retries work, exceptions are bounded | Features: filtering methods |
| Reusable From/To/When/What/Action rules | Open | Priority, enablement, direction, Boolean matching and terminal-action behavior tested | Features: rule system |
| Address, domain, IP/network, regex and directory-group objects | Partial: exact mailbox/sender rules only | Validation and match semantics for every supported object; no cross-tenant leakage | Features: lists and rule objects |
| Content/header/MIME/attachment and time-based policies | Open | Filename/type/body/header/time fixtures, MIME integrity and explicit timezone behavior | Features: rule system; guide: filter rules |
| Accept/block/quarantine, header changes, notifications, copies and attachment actions | Partial: Inbox/Junk/quarantine only | Each action's complete lifecycle; copies cannot escape recipient authorization | Guide: filter rules |
| SMTP/LMTP destinations, relay domains, transport maps and smarthosts | Partial: private local Gromox route only | Domain validation, loop prevention, TLS and retry behavior | Guide: mail proxy |
| TLS policy, message limits, rate controls and NDR policy | Partial: existing mail service configuration | Settings validation, actual enforcement and controlled failure paths | Guide: mail proxy |
| Before-queue and after-queue modes | Partial: staged after-queue handoff | Accurate SMTP response and custody semantics for both modes | Guide: mail proxy |
| Outbound DKIM signing and key management | Partial: migrated keys retained | Signature validation, DNS/key matching, rotation and outbound routing proof | Features/guide: DKIM |
| Spam, virus and attachment quarantines | Partial: one durable quarantine store | Distinct access policies, list/inspect/release/delete, retention and attachment handling | Guide: quarantine |
| Safe previews and review state | Partial: text-only preview | Sanitized optional HTML, no unsolicited remote fetch, seen/reviewed state and attachment controls | Guide: quarantine |
| User quarantine, digests and access links | Open | Mailbox-bound authentication, expiring/revocable links, schedules and alias/shared-mailbox mapping | Guide: quarantine |
| Personal welcome/block lists and admin assistance | Staged: exact sender rules and owner actions | Customer self-service, ownership changes, import/export and audit proof | Features: lists; guide: quarantine |
| Tracking from arrival through final delivery | Partial: latest 1,000 local records | Date-range search, pagination, SMTP/log correlation, queue hops and all delivery outcomes | Features: tracking; guide: tracking center |
| Queue inspection, aging, retry/flush, deletion and verification-cache controls | Partial: failed local-copy retry only | Correct queue identity, scoped actions, destructive-action confirmation and recovery | Guide: queue administration |
| Traffic/spam/virus/address/domain statistics and reports | Partial: local summary charts only | Inbound/outbound aggregates, selectable time windows, export, scheduled reports and consistent totals | Guide: administration/statistics |
| Admin, quarantine manager, auditor and helpdesk permissions | Partial: owner/client roles only | Read/write/content-access matrix and attempted privilege-escalation tests | Guide: user management |
| LDAP/AD users, groups and aliases; authentication integration | Open | TLS, sync failure behavior, identity mapping, access revocation and group matching | Features/guide: LDAP |
| Fetchmail | Open | Per-account scheduling, credentials, TLS, deduplication and remote-retention policy | Guide: Fetchmail |
| Services, health, logs, tasks and updates | Partial: general panel facilities | Mail-engine-specific status, update/rollback path and failure alerts | Guide: administration |
| Backup, restore, scheduling and remote backup integration | Partial: general panel backups | Restore rules, identities, secrets, statistics and accepted-message custody consistently | Guide: backup/restore |
| Clustering, synchronization and redundant operation | Open | Multi-node failure/rejoin tests; no lost/duplicated accepted messages or stale policies | Features: HA |
| API and automation coverage | Partial: local MassPanel endpoints | Versioned contracts, scoped credentials, audit and capability discovery | Guide: API |

The table is a coverage register, not a substitute for reviewing every option and
object of the selected engine version. Preserve access to supported backend
features until each equivalent MassPanel control is proven. A link to a separate
admin UI alone does not satisfy the requested integrated management experience.

## Additional owner requirements

These must be tested separately from PMG coverage; using PMG does not establish
them automatically.

| Requirement | Current state | Acceptance proof |
| --- | --- | --- |
| Independent mailbox learning | Open | Train identical content differently for two mailboxes; verify separate model state and decisions |
| Automatic learning from explicit Junk/Not Junk actions | Open | User moves train once; imports, scanner placement and retries never count as corrections |
| Native-looking Grommunio quarantine controls | Open | Existing mailbox session authorizes list/preview/release; browser-supplied mailbox identity cannot grant access |
| Owner-configured Ollama/open-model scoring | Staged, disabled | Mock contracts pass; owner-configured synthetic connection test precedes any customer-data use |
| Recoverable Junk versus strongly suspicious quarantine | Staged policy | Authentication alone cannot bypass content protection; mixed-recipient decisions remain independent |

## Implementation contract

MassPanel owns the management surface, tenant permissions, audit and integration
configuration. The gateway owns SMTP policy, filtering, its queue and quarantine.
Gromox owns mailbox delivery and storage. Grommunio identifies the logged-in
mailbox user. The training service accepts authenticated correction events with
stable event/message/recipient identifiers; it must not infer consent from the
mere presence of mail in Junk.

Gateway operations need a typed adapter for capabilities/version, configuration,
policy objects, quarantine, queue state, tracking, statistics, identities, health,
backup and clustering. Do not expose an unrestricted upstream API proxy. Validate
and authorize operations before forwarding them, keep credentials server-side,
validate TLS and record actor, recipient, action, backend result and correlation ID.

Represent the backend instance, node, queue/message identifier, recipient and
operation state separately. A browser retry cannot blindly repeat a release.
Unknown outcomes require reconciliation. Welcome-list updates and delivery are
distinct operations and must not be silently coupled.

Historical local records remain readable during engine migration. Do not convert
previous SMTP rejections into accepted quarantine. Do not run two independent
delivery workers against the same custody record or train a shared model from
mailbox-specific feedback. Rollback must preserve accepted mail and ongoing import
writes; restoring an old configuration must not roll back the live mail database.

## Architecture decision still open

The owner has been asked to choose between:

1. A separate PMG gateway integrated through its supported interfaces, with the
   mailbox-learning and Ollama additions developed alongside it. This is the
   recommended foundation for retaining PMG's full feature scope. PMG remains a
   separate upstream component with its own notices and licence.
2. The current Rspamd/Postfix foundation, implementing the entire register as
   native MassPanel features. This requires substantially more engineering and
   behavioral validation. Rspamd alone is not a replacement for PMG's management,
   policy, queue, quarantine, identity and cluster functions.

Do not silently switch foundations or install PMG packages into the Ubuntu
Grommunio VM while that choice is pending. There is no authorization to reduce
another VM's memory or stop an existing service to make room for a gateway.

## Delivery stages and handoff

1. Confirm the foundation and capacity; pin the engine/API baseline and expand
   this register into option-level acceptance cases for that release.
2. Build the adapter, mailbox identity mapping and management surfaces. Test with
   fixtures and isolated queues before enabling any route.
3. Complete quarantine/digest workflows, policy objects, tracking/queue/reporting,
   directory/roles, operational controls and backup recovery.
4. Prove mailbox learning and the Grommunio interface. Exercise retries, outages,
   simultaneous recipients, malware, abusive content and recovery.
5. Test cluster behavior on multiple nodes before claiming redundant operation.
   Multiple guests on one physical host do not prove host-failure tolerance.
6. Produce the completed evidence register for the owner. Public cutover remains
   a separately authorized action even after all tests pass.

Current handoff: foundation choice and gateway capacity need resolution before
engine-specific deployment. The existing staged subset and migration may continue
without changing public mail flow. No feature is marked complete by this document.
