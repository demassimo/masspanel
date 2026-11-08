# Mail security and owner-configured AI

The owner now requires full PMG mail-feature coverage. The current implementation
is a staged subset. See [the coverage register](PMG_FEATURE_COVERAGE.md) for the
required capabilities, gaps, acceptance evidence and pending architecture choice.

MassPanel prepares Rspamd message tracking, recipient-specific quarantine, sender
rules and an optional Ollama/OpenAI-compatible connector. Installing or updating
these files **does not activate mail routing**. The delivery worker defaults to
disabled. Do not change public DNS, listeners or routing during migration staging.

## Routing and review

The initial policy is Inbox below 6, Junk from 6, quarantine from 15. A passing
SPF/DKIM/DMARC result alone never bypasses content scoring. An optional review-all
setting sends otherwise accepted mail to Junk. Malware, mailbox block rules and
explicit scanner rejection verdicts are held in quarantine. Temporary scanner
failures keep the original message in Postfix for retry.

The administrator can inspect a text-only preview, choose a customer mailbox,
welcome-list an exact envelope sender, block it, or deliver one held copy. A
welcome rule requires SPF for that envelope sender and cannot bypass malware or
an explicit scanner rejection. It is scoped to one recipient. A one-time release
does not create a sender exception and needs a separate confirmation for malware.
Preview never loads attachments, HTML scripts or remote images.

Charts and search cover the latest 1,000 events; the table shows at most 250
matching events. Customer views are restricted to owned mail domains; settings,
sender rules and release/retry actions require administrator access and CSRF.
Settings, previews, rules, release requests and retries are audited. Final local
delivery status is recorded separately from the original scan decision.

## Queue acceptance and duplicate protection

The Postfix pipe sends exactly one trusted envelope recipient to the loopback
MassPanel endpoint. Raw MIME is fsynced in a private spool before the SQLite
transaction commits with full synchronization. Only then does the pipe return
success. API errors, timeouts or capacity limits return temporary failure, leaving
Postfix responsible for the original. A stable queue ID, recipient, envelope
sender and message digest make repeated handoffs idempotent.

The delivery worker sends only to loopback Gromox, never to an arbitrary remote
SMTP server. It strips untrusted `X-MassPanel-*` headers and sets the Junk marker
itself. MIME bodies are retained without re-encoding. Repeated release clicks
cannot enqueue another copy. A lost connection during DATA is held as
`delivery_uncertain`; a crash after claiming a copy leaves `delivering`. Neither
is automatically retried because delivery might already have succeeded. Reconcile
the Gromox delivery log/store before an operator resolves these states. Confirmed
refusals appear as `failed` and can be retried in the inspector. A lost QUIT after
an explicit DATA acceptance does not invalidate that acceptance.

This is not a claim of exactly-once SMTP delivery: an acknowledgement can be
lost. Explicitly preserving uncertainty avoids silent duplicate delivery.

The old metadata exporter was not a durable SMTP quarantine: a copy of an SMTP
rejection is tracking evidence, not accepted mail. Historical copies cannot be
released by this API. The old privileged port-10026 release helper was removed.

## Optional AI

In **Mail security → Routing & AI**, the owner chooses Ollama or an
OpenAI-compatible API, enters their server base URL and installed model name,
and optionally stores an API key. No endpoint, model, key or external service is
provided. Scanning starts disabled. Sending customer content additionally requires
the owner's content approval. Plain HTTP needs explicit approval for a trusted
private connection; HTTPS validates the certificate normally.

Ollama uses `/api/chat`, a JSON schema and non-streaming responses. A compatible
server uses `/chat/completions` appended to its base URL (usually ending `/v1`).
The synthetic connection test contains a fixed example only. It never samples a
customer mailbox or silently enables scanning. No model is downloaded or started.

Only subject, displayed sender and bounded message text are sent; attachment
payloads are excluded. Email is treated as untrusted data, with no tool execution
or link retrieval. Model output is validated as a finite probability and a short
reason. AI adds at most the configured score (default 5, maximum 6); a ham verdict
cannot subtract Rspamd protection. Timeouts, malformed replies and provider errors
leave the normal result intact. Redirects and environment proxies are disabled.
Provider error text is never returned because it can contain message data/secrets.

API keys are encrypted using a key derived from the installation secret, omitted
from responses and cleared when changing the destination unless replaced. Keep
the installation secret and state database together in protected backups.

## Preparing activation

`deploy/install-mail-security.sh` installs private directories, a secret, a
disabled root-owned runtime configuration, systemd units and configuration
examples. It changes no Postfix/Rspamd/Gromox routing, starts no new timer and
does not alter an existing runtime activation flag.

Before a separately authorized activation:

1. Back up the mail configs, MassPanel database, installation secret and spool.
2. Review `mail-security-postfix.example`, including the per-transport recipient
   limit of one and any transport-map override. Preserve recipient verification,
   anti-relay restrictions, outgoing DKIM and submission authentication.
3. Configure Rspamd, Redis and antivirus. The normal scanner must listen only on
   loopback port 11333. Verify timeout/error handling. For accepted quarantine,
   do not additionally reject the same content in a pre-queue milter. SMTP policy
   rejections that happen before acceptance remain rejections.
4. Configure Gromox `lda_junk_rules = X-MassPanel-Spam=Yes` and verify the loopback
   delivery port (default 10024) with isolated synthetic Inbox/Junk/quarantine
   fixtures before changing any production route.
5. Validate `postfix check`, `rspamadm configtest`, per-recipient delivery and
   sender authentication. Review/remove only obsolete MassPanel metadata-copy
   quarantine and port-10026 release configuration after backing it up.
6. When authorized, enable the root-owned
   `/etc/masspanel/mail-security-delivery.json` flag and the
   `masspanel-mail-delivery.timer`, then route new local mail through the prepared
   transport. Stage restrictions and public DNS changes remain separate decisions.

The UI's Enabled/Staged badge reports the root-owned activation flag; it is not a
service health probe. Monitor Postfix queues, worker journal, failed/uncertain
states and spool free space. Delivered message bodies expire after seven days
(`delivered_body_days`, 1–365, in the runtime file); event metadata remains.
Quarantined, queued, failed and uncertain copies never expire automatically.
The worker and expiry process are both inactive while staged.

## Mailbox learning and Grommunio

The classifier example sets Redis `per_user=true` and disables global autolearn.
Every final-delivery scan must have one recipient with a matching `Deliver-To`.
Do not enable a shared `grommunio-spam-run` job: one customer's training must not
affect another. Sender rules are already isolated per mailbox.

Grommunio's native Junk folder remains the customer interface for delivered spam.
Automatic learning from user-initiated folder moves and an embedded Grommunio
gateway-quarantine view are **not implemented by this patch**. Do not treat imported
messages or automatic Junk delivery as user feedback. Those integrations and
real per-mailbox Bayes isolation proofs remain activation prerequisites when
automatic learning is required.

## Verification and references

Run `python -m unittest discover -s qa -q` on the supported Ubuntu environment,
then `npm --prefix frontend run build`. Mail tests use synthetic data and stub
model/SMTP transports. Browser fixtures check owner defaults, plaintext preview,
single-recipient release, search and desktop/mobile rendering. Real Gromox delivery
and classifier isolation require the separate staged integration checks above.

Protocol references: [Ollama chat API](https://docs.ollama.com/api/chat),
[Rspamd scanner protocol](https://docs.rspamd.com/developers/protocol/),
[Rspamd per-user statistics](https://docs.rspamd.com/configuration/statistic/),
[Postfix pipe transport](https://www.postfix.org/pipe.8.html).
