import { useEffect, useState } from 'react';
import { api } from '../legacy.jsx';

const FILTERS = ['all', 'inbox', 'junk', 'quarantined', 'blocked', 'released', 'failed', 'delivery_uncertain'];
const AI = { enabled: false, provider: 'ollama', url: '', model: '', api_key: '', content_approved: false, allow_http: false, timeout: 20, max_characters: 12000, max_score: 5 };
const label = value => String(value || 'unknown').replaceAll('_', ' ');
const Mark = ({ value }) => <span className={`mail-action mail-action-${String(value).replaceAll('_', '-')}`}>{label(value)}</span>;

export default function MailSecurityPage({ session }) {
  const owner = session.role === 'admin';
  const [data, setData] = useState({ events: [], stats: {}, daily: [], pipeline: 'staged' });
  const [filter, setFilter] = useState('all'), [search, setSearch] = useState(''), [tab, setTab] = useState('tracking');
  const [selected, setSelected] = useState(null), [recipient, setRecipient] = useState(''), [preview, setPreview] = useState(null), [dangerous, setDangerous] = useState(false);
  const [rules, setRules] = useState({ rules: [], recipients: [] }), [rule, setRule] = useState({ recipient: '', sender: '', kind: 'welcome' });
  const [ai, setAi] = useState(AI), [routing, setRouting] = useState({ junk_score: 6, quarantine_score: 15, accepted_to_junk: false });
  const [busy, setBusy] = useState(''), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const send = (url, value, method = 'POST') => api(url, { method, csrf: session.csrf, body: JSON.stringify(value) });
  const query = `/mail-security/events?status=${encodeURIComponent(filter)}&search=${encodeURIComponent(search)}`;
  async function load() { setData(await api(query)); }
  async function loadSettings() {
    if (!owner) return;
    const [settings, list] = await Promise.all([api('/mail-security/settings'), api('/mail-security/rules')]);
    setAi({ ...AI, ...settings.ai, api_key: '' }); setRouting(settings.policy); setRules(list);
  }
  useEffect(() => {
    let current = true;
    const timer = setTimeout(() => api(query).then(result => { if (current) setData(result); }).catch(e => { if (current) setError(e.message); }), 180);
    return () => { current = false; clearTimeout(timer); };
  }, [query]);
  useEffect(() => { loadSettings().catch(e => setError(e.message)); }, [owner]);
  useEffect(() => {
    if (!selected) return;
    const previous = document.activeElement;
    const dialog = document.querySelector('.mail-inspector');
    const focusables = () => [...dialog.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),[tabindex="0"]')];
    focusables()[0]?.focus();
    function keydown(event) {
      if (event.key === 'Escape') setSelected(null);
      if (event.key !== 'Tab') return;
      const elements = focusables(), first = elements[0], last = elements.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', keydown);
    return () => { document.removeEventListener('keydown', keydown); previous?.focus(); };
  }, [selected]);
  async function run(name, fn) {
    setBusy(name); setError(''); setNotice('');
    try { await fn(); } catch (e) { setError(e.message); } finally { setBusy(''); }
  }
  function inspect(event) { setSelected(event); setRecipient(event.recipients[0] || ''); setPreview(null); setDangerous(false); }
  async function release() {
    if (!window.confirm(`Queue this message for one delivery to ${recipient}? This does not welcome-list its sender.`)) return;
    await send(`/mail-security/events/${selected.id}/release`, { recipient, confirm_dangerous: dangerous });
    setNotice('One recipient copy queued. Delivery status updates when the worker processes it.'); setSelected(null); await load();
  }
  async function saveRule(value) {
    await send('/mail-security/rules', value); await loadSettings();
    setNotice(value.kind === 'remove' ? 'Rule removed.' : 'Mailbox-specific rule saved. Existing quarantine is unchanged.');
  }
  async function saveSettings() {
    await send('/mail-security/settings', { ai, policy: routing }, 'PUT');
    await loadSettings(); await load(); setNotice('Settings saved. Mail routing activation is separate.');
  }
  const stats = data.stats || {}, maximum = Math.max(1, ...data.daily.map(x => x.count));
  const delivery = selected?.deliveries.find(x => x.recipient === recipient);

  return <section className="mail-security-page">
    <header className="mail-security-hero"><div><h1>Mail security</h1><p>Review mail decisions and act for a customer without changing another mailbox’s policy.</p></div><div className="security-engine"><span className={`engine-dot ${data.pipeline !== 'active' ? 'engine-staged' : ''}`} /><span><small>Rspamd routing</small><b>{data.pipeline === 'active' ? 'Enabled' : data.pipeline === 'configuration_error' ? 'Configuration needs attention' : 'Staged · not activated'}</b></span></div></header>
    {error && <div className="form-error" role="alert">{error}</div>}{notice && <div className="mail-notice" role="status">{notice}</div>}
    <div className="mail-metrics">{[['total', 'Visible messages'], ['junk', 'Routed to Junk'], ['quarantined', 'Held in quarantine'], ['blocked', 'Blocked / rejected'], ['released', 'Delivered after release'], ['pending', 'Queued / needs attention']].map(([key, title]) => <article key={key}><small>{title}</small><b>{stats[key] || 0}</b><span>{data.scope || 'your visible scope'}</span></article>)}</div>
    <section className="mail-visuals" aria-label="Mail decision charts"><article className="mail-chart"><h2>Routing decisions</h2><div className="mail-decision-bars">{[['inbox', 'Inbox'], ['junk', 'Junk'], ['quarantined', 'Quarantine'], ['blocked', 'Blocked']].map(([key, title]) => <div key={key}><span>{title}</span><meter aria-label={`${title} messages`} min="0" max={Math.max(1, stats.total || 0)} value={stats[key] || 0} /><b>{stats[key] || 0}</b></div>)}</div></article><article className="mail-chart"><h2>Recent volume</h2><div className="mail-volume">{data.daily.length ? data.daily.slice(-14).map(day => <div key={day.day} title={`${day.day}: ${day.count} messages`}><span>{day.count}</span><div style={{ height: `${Math.max(4, 80 * day.count / maximum)}px` }} /><small>{day.day.slice(5)}</small></div>) : <p>No mail events yet. Charts will populate when scanning is connected.</p>}</div></article></section>
    <p className="mail-window">{data.window}</p>
    <nav className="security-tabs mail-section-tabs" aria-label="Mail security sections">{[['tracking', 'Message tracking'], ...(owner ? [['rules', 'Welcome / block lists'], ['settings', 'Routing & AI']] : [])].map(([key, title]) => <button key={key} className={tab === key ? 'active' : ''} onClick={() => setTab(key)}>{title}</button>)}</nav>
    {tab === 'tracking' && <section className="tracking-center"><header><div><h2>{owner ? 'Customer mail tracking' : 'Your mail tracking'}</h2><p>Passing SPF, DKIM or DMARC does not automatically make content safe.</p></div><button className="secondary" disabled={!!busy} onClick={() => run('refresh', load)}>Refresh</button></header><div className="tracking-toolbar"><label>Decision <select aria-label="Filter decisions" value={filter} onChange={e => setFilter(e.target.value)}>{FILTERS.map(key => <option key={key} value={key}>{label(key)}</option>)}</select></label><label className="tracking-search"><input aria-label="Search mail" value={search} onChange={e => setSearch(e.target.value)} placeholder="Sender, recipient, subject or queue ID" /></label></div><div className="tracking-table-wrap"><table className="tracking-table"><thead><tr><th>Time</th><th>Envelope sender</th><th>Customer mailbox</th><th>Subject</th><th>Score</th><th>Decision / delivery</th><th /></tr></thead><tbody>{data.events.map(event => <tr key={event.id}><td>{event.created_at}<small>{event.queue_id}</small></td><td>{event.sender || '(Bounce sender)'}</td><td>{event.recipients.join(', ')}</td><td><b>{event.subject || '(No subject)'}</b></td><td>{Number(event.score).toFixed(1)}</td><td><Mark value={event.action} /><small>{event.deliveries.map(d => label(d.status)).join(', ')}</small></td><td><button className="secondary compact" onClick={() => inspect(event)}>Inspect</button></td></tr>)}</tbody></table>{!data.events.length && <div className="empty">No messages match this view.</div>}</div></section>}
    {tab === 'rules' && owner && <section className="tracking-center"><header><div><h2>Mailbox-specific sender rules</h2><p>A welcome rule requires the envelope sender to pass SPF and never bypasses malware. Rules do not train other users’ filters.</p></div></header><form className="mail-rule-form" onSubmit={e => { e.preventDefault(); run('rule', () => saveRule(rule)); }}><label>Customer mailbox<select required value={rule.recipient} onChange={e => setRule({ ...rule, recipient: e.target.value })}><option value="">Select mailbox</option>{rules.recipients.map(address => <option key={address}>{address}</option>)}</select></label><label>Exact envelope sender<input required type="email" value={rule.sender} onChange={e => setRule({ ...rule, sender: e.target.value })} /></label><label>Action<select value={rule.kind} onChange={e => setRule({ ...rule, kind: e.target.value })}><option value="welcome">Welcome list</option><option value="block">Block to quarantine</option></select></label><button className="primary" disabled={!!busy}>Save rule</button></form><div className="tracking-table-wrap"><table className="tracking-table"><thead><tr><th>Mailbox</th><th>Sender</th><th>Rule</th><th>Changed by</th><th /></tr></thead><tbody>{rules.rules.map(r => <tr key={`${r.recipient}:${r.sender}`}><td>{r.recipient}</td><td>{r.sender}</td><td><Mark value={r.kind} /></td><td>{r.created_by}<small>{r.created_at}</small></td><td><button className="secondary compact" disabled={!!busy} onClick={() => run('remove-rule', () => saveRule({ ...r, kind: 'remove' }))}>Remove</button></td></tr>)}</tbody></table>{!rules.rules.length && <div className="empty">No sender exceptions configured.</div>}</div></section>}
    {tab === 'settings' && owner && <form className="mail-settings" onSubmit={e => { e.preventDefault(); run('settings', saveSettings); }}><section className="mail-chart"><h2>Routing policy</h2><p>Lower scores go to Inbox, suspected spam to Junk, and high scores or malware to quarantine.</p><div className="mail-form-grid"><label>Junk score<input type="number" min="0" max="99" step="0.1" value={routing.junk_score} onChange={e => setRouting({ ...routing, junk_score: Number(e.target.value) })} /></label><label>Quarantine score<input type="number" min="0.1" max="100" step="0.1" value={routing.quarantine_score} onChange={e => setRouting({ ...routing, quarantine_score: Number(e.target.value) })} /></label></div><label className="mail-check"><input type="checkbox" checked={routing.accepted_to_junk} onChange={e => setRouting({ ...routing, accepted_to_junk: e.target.checked })} />Put otherwise accepted mail in Junk for manual review</label></section><section className="mail-chart"><h2>Optional AI scanning</h2><p>Connect your own open model. No server or model is preselected, and no customer content is sent while disabled.</p><div className="mail-form-grid">
      <label>API format<select value={ai.provider} onChange={e => setAi({ ...ai, provider: e.target.value, enabled: false, content_approved: false })}><option value="ollama">Ollama</option><option value="openai-compatible">OpenAI-compatible</option></select></label>
      <label>Server base URL<input type="url" value={ai.url} placeholder={ai.provider === 'ollama' ? 'https://your-ollama-server' : 'https://your-model-server/v1'} onChange={e => setAi({ ...ai, url: e.target.value, enabled: false, content_approved: false })} /></label>
      <label>Installed model name<input value={ai.model} placeholder="Enter your installed model name" onChange={e => setAi({ ...ai, model: e.target.value })} /></label>
      <label>Optional API key<input type="password" autoComplete="new-password" value={ai.api_key} placeholder={ai.has_key ? 'A key is stored; leave blank to keep it' : 'No key configured'} onChange={e => setAi({ ...ai, api_key: e.target.value })} /></label>
      <label>Timeout (seconds)<input type="number" min="2" max="60" value={ai.timeout} onChange={e => setAi({ ...ai, timeout: Number(e.target.value) })} /></label>
      <label>Maximum AI score contribution<input type="number" min="0" max="6" step="0.5" value={ai.max_score} onChange={e => setAi({ ...ai, max_score: Number(e.target.value) })} /></label>
      </div><label className="mail-check"><input type="checkbox" checked={ai.allow_http} onChange={e => setAi({ ...ai, allow_http: e.target.checked })} />Allow plain HTTP on an owner-trusted private connection</label><label className="mail-check"><input type="checkbox" checked={ai.content_approved} onChange={e => setAi({ ...ai, content_approved: e.target.checked, enabled: e.target.checked && ai.enabled })} />I approve sending email subject, sender and up to {Number(ai.max_characters).toLocaleString()} characters of message text to this server. Attachments are excluded.</label><label className="mail-check"><input type="checkbox" checked={ai.enabled} disabled={!ai.content_approved || !ai.url || !ai.model} onChange={e => setAi({ ...ai, enabled: e.target.checked })} />Enable AI scanning</label><p className="field-help">AI adds a bounded spam signal. It cannot override malware or remove protective scores. Timeouts keep the normal Rspamd result.</p><div className="inspector-actions"><button className="primary" disabled={!!busy}>Save settings</button><button type="button" className="secondary" disabled={!!busy || !ai.url || !ai.model} onClick={() => run('ai-test', async () => { await saveSettings(); const result = await send('/mail-security/ai/test', {}); setNotice(`Synthetic test: ${result.status}${result.reason ? ` — ${result.reason}` : ''}`); })}>Save & test with synthetic mail</button></div></section></form>}
    {selected && <div className="drawer-backdrop" onMouseDown={e => e.target === e.currentTarget && setSelected(null)}><aside className="drawer mail-inspector" role="dialog" aria-modal="true" aria-label="Message inspection"><header><h2>Message inspection</h2><button onClick={() => setSelected(null)} aria-label="Close inspection">×</button></header><div className="drawer-content"><Mark value={selected.action} /><h3>{selected.subject || '(No subject)'}</h3><p>{selected.details.reason}</p><dl className="message-facts"><div><dt>Envelope sender</dt><dd>{selected.sender || '(Bounce sender)'}</dd></div><div><dt>Recipient</dt><dd><select aria-label="Message recipient" value={recipient} onChange={e => setRecipient(e.target.value)}>{selected.recipients.map(r => <option key={r}>{r}</option>)}</select></dd></div><div><dt>Delivery status</dt><dd>{label(delivery?.status)}</dd></div><div><dt>Score</dt><dd>{Number(selected.score).toFixed(2)}</dd></div><div><dt>Source IP</dt><dd>{selected.source_ip || 'Unknown'}</dd></div><div><dt>AI verdict</dt><dd>{label(selected.details.ai?.status || 'not scanned')}{selected.details.ai?.reason && <p>{selected.details.ai.reason}</p>}</dd></div></dl><div className="mail-auth-checks">{Object.entries(selected.details.authentication || {}).map(([name, result]) => <span key={name}><b>{name.toUpperCase()}</b><Mark value={result} /></span>)}</div><section className="symbol-section"><h4>Scanner signals</h4><div>{selected.symbols.map((s, i) => <span key={`${s.name}-${i}`}><b>{s.name}</b><small>{Number(s.score || 0).toFixed(1)}</small></span>)}</div></section><button className="secondary" disabled={!!busy} onClick={() => run('preview', async () => { const value = await api(`/mail-security/events/${selected.id}/preview`); setPreview(value.text); })}>Preview text without loading attachments</button>{preview !== null && <pre className="mail-safe-preview">{preview || 'No text body available.'}</pre>}
      {owner && <><div className="inspector-actions"><button className="secondary" disabled={!!busy || !selected.sender} onClick={() => run('welcome', () => saveRule({ recipient, sender: selected.sender, kind: 'welcome' }))}>Welcome sender for this mailbox</button><button className="secondary" disabled={!!busy || !selected.sender} onClick={() => run('block', () => saveRule({ recipient, sender: selected.sender, kind: 'block' }))}>Block for this mailbox</button></div>{selected.details.dangerous && <label className="mail-check"><input type="checkbox" checked={dangerous} onChange={e => setDangerous(e.target.checked)} />I understand this message has a malware verdict and still want it delivered.</label>}{delivery?.status === 'quarantined' && <button className="primary" disabled={!!busy || (selected.details.dangerous && !dangerous)} onClick={() => run('release', release)}>Deliver once to this mailbox</button>}{delivery?.status === 'failed' && <button className="secondary" disabled={!!busy} onClick={() => run('retry', async () => { await send(`/mail-security/events/${selected.id}/retry`, { recipient }); setSelected(null); await load(); setNotice('Confirmed failed delivery queued for retry.'); })}>Retry failed delivery</button>}{['delivering', 'delivery_uncertain'].includes(delivery?.status) && <p className="form-error">Check the local delivery log before retrying: the server may already have accepted this copy. Automatic redelivery is held.</p>}</>}
    </div></aside></div>}
  </section>;
}
