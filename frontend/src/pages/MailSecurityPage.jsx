import { useEffect, useMemo, useState } from 'react';
import { api } from '../legacy.jsx';

const FILTERS = [['all','All mail'],['quarantined','Quarantine'],['reject','Rejected'],['released','Released']];

function ActionMark({ action, status }) {
  const value = status === 'quarantined' ? 'Quarantined' : status === 'released' ? 'Released' : action || 'No action';
  return <span className={`mail-action mail-action-${value.toLowerCase().replace(/\s+/g,'-')}`}>{value}</span>;
}

export default function MailSecurityPage({ session }) {
  const [data,setData] = useState({events:[],stats:{},scope:''});
  const [filter,setFilter] = useState('all');
  const [search,setSearch] = useState('');
  const [selected,setSelected] = useState(null);
  const [busy,setBusy] = useState('');
  const [error,setError] = useState('');

  async function load() {
    try { setData(await api(`/mail-security/events?status=${encodeURIComponent(filter)}&search=${encodeURIComponent(search)}`)); setError(''); }
    catch (reason) { setError(reason.message); }
  }
  useEffect(() => { const timer=setTimeout(load,180); return () => clearTimeout(timer); }, [filter,search]);
  const stats = useMemo(() => data.stats || {}, [data]);

  async function act(event, action) {
    if (action === 'release' && !window.confirm(`Release “${event.subject || 'No subject'}” to ${event.recipients.join(', ')}?`)) return;
    if (action === 'delete' && !window.confirm('Permanently remove this quarantined message?')) return;
    setBusy(`${action}-${event.id}`); setError('');
    try {
      await api(`/mail-security/events/${event.id}${action === 'release' ? '/release' : ''}`, {method:action === 'release' ? 'POST' : 'DELETE',csrf:session.csrf,body:action === 'release' ? '{}' : undefined});
      setSelected(null); await load();
    } catch (reason) { setError(reason.message); }
    finally { setBusy(''); }
  }

  return <section className="mail-security-page">
    <header className="mail-security-hero">
      <div><h1>Mail security</h1><p>Track delivery decisions, inspect spam scores and safely release quarantined mail.</p></div>
      <div className="security-engine"><span className="engine-dot" /><span><small>Filtering engine</small><b>Rspamd · active</b></span></div>
    </header>
    {error && <div className="form-error">{error}</div>}
    <div className="mail-metrics">
      <article><small>Visible messages</small><b>{stats.total || 0}</b><span>{data.scope || (session.role === 'admin' ? 'all tenants' : 'your domains')}</span></article>
      <article><small>In quarantine</small><b>{stats.quarantined || 0}</b><span>ready for review</span></article>
      <article><small>Rejected</small><b>{stats.rejected || 0}</b><span>blocked by policy</span></article>
      <article><small>Released</small><b>{stats.released || 0}</b><span>restored by a user</span></article>
    </div>
    <section className="tracking-center">
      <header><div><h2>{session.role === 'admin' ? 'Global tracking center' : 'Your tracking center'}</h2><p>{session.role === 'admin' ? 'Messages across every hosted customer and domain.' : 'Messages addressed to mail domains owned by your account.'}</p></div><button className="secondary" onClick={load}>Refresh</button></header>
      <div className="tracking-toolbar">
        <div className="security-tabs">{FILTERS.map(([key,label]) => <button key={key} className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>{label}</button>)}</div>
        <label className="tracking-search"><span>⌕</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Sender, recipient, subject or queue ID" /></label>
      </div>
      <div className="tracking-table-wrap"><table className="tracking-table"><thead><tr><th>Time</th><th>From</th><th>To</th><th>Subject</th><th>Score</th><th>Decision</th><th /></tr></thead><tbody>
        {data.events.map((event) => <tr key={event.id}><td><time>{event.created_at.replace(' UTC','')}</time><small>{event.direction}</small></td><td>{event.sender || 'Envelope sender unavailable'}</td><td><b>{event.recipients[0] || 'Unknown'}</b>{event.recipients.length > 1 && <small>+{event.recipients.length-1} recipient(s)</small>}</td><td><b>{event.subject || '(No subject)'}</b><small>{event.queue_id || event.id}</small></td><td><strong className={event.score >= 6 ? 'score-high' : event.score >= 3 ? 'score-mid' : 'score-low'}>{Number(event.score).toFixed(1)}</strong></td><td><ActionMark action={event.action} status={event.status} /></td><td><button className="secondary compact" onClick={() => setSelected(event)}>Inspect</button></td></tr>)}
      </tbody></table>{!data.events.length && <div className="empty">No messages match this view yet. New mail will appear here automatically.</div>}</div>
    </section>
    {selected && <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && setSelected(null)}><aside className="drawer mail-inspector"><header><h2>Message inspection</h2><button onClick={() => setSelected(null)} aria-label="Close">×</button></header><div className="drawer-content">
      <ActionMark action={selected.action} status={selected.status} /><h3>{selected.subject || '(No subject)'}</h3>
      <dl className="message-facts"><div><dt>Envelope sender</dt><dd>{selected.sender || 'Unavailable'}</dd></div><div><dt>Recipients</dt><dd>{selected.recipients.join(', ') || 'Unavailable'}</dd></div><div><dt>Spam score</dt><dd>{Number(selected.score).toFixed(2)}</dd></div><div><dt>Source IP</dt><dd>{selected.source_ip || 'Local/unknown'}</dd></div><div><dt>Queue ID</dt><dd>{selected.queue_id || 'Unavailable'}</dd></div><div><dt>Size</dt><dd>{selected.size_bytes ? `${Math.ceil(selected.size_bytes/1024)} KB` : 'Metadata only'}</dd></div></dl>
      <section className="symbol-section"><h4>Why Rspamd made this decision</h4><div>{selected.symbols.length ? selected.symbols.slice(0,30).map((symbol,index) => <span key={`${symbol.name || symbol.symbol}-${index}`}><b>{symbol.name || symbol.symbol || 'Rule'}</b><small>{Number(symbol.score || 0).toFixed(1)}</small></span>) : <p>No symbol details were supplied for this message.</p>}</div></section>
      {selected.status === 'quarantined' && <div className="inspector-actions"><button className="primary" disabled={!!busy} onClick={() => act(selected,'release')}>{busy === `release-${selected.id}` ? 'Releasing…' : 'Release message'}</button><button className="secondary danger" disabled={!!busy} onClick={() => act(selected,'delete')}>Delete permanently</button></div>}
    </div></aside></div>}
  </section>;
}
