import React, { useEffect, useState } from 'react';
import { api } from '../legacy.jsx';

const EMPTY_FORM = { name: '', domain: '', schedule: '0 2 * * *', command: '' };

function ResourceCard({ label, value }) {
  const amount = Math.max(0, Math.min(100, Number(value || 0)));
  return <article className="tool-stat"><small>{label}</small><strong>{amount.toFixed(1)}%</strong><span><i style={{ width: `${amount}%` }} /></span></article>;
}

function PhpDomainCard({ domain, session, onSaved, onLogs }) {
  const [form, setForm] = useState({ enabled: !!domain.php_enabled, memory_limit: domain.php_memory_limit, upload_limit: domain.php_upload_limit, execution_time: domain.php_execution_time });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const save = async () => {
    setBusy(true); setMessage('');
    try {
      await api(`/tools/php/${encodeURIComponent(domain.domain)}`, { method: 'PUT', csrf: session.csrf, body: JSON.stringify(form) });
      setMessage('PHP settings applied.'); onSaved();
    } catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  };
  return <article className="php-domain-card">
    <header><div><b>{domain.domain}</b><small>Owner: {domain.owner}</small></div><label className="mini-switch"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} /> PHP-FPM</label></header>
    <div className="php-limit-grid">
      <label>Memory MB<input type="number" min="32" max="2048" value={form.memory_limit} onChange={(event) => setForm((current) => ({ ...current, memory_limit: event.target.value }))} /></label>
      <label>Upload MB<input type="number" min="2" max="2048" value={form.upload_limit} onChange={(event) => setForm((current) => ({ ...current, upload_limit: event.target.value }))} /></label>
      <label>Timeout sec<input type="number" min="10" max="3600" value={form.execution_time} onChange={(event) => setForm((current) => ({ ...current, execution_time: event.target.value }))} /></label>
    </div>
    {message && <small className="tool-message">{message}</small>}
    <footer><button className="secondary" onClick={() => onLogs(domain.domain)}>View logs</button><button className="primary" disabled={busy} onClick={save}>{busy ? 'Applying…' : 'Apply PHP settings'}</button></footer>
  </article>;
}

export default function HostingToolsPage({ session }) {
  const [overview, setOverview] = useState({ domains: [], services: [], resources: {} });
  const [tasks, setTasks] = useState([]);
  const [packages, setPackages] = useState([]);
  const [catalog, setCatalog] = useState({});
  const [packageForm, setPackageForm] = useState({ name: '', domain_limit: 10, disk_mb: 10240, bandwidth_mb: 102400, database_limit: 10, mailbox_limit: 25, cron_limit: 10, backup_limit: 5, allow_php: true, allow_ssh: false });
  const [form, setForm] = useState(EMPTY_FORM);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [runOutput, setRunOutput] = useState('');
  const [logs, setLogs] = useState(null);

  const load = async () => {
    setError('');
    try {
      const cronAllowed = session.role === 'admin' || session.features?.cron !== false;
      const [nextOverview, nextTasks, nextPackages] = await Promise.all([api('/tools/overview'), cronAllowed ? api('/cron') : Promise.resolve({ tasks:[] }), api('/packages')]);
      setOverview(nextOverview || { domains: [], services: [], resources: {} });
      setTasks(Array.isArray(nextTasks?.tasks) ? nextTasks.tasks : []);
      setPackages(Array.isArray(nextPackages?.packages) ? nextPackages.packages : []);
      setCatalog(nextPackages?.catalog || {});
      if (!form.domain && nextOverview?.domains?.[0]) setForm((current) => ({ ...current, domain: nextOverview.domains[0].domain }));
    } catch (nextError) { setError(nextError.message); }
  };
  useEffect(() => { load(); }, []);

  const createTask = async (event) => {
    event.preventDefault(); setBusy('create'); setError('');
    try {
      await api('/cron', { method: 'POST', csrf: session.csrf, body: JSON.stringify(form) });
      setForm((current) => ({ ...EMPTY_FORM, domain: current.domain })); await load();
    } catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const taskAction = async (task, action) => {
    setBusy(`${action}-${task.id}`); setError(''); setRunOutput('');
    try {
      const result = await api(`/cron/${task.id}${action === 'delete' ? '' : `/${action}`}`, { method: action === 'delete' ? 'DELETE' : 'POST', csrf: session.csrf, body: action === 'delete' ? undefined : '{}' });
      if (action === 'run') setRunOutput(result.output || 'Task completed without output.');
      await load();
    } catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const openLogs = async (domain) => {
    setBusy('logs'); setError('');
    try { setLogs(await api(`/tools/logs/${encodeURIComponent(domain)}?lines=120`)); }
    catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const createPackage = async (event) => {
    event.preventDefault(); setBusy('package'); setError('');
    try { await api('/packages', { method:'POST', csrf:session.csrf, body:JSON.stringify(packageForm) }); setPackageForm((current) => ({ ...current, name:'' })); await load(); }
    catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const deletePackage = async (item) => {
    if (!window.confirm(`Delete hosting package ${item.name}?`)) return;
    setBusy(`package-${item.id}`); setError('');
    try { await api(`/packages/${item.id}`, { method:'DELETE', csrf:session.csrf }); await load(); }
    catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const togglePackageFeature = (packageId, key) => setPackages((current) => current.map((item) => item.id === packageId ? ({ ...item, features:{ ...item.features, [key]:!item.features?.[key] } }) : item));
  const savePackageFeatures = async (item) => {
    setBusy(`features-${item.id}`); setError('');
    try { await api(`/packages/${item.id}/features`, { method:'PUT', csrf:session.csrf, body:JSON.stringify({ features:item.features }) }); await load(); }
    catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };

  return <>
    <header className="page-header"><div><h1>Hosting Tools</h1><p>Scheduled tasks, PHP controls, website logs and server health.</p></div><button className="secondary" onClick={load}>Refresh status</button></header>
    <div className="tools-canvas">
      {error && <div className="form-error">{error}</div>}
      <section className="tools-resource-grid"><ResourceCard label="CPU" value={overview.resources?.cpu_percent} /><ResourceCard label="Memory" value={overview.resources?.memory_percent} /><ResourceCard label="System disk" value={overview.resources?.disk_percent} /></section>
      <section className="tools-panel"><header><div><h2>Service health</h2><p>Live state of the core website, database and Grommunio services.</p></div></header><div className="service-chip-grid">{overview.services.map((service) => <span key={service.name} className={service.state === 'active' ? 'is-active' : 'is-warning'}><i />{service.name}<b>{service.state}</b></span>)}</div></section>
      {session.role === 'admin' && <section className="tools-panel"><header><div><h2>Hosting packages</h2><p>Reusable limits applied to customer accounts. Package limits also govern tools such as cron and PHP.</p></div></header>
        <form className="package-form" onSubmit={createPackage}><label>Package name<input value={packageForm.name} maxLength="64" onChange={(event) => setPackageForm((current) => ({ ...current, name:event.target.value }))} required /></label>{[['domain_limit','Domains'],['disk_mb','Disk MB'],['bandwidth_mb','Bandwidth MB'],['database_limit','Databases'],['mailbox_limit','Mailboxes'],['cron_limit','Cron jobs'],['backup_limit','Backups']].map(([key,label]) => <label key={key}>{label}<input type="number" min="0" value={packageForm[key]} onChange={(event) => setPackageForm((current) => ({ ...current, [key]:event.target.value }))} required /></label>)}<label className="mini-switch"><input type="checkbox" checked={packageForm.allow_php} onChange={(event) => setPackageForm((current) => ({ ...current, allow_php:event.target.checked }))} /> PHP</label><label className="mini-switch"><input type="checkbox" checked={packageForm.allow_ssh} onChange={(event) => setPackageForm((current) => ({ ...current, allow_ssh:event.target.checked }))} /> SSH</label><button className="primary" disabled={busy === 'package'}>{busy === 'package' ? 'Creating…' : 'Create package'}</button></form>
        <div className="package-list">{packages.map((item) => <article key={item.id}><span><b>{item.name}</b><small>{item.disk_mb} MB disk · {item.bandwidth_mb ? `${item.bandwidth_mb} MB bandwidth` : 'Unlimited bandwidth'}</small></span><dl><div><dt>Domains</dt><dd>{item.domain_limit}</dd></div><div><dt>Databases</dt><dd>{item.database_limit}</dd></div><div><dt>Mailboxes</dt><dd>{item.mailbox_limit}</dd></div><div><dt>Cron</dt><dd>{item.cron_limit}</dd></div></dl><div className="package-features">{Object.entries(catalog).map(([key,label]) => <label className="mini-switch" key={key}><input type="checkbox" checked={item.features?.[key] !== false} onChange={() => togglePackageFeature(item.id,key)} /> {label}</label>)}</div><div><button className="secondary" disabled={!!busy} onClick={() => savePackageFeatures(item)}>{busy === `features-${item.id}` ? 'Saving…' : 'Save access'}</button><button className="secondary danger" disabled={!!busy} onClick={() => deletePackage(item)}>Delete</button></div></article>)}{!packages.length && <div className="empty">No hosting packages yet.</div>}</div>
      </section>}
      {(session.role === 'admin' || session.features?.cron !== false) && <section className="tools-panel"><header><div><h2>Cron jobs</h2><p>Commands run as the selected website owner and write output to ~/logs/cron.log.</p></div></header>
        <form className="cron-form" onSubmit={createTask}>
          <label>Name<input value={form.name} maxLength="80" onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} required /></label>
          <label>Website<select value={form.domain} onChange={(event) => setForm((current) => ({ ...current, domain: event.target.value }))} required><option value="">Choose website</option>{overview.domains.map((domain) => <option key={domain.domain} value={domain.domain}>{domain.domain}</option>)}</select></label>
          <label>Schedule<input className="mono" value={form.schedule} onChange={(event) => setForm((current) => ({ ...current, schedule: event.target.value }))} required /></label>
          <label className="cron-command">Command<input className="mono" value={form.command} onChange={(event) => setForm((current) => ({ ...current, command: event.target.value }))} required /></label>
          <button className="primary" disabled={busy === 'create' || !overview.domains.length}>{busy === 'create' ? 'Adding…' : 'Add cron job'}</button>
        </form>
        <div className="task-list">{tasks.map((task) => <article key={task.id}><span><b>{task.name}</b><small>{task.owner}{task.domain ? ` · ${task.domain}` : ''}</small></span><code>{task.schedule}</code><code>{task.command}</code><strong className={task.enabled ? 'status-pass' : 'status-warn'}>{task.enabled ? 'Enabled' : 'Paused'}</strong><div><button className="secondary" disabled={!!busy} onClick={() => taskAction(task, 'run')}>Run now</button><button className="secondary" disabled={!!busy} onClick={() => taskAction(task, 'toggle')}>{task.enabled ? 'Pause' : 'Enable'}</button><button className="secondary danger" disabled={!!busy} onClick={() => taskAction(task, 'delete')}>Delete</button></div></article>)}{!tasks.length && <div className="empty">No scheduled tasks yet.</div>}</div>
        {runOutput && <pre className="tool-output">{runOutput}</pre>}
      </section>}
      {(session.role === 'admin' || session.features?.php !== false || session.features?.websites !== false) && <section className="tools-panel"><header><div><h2>PHP and website logs</h2><p>Manage PHP where included and inspect Nginx traffic or errors.</p></div></header><div className="php-domain-grid">{overview.domains.map((domain) => session.role === 'admin' || session.features?.php !== false ? <PhpDomainCard key={domain.domain} domain={domain} session={session} onSaved={load} onLogs={openLogs} /> : <article className="php-domain-card" key={domain.domain}><header><div><b>{domain.domain}</b><small>Website logs</small></div></header><footer><button className="secondary" onClick={() => openLogs(domain.domain)}>View logs</button></footer></article>)}{!overview.domains.length && <div className="empty">Create a website to inspect logs.</div>}</div></section>}
      {logs && <section className="tools-panel log-viewer"><header><div><h2>{logs.domain} logs</h2><p>{logs.metrics?.requests || 0} recent requests · {logs.metrics?.bytes || 0} bytes transferred</p></div><button className="secondary" onClick={() => setLogs(null)}>Close</button></header><h3>Error log</h3><pre>{logs.errors?.join('\n') || 'No recent errors.'}</pre><h3>Access log</h3><pre>{logs.access?.join('\n') || 'No recent requests.'}</pre></section>}
    </div>
  </>;
}
