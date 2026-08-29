import React, { useEffect, useState } from 'react';
import { api } from '../legacy.jsx';

const EMPTY_FORM = { name: '', domain: '', schedule: '0 2 * * *', command: '' };
const EMPTY_BACKUP_SCHEDULE = { domain: '', frequency: 'daily', hour: 2, minute: 0, weekday: 0, monthday: 1, retention: 3, destination_type: 'local', remote_path: 'MassPanel', destination_config: {} };
const WEEKDAYS = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];

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

function BackupDestinationFields({ form, setForm }) {
  const updateConfig = (key, value) => setForm((current) => ({ ...current, destination_config:{ ...current.destination_config, [key]:value } }));
  return <>
    <label>Destination<select value={form.destination_type} onChange={(event) => setForm((current) => ({ ...current, destination_type:event.target.value, destination_config:{} }))}><option value="local">This server</option><option value="google_drive">Google Drive</option><option value="sftp">SFTP</option><option value="ftp">FTP</option></select></label>
    {form.destination_type !== 'local' && <label>Remote folder<input value={form.remote_path} onChange={(event) => setForm((current) => ({ ...current, remote_path:event.target.value }))} placeholder="MassPanel" /></label>}
    {(form.destination_type === 'ftp' || form.destination_type === 'sftp') && <><label>Server<input value={form.destination_config.host || ''} onChange={(event) => updateConfig('host',event.target.value)} placeholder="backup.example.com" required /></label><label>Port<input type="number" min="1" max="65535" value={form.destination_config.port || (form.destination_type === 'ftp' ? 21 : 22)} onChange={(event) => updateConfig('port',Number(event.target.value))} required /></label><label>Username<input value={form.destination_config.username || ''} onChange={(event) => updateConfig('username',event.target.value)} required /></label><label>Password<input type="password" value={form.destination_config.password || ''} onChange={(event) => updateConfig('password',event.target.value)} autoComplete="new-password" required /></label></>}
    {form.destination_type === 'google_drive' && <><label>Google client ID<input value={form.destination_config.client_id || ''} onChange={(event) => updateConfig('client_id',event.target.value)} /></label><label>Google client secret<input type="password" value={form.destination_config.client_secret || ''} onChange={(event) => updateConfig('client_secret',event.target.value)} autoComplete="new-password" /></label><label className="backup-token-field">OAuth token JSON<textarea value={form.destination_config.token || ''} onChange={(event) => updateConfig('token',event.target.value)} placeholder={'{"access_token":"…","token_type":"Bearer","refresh_token":"…","expiry":"…"}'} required /></label></>}
  </>;
}

export default function HostingToolsPage({ session }) {
  const [overview, setOverview] = useState({ domains: [], services: [], resources: {} });
  const [tasks, setTasks] = useState([]);
  const [services, setServices] = useState([]);
  const [backupSchedules, setBackupSchedules] = useState([]);
  const [backupForm, setBackupForm] = useState(EMPTY_BACKUP_SCHEDULE);
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
      const [nextOverview, nextTasks, nextPackages, nextServices, nextBackupSchedules] = await Promise.all([
        api('/tools/overview'),
        cronAllowed ? api('/cron') : Promise.resolve({ tasks:[] }),
        api('/packages'),
        session.role === 'admin' ? api('/tools/services') : Promise.resolve({ services:[] }),
        api('/backup-schedules'),
      ]);
      setOverview(nextOverview || { domains: [], services: [], resources: {} });
      setTasks(Array.isArray(nextTasks?.tasks) ? nextTasks.tasks : []);
      setPackages(Array.isArray(nextPackages?.packages) ? nextPackages.packages : []);
      setServices(Array.isArray(nextServices?.services) ? nextServices.services : []);
      setBackupSchedules(Array.isArray(nextBackupSchedules?.schedules) ? nextBackupSchedules.schedules : []);
      setCatalog(nextPackages?.catalog || {});
      if (!form.domain && nextOverview?.domains?.[0]) setForm((current) => ({ ...current, domain: nextOverview.domains[0].domain }));
      if (!backupForm.domain && nextOverview?.domains?.[0]) setBackupForm((current) => ({ ...current, domain: nextOverview.domains[0].domain }));
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
  const serviceAction = async (service, action) => {
    if (action === 'stop' && !window.confirm(`Stop ${service.label || service.name}? Dependent websites or mail may become unavailable.`)) return;
    setBusy(`service-${service.name}-${action}`); setError('');
    try {
      await api(`/tools/services/${encodeURIComponent(service.name)}/${action}`, { method:'POST', csrf:session.csrf, body:'{}' });
      window.setTimeout(load, action === 'restart' && service.critical ? 3500 : 800);
    } catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const createBackupSchedule = async (event) => {
    event.preventDefault(); setBusy('backup-schedule-create'); setError('');
    try { await api('/backup-schedules', { method:'POST', csrf:session.csrf, body:JSON.stringify(backupForm) }); await load(); }
    catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };
  const backupScheduleAction = async (item, action) => {
    if (action === 'delete' && !window.confirm(`Delete the backup schedule for ${item.domain}? Existing backup files will remain.`)) return;
    setBusy(`backup-schedule-${item.id}-${action}`); setError('');
    try {
      await api(`/backup-schedules/${item.id}${action === 'delete' ? '' : `/${action}`}`, { method:action === 'delete' ? 'DELETE' : 'POST', csrf:session.csrf, body:action === 'delete' ? undefined : '{}' });
      await load();
    } catch (nextError) { setError(nextError.message); }
    finally { setBusy(''); }
  };

  const describeBackupSchedule = (item) => {
    const time = `${String(item.hour).padStart(2,'0')}:${String(item.minute).padStart(2,'0')}`;
    if (item.frequency === 'weekly') return `${WEEKDAYS[item.weekday]} at ${time}`;
    if (item.frequency === 'monthly') return `Day ${item.monthday} at ${time}`;
    return `Every day at ${time}`;
  };

  return <>
    <header className="page-header"><div><h1>Hosting Tools</h1><p>Scheduled tasks, PHP controls, website logs and server health.</p></div><button className="secondary" onClick={load}>Refresh status</button></header>
    <div className="tools-canvas">
      {error && <div className="form-error">{error}</div>}
      <section className="tools-resource-grid"><ResourceCard label="CPU" value={overview.resources?.cpu_percent} /><ResourceCard label="Memory" value={overview.resources?.memory_percent} /><ResourceCard label="System disk" value={overview.resources?.disk_percent} /></section>
      {session.role === 'admin' ? <section className="tools-panel service-manager"><header><div><h2>Server services</h2><p>Live state and controls for the MassPanel, website, DNS, database and Grommunio stack.</p></div><small>Critical web services can be restarted but not stopped from the panel.</small></header><div className="service-table"><div className="service-table-head"><span>Service</span><span>Status</span><span>Startup</span><span>Controls</span></div>{services.map((service) => <article key={service.name}><div><b>{service.name}</b><small>{service.description || service.label}</small></div><strong className={service.state === 'active' ? 'status-pass' : 'status-warn'}><i />{service.state}{service.sub_state && service.sub_state !== service.state ? ` · ${service.sub_state}` : ''}</strong><span>{service.enabled ? 'Enabled' : 'Not enabled'}</span><div className="service-actions"><button className="secondary" disabled={!!busy || service.state === 'active'} onClick={() => serviceAction(service,'start')}>Start</button><button className="secondary" disabled={!!busy || service.state !== 'active' || service.critical} onClick={() => serviceAction(service,'stop')}>Stop</button><button className="secondary" disabled={!!busy || service.state !== 'active'} onClick={() => serviceAction(service,'restart')}>{busy === `service-${service.name}-restart` ? 'Restarting…' : 'Restart'}</button></div></article>)}{!services.length && <div className="empty">No managed services were detected.</div>}</div></section> : <section className="tools-panel"><header><div><h2>Service health</h2><p>Live state of the core website, database and Grommunio services.</p></div></header><div className="service-chip-grid">{overview.services.map((service) => <span key={service.name} className={service.state === 'active' ? 'is-active' : 'is-warning'}><i />{service.name}<b>{service.state}</b></span>)}</div></section>}
      {(session.role === 'admin' || session.features?.backups !== false) && <section className="tools-panel backup-scheduler">
        <header><div><h2>Scheduled backups</h2><p>Back up daily, weekly or monthly to this server, Google Drive, FTP or SFTP. Times use the server timezone.</p></div></header>
        <form className="backup-schedule-form" onSubmit={createBackupSchedule}>
          <label>Website<select value={backupForm.domain} onChange={(event) => setBackupForm((current) => ({ ...current, domain:event.target.value }))} required><option value="">Choose website</option>{overview.domains.map((domain) => <option key={domain.domain} value={domain.domain}>{domain.domain}</option>)}</select></label>
          <label>Frequency<select value={backupForm.frequency} onChange={(event) => setBackupForm((current) => ({ ...current, frequency:event.target.value }))}><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></label>
          {backupForm.frequency === 'weekly' && <label>Day<select value={backupForm.weekday} onChange={(event) => setBackupForm((current) => ({ ...current, weekday:Number(event.target.value) }))}>{WEEKDAYS.map((day,index) => <option key={day} value={index}>{day}</option>)}</select></label>}
          {backupForm.frequency === 'monthly' && <label>Day of month<input type="number" min="1" max="28" value={backupForm.monthday} onChange={(event) => setBackupForm((current) => ({ ...current, monthday:Number(event.target.value) }))} /></label>}
          <label>Time (server)<div className="time-fields"><input aria-label="Backup hour" type="number" min="0" max="23" value={backupForm.hour} onChange={(event) => setBackupForm((current) => ({ ...current, hour:Number(event.target.value) }))} /><span>:</span><input aria-label="Backup minute" type="number" min="0" max="59" value={backupForm.minute} onChange={(event) => setBackupForm((current) => ({ ...current, minute:Number(event.target.value) }))} /></div></label>
          <label>Keep latest<input type="number" min="1" max="30" value={backupForm.retention} onChange={(event) => setBackupForm((current) => ({ ...current, retention:Number(event.target.value) }))} /></label>
          <BackupDestinationFields form={backupForm} setForm={setBackupForm} />
          <button className="primary" disabled={busy === 'backup-schedule-create' || !overview.domains.length}>{busy === 'backup-schedule-create' ? 'Saving…' : 'Add schedule'}</button>
        </form>
        <div className="backup-schedule-list">{backupSchedules.map((item) => <article key={item.id}><div><b>{item.domain}</b><small>{describeBackupSchedule(item)} · keep {item.retention} · {item.destination_type === 'google_drive' ? 'Google Drive' : (item.destination_type || 'local').toUpperCase()}</small></div><div><small>Last run</small><b>{item.last_run_at || 'Not run yet'}</b>{item.last_status === 'failed' && <em>{item.last_error}</em>}</div><strong className={item.enabled ? 'status-pass' : 'status-warn'}>{item.enabled ? 'Enabled' : 'Paused'}</strong><div><button className="secondary" disabled={!!busy} onClick={() => backupScheduleAction(item,'run')}>Run now</button><button className="secondary" disabled={!!busy} onClick={() => backupScheduleAction(item,'toggle')}>{item.enabled ? 'Pause' : 'Enable'}</button><button className="secondary danger" disabled={!!busy} onClick={() => backupScheduleAction(item,'delete')}>Delete</button></div></article>)}{!backupSchedules.length && <div className="empty">No scheduled backups yet.</div>}</div>
      </section>}
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
