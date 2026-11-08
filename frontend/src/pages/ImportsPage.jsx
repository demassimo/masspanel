import React, { useEffect, useState } from 'react';
import { api } from '../legacy.jsx';

const running = (job) => ['queued', 'inspecting', 'restoring'].includes(job?.phase);
const size = (bytes) => `${(bytes / 1024 ** 3).toFixed(2)} GiB`;

export default function ImportsPage({ session }) {
  const [data, setData] = useState({ files: [], jobs: [] });
  const [selected, setSelected] = useState([]);
  const [job, setJob] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [merge, setMerge] = useState(false);
  async function refresh() {
    try { setData(await api('/imports/directadmin')); }
    catch (e) { setError(e.message); }
  }
  useEffect(() => { refresh(); }, []);
  useEffect(() => {
    if (!running(job)) return;
    let cancelled = false;
    const timer = setInterval(async () => {
      try {
        const next = await api(`/imports/directadmin/${job.id}`);
        if (!cancelled) setJob(next);
      } catch (e) { if (!cancelled) setError(e.message); }
    }, 3000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [job?.id, job?.phase]);
  async function submit(action) {
    setBusy(true); setError('');
    try {
      const result = await api('/imports/directadmin', { method: 'POST', csrf: session.csrf,
        body: JSON.stringify({ action, files: selected, job: job?.id, confirm: confirmed, merge_admin: merge }) });
      setJob(await api(`/imports/directadmin/${result.job}`));
      setConfirmed(false);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  const disabled = busy || running(job);
  return <section>
    <div className="page-header"><div><h1>DirectAdmin import</h1><p>Review backup accounts, then restore websites, databases, DNS and Grommunio mail.</p></div></div>
    {error && <p role="alert" className="form-error">{error}</p>}
    <div className="card" style={{ padding: 24, marginBottom: 20 }}>
      <h2>1. Select staged backups</h2>
      <p>Transfer native DirectAdmin user backups to <code>{data.staging_directory || '/var/lib/masspanel-imports/directadmin/incoming'}</code> over SSH. Files must be owned by root and private.</p>
      <button onClick={refresh} disabled={disabled}>Refresh files</button>{' '}
      <button disabled={disabled || !data.files.length} onClick={() => setSelected(data.files.map(f => f.name))}>Select all</button>
      {!data.files.length && <p>No staged backups found.</p>}
      <div style={{ maxHeight: 340, overflow: 'auto', margin: '16px 0' }}>
        {data.files.map(file => <label key={file.name} style={{ display: 'block', padding: 6 }}>
          <input type="checkbox" disabled={disabled} checked={selected.includes(file.name)} onChange={e => setSelected(current => e.target.checked ? [...current, file.name] : current.filter(x => x !== file.name))} />{' '}
          {file.name} <small>({size(file.size)})</small>
        </label>)}
      </div>
      <button disabled={disabled || !selected.length} onClick={() => submit('inspect')}>Inspect {selected.length || ''} backups</button>
    </div>
    {job && <div className="card" style={{ padding: 24, marginBottom: 20 }}>
      <h2>2. Review and restore</h2>
      <p role="status" aria-live="polite"><strong>{job.phase}</strong> — {job.message}</p>
      {running(job) && <progress value={job.progress || 0} max="100" aria-label="Import progress" />}
      {job.mail_progress && <p>Copying {job.mail_progress.address}{Number.isInteger(job.mail_progress.total) && <>: {job.mail_progress.remaining.toLocaleString()} of {job.mail_progress.total.toLocaleString()} messages remaining in this pass</>}. Verification follows the copy.</p>}
      <p>{job.accounts?.length || 0} accounts · {(job.accounts || []).reduce((n, a) => n + a.domains.length, 0)} domains · {(job.accounts || []).reduce((n, a) => n + (a.websites || a.domains).length, 0)} websites · {(job.accounts || []).reduce((n, a) => n + a.mailboxes, 0)} mailboxes</p>
      <div style={{ overflowX: 'auto' }}><table><thead><tr><th>Username</th><th>Domains</th><th>Databases</th><th>Mailboxes</th><th>Passwords / status</th></tr></thead>
        <tbody>{(job.accounts || []).map(account => <tr key={account.username}><td>{account.username}</td><td>{(account.websites || account.domains).join(', ') || '—'}{account.warnings?.map((warning, i) => <p key={i}><small>{warning}</small></p>)}</td><td>{account.databases.length}</td><td>{account.mailboxes}</td><td>{account.passwords}{account.suspended && ' · suspended'}</td></tr>)}</tbody></table></div>
      {['ready', 'blocked', 'failed'].includes(job.phase) && <>
        <p>Restore checks destination conflicts, available storage, PHP versions and capacity before making changes. Existing source data stays available. DNS cutover and scheduled tasks are separate steps.</p>
        <label style={{ display: 'block', margin: '12px 0' }}><input type="checkbox" checked={merge} onChange={e => setMerge(e.target.checked)} /> Replace the initial panel administrator password with the backed-up admin password. A destination backup is saved first.</label>
        <label style={{ display: 'block', margin: '12px 0' }}><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} /> I have reviewed these accounts and the compatibility notes.</label>
        <button disabled={disabled || !confirmed} onClick={() => submit('start')}>Restore reviewed accounts</button>
      </>}
    </div>}
    {!!data.jobs.length && <div className="card" style={{ padding: 24 }}><h2>Import history</h2>{data.jobs.map(item => <p key={item.id}><button disabled={disabled} onClick={() => { setJob(item); setConfirmed(false); }}>{item.id.slice(0, 8)} · {item.phase}</button>{' '}{item.message}</p>)}</div>}
  </section>;
}
