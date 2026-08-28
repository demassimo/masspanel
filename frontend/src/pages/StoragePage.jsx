import React, { useEffect, useState } from 'react';
import { api } from '../legacy.jsx';

const size = (bytes = 0) => {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = Number(bytes) || 0;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit < 2 ? 0 : 1)} ${units[unit]}`;
};

export default function StoragePage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const load = () => api('/storage').then(setData).catch((err) => setError(err.message));
  useEffect(load, []);
  return <section className="storage-page">
    <header className="storage-hero"><div><h1>Server storage</h1><p>Owner-only physical disks and customer allocations.</p></div><button className="secondary" onClick={load}>Refresh</button></header>
    {error && <div className="form-error">{error}</div>}
    {!data ? <div className="loading">Reading disks…</div> : <>
      <div className="storage-summary">
        <article><span>Physical filesystems</span><b>{data.drives.length}</b></article>
        <article><span>Customer allocations</span><b>{size(data.allocated_bytes)}</b></article>
        <article><span>Active hosting accounts</span><b>{data.active_accounts}</b></article>
        <article><span>Hosted domains</span><b>{data.hosted_domains}</b></article>
      </div>
      <div className="storage-card"><header><div><h2>Physical filesystems</h2><p>{data.note}</p></div><span className="storage-root">Hosting root: {data.hosting_root}</span></header>
        <div className="storage-drives">{data.drives.map((drive) => <article key={`${drive.device}:${drive.mountpoint}`}>
          <div className="drive-head"><span className="drive-icon">◫</span><div><b>{drive.device || 'Filesystem'}</b><small>{drive.mountpoint} · {drive.filesystem}</small>{drive.mountpoints?.length > 1 && <small>Also mounted at {drive.mountpoints.filter((path) => path !== drive.mountpoint).join(', ')}</small>}</div>{drive.hosting && <em>Hosting data</em>}</div>
          <div className="drive-meter"><i style={{width:`${Math.min(100, drive.percent)}%`}} /></div>
          <div className="drive-facts"><span>{size(drive.used_bytes)} used</span><span>{size(drive.free_bytes)} free</span><b>{size(drive.total_bytes)} total</b></div>
        </article>)}</div>
      </div>
      <div className="storage-guidance"><b>Using a second drive</b><p>Mount additional disks under <code>/mnt</code> or <code>/srv</code>. They appear here automatically. Moving live customer homes requires a verified migration because websites, mail, backups and permissions must move together; MassPanel will not silently relocate them.</p></div>
    </>}
  </section>;
}
