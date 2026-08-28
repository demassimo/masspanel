import React, { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../legacy.jsx';

const list = value => Array.isArray(value) ? value : [];
const join = (base, name) => base ? `${base}/${name}` : name;
const size = bytes => bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`;
const storageSize = bytes => bytes >= 1073741824 ? `${(bytes / 1073741824).toFixed(1)} GB` : `${(bytes / 1048576).toFixed(bytes >= 104857600 ? 0 : 1)} MB`;

function FileEdit({ session, domain, item, onClose, onSaved }) {
  const [content, setContent] = useState('');
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    api(`/files/content?domain=${encodeURIComponent(domain)}&path=${encodeURIComponent(item.path)}`)
      .then(value => setContent(value.content || '')).catch(reason => setError(reason.message)).finally(() => setBusy(false));
  }, []);
  const save = async () => {
    setBusy(true);
    try {
      await api('/files', { method: 'POST', csrf: session.csrf, body: JSON.stringify({ action: 'write_file', domain, path: item.path, content }) });
      onSaved(); onClose();
    } catch (reason) { setError(reason.message); } finally { setBusy(false); }
  };
  return <div className="explorer-modal"><section><header><div><b>{item.name}</b><span>{item.path}</span></div><button onClick={onClose}>×</button></header>{error && <div className="form-error">{error}</div>}<textarea value={busy ? 'Loading…' : content} onChange={event => setContent(event.target.value)} disabled={busy}/><footer><button className="secondary" onClick={onClose}>Cancel</button><button className="primary" onClick={save} disabled={busy}>Save file</button></footer></section></div>;
}

export default function FilesPage({ session }) {
  const [domains, setDomains] = useState([]);
  const [domain, setDomain] = useState('');
  const [path, setPath] = useState('');
  const [data, setData] = useState({ items: [] });
  const [selected, setSelected] = useState(null);
  const [editor, setEditor] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [search, setSearch] = useState('');
  const [quota, setQuota] = useState(null);
  const input = useRef(null);

  useEffect(() => {
    api('/domains').then(value => { const next = list(value.domains); setDomains(next); setDomain(next[0]?.domain || ''); }).catch(reason => setError(reason.message));
  }, []);
  const reload = () => {
    if (domain) api(`/files?${new URLSearchParams({ domain, path })}`).then(value => setData({ ...value, items: list(value.items) })).catch(reason => setError(reason.message));
  };
  useEffect(() => { setSelected(null); reload(); }, [domain, path]);
  useEffect(() => {
    if (!domain) { setQuota(null); return; }
    api(`/files/quota?domain=${encodeURIComponent(domain)}`).then(setQuota).catch(() => setQuota(null));
  }, [domain]);

  const items = useMemo(() => list(data.items)
    .filter(item => item.name.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : 1), [data, search]);
  const crumbs = path ? path.split('/').filter(Boolean) : [];
  const goBack = () => setPath(crumbs.slice(0, -1).join('/'));
  const mutate = async payload => {
    setBusy(payload.action); setError('');
    try { await api('/files', { method: 'POST', csrf: session.csrf, body: JSON.stringify({ domain, ...payload }) }); reload(); }
    catch (reason) { setError(reason.message); } finally { setBusy(''); }
  };
  const createFolder = () => { const name = window.prompt('Folder name'); if (name) mutate({ action: 'mkdir', path: join(path, name) }); };
  const createFile = () => { const name = window.prompt('File name'); if (name) mutate({ action: 'create_file', path: join(path, name), content: '' }).then(() => setEditor({ name, path: join(path, name) })); };
  const upload = async files => {
    setBusy('upload'); setError('');
    try {
      for (const file of files) { const body = new FormData(); body.append('domain', domain); body.append('path', path); body.append('file', file, file.name); await api('/files/upload', { method: 'POST', csrf: session.csrf, body }); }
      reload();
    } catch (reason) { setError(reason.message); } finally { setBusy(''); }
  };
  const open = item => item.type === 'dir' ? setPath(join(path, item.name)) : setEditor({ ...item, path: join(path, item.name) });
  const rename = item => { const name = window.prompt('New name', item.name); if (name && name !== item.name) mutate({ action: 'rename', path: join(path, item.name), new_name: name }); };
  const remove = item => { if (window.confirm(`Delete ${item.name}?`)) mutate({ action: 'delete', path: join(path, item.name) }); };

  return <>
    <header className="page-header"><div><h1>File Manager</h1><p>Browse folders, edit documents and upload multiple files.</p></div><div className="explorer-header-actions">{quota&&<div className="storage-allocation"><span>Account storage</span><b>{storageSize(quota.used_bytes)} of {quota.limit_bytes?storageSize(quota.limit_bytes):'Unlimited'}</b></div>}<input ref={input} hidden type="file" multiple onChange={event => { upload([...event.target.files]); event.target.value = ''; }}/><a className="secondary" href="/api/file-tool/open" target="_blank" rel="noreferrer">Advanced manager</a><button className="secondary" onClick={createFolder} disabled={!domain}>New folder</button><button className="secondary" onClick={createFile} disabled={!domain}>New file</button><button className="primary" onClick={() => input.current?.click()} disabled={!domain || busy === 'upload'}>{busy === 'upload' ? 'Uploading…' : 'Upload files'}</button></div></header>
    <main className="explorer-shell" onDragOver={event => event.preventDefault()} onDrop={event => { event.preventDefault(); if (event.dataTransfer.files.length) upload([...event.dataTransfer.files]); }}>
      <aside><h3>Websites</h3>{domains.map(item => <button className={domain === item.domain ? 'active' : ''} key={item.domain} onClick={() => { setDomain(item.domain); setPath(''); }}>▣ <span>{item.domain}</span></button>)}</aside>
      <section className="explorer-main">{error && <div className="form-error">{error}</div>}
        <div className="explorer-toolbar"><button aria-label="Back to parent folder" title="Back to parent folder" onClick={goBack} disabled={!path}>←</button><button aria-label="Refresh folder" title="Refresh folder" onClick={reload}>↻</button><nav><button onClick={() => setPath('')}>Home</button>{crumbs.map((crumb, index) => <React.Fragment key={`${crumb}-${index}`}><span>›</span><button onClick={() => setPath(crumbs.slice(0, index + 1).join('/'))}>{crumb}</button></React.Fragment>)}</nav><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search this folder"/></div>
        <div className="explorer-grid">{items.map(item => <article key={item.name} className={selected?.name === item.name ? 'selected' : ''} onClick={() => setSelected(item)} onDoubleClick={() => open(item)}><div className={`file-art ${item.type}`}>{item.type === 'dir' ? '📁' : /\.(png|jpe?g|gif|webp|svg)$/i.test(item.name) ? '▧' : /\.(php|js|css|html?|json)$/i.test(item.name) ? '⌨' : '▤'}</div><b title={item.name}>{item.name}</b><span>{item.type === 'dir' ? 'File folder' : size(item.size || 0)}</span></article>)}{!items.length && <div className="explorer-empty"><b>This folder is empty</b><span>Drop files here or use Upload files.</span></div>}</div>
        <footer className="explorer-status">{items.length} item{items.length === 1 ? '' : 's'}<span>{selected ? selected.name : 'No item selected'}</span></footer>
      </section>
      {selected && <aside className="explorer-details"><div className={`file-art large ${selected.type}`}>{selected.type === 'dir' ? '📁' : '▤'}</div><h3>{selected.name}</h3><p>{selected.type === 'dir' ? 'Folder' : size(selected.size || 0)}</p><button className="primary" onClick={() => open(selected)}>{selected.type === 'dir' ? 'Open' : 'Edit'}</button>{selected.type === 'file' && <a className="secondary" href={`/api/files/download?domain=${encodeURIComponent(domain)}&path=${encodeURIComponent(join(path, selected.name))}`}>Download</a>}<button className="secondary" onClick={() => rename(selected)}>Rename</button><button className="secondary danger" onClick={() => remove(selected)}>Delete</button></aside>}
    </main>
    {editor && <FileEdit session={session} domain={domain} item={editor} onClose={() => setEditor(null)} onSaved={reload}/>} 
  </>;
}
