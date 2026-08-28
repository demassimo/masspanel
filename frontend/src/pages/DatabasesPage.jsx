import { useEffect, useMemo, useState } from 'react';
import { api } from '../legacy.jsx';

const list = value => Array.isArray(value) ? value : [];
const emptyBrowser = { tables:[], table:'', columns:[], primary_key:[], rows:[] };

export default function DatabasesPage({ session }) {
  const [databases,setDatabases]=useState([]), [domains,setDomains]=useState([]), [domain,setDomain]=useState('');
  const [name,setName]=useState(''), [selected,setSelected]=useState(null), [sql,setSql]=useState('SELECT name FROM sqlite_master LIMIT 20;');
  const [result,setResult]=useState([]), [error,setError]=useState(''), [busy,setBusy]=useState('');
  const [browser,setBrowser]=useState(emptyBrowser), [editing,setEditing]=useState(null);
  const load = () => Promise.all([api('/databases'),api('/domains')]).then(([db,sites]) => {
    const next=list(db?.databases), hosted=list(sites?.domains);
    setDatabases(next); setDomains(hosted);
    setDomain(current=>hosted.some(item=>item.domain===current)?current:hosted[0]?.domain||'');
    setSelected(current=>next.find(item=>String(item.id)===String(current?.id))||next[0]||null);
  }).catch(e=>setError(e.message));
  useEffect(()=>{ load(); },[]);
  useEffect(()=>{
    if(selected?.engine!=='mariadb'){ setBrowser(emptyBrowser); return; }
    setBusy('browse');
    api(`/databases/${selected.id}/browse`).then(value=>{setBrowser(value);setError('');}).catch(e=>setError(e.message)).finally(()=>setBusy(''));
  },[selected?.id]);
  const visible=useMemo(()=>domain?databases.filter(item=>item.domain===domain):databases,[databases,domain]);
  const columns=result[0]?Object.keys(result[0]):[];
  const create=async event=>{event.preventDefault();setBusy('create');setError('');try{await api('/databases',{method:'POST',csrf:session.csrf,body:JSON.stringify({domain,name})});setName('');await load();}catch(e){setError(e.message);}finally{setBusy('');}};
  const remove=async item=>{if(item.managed_application||!window.confirm(`Delete ${item.name}?`))return;setBusy(`delete-${item.id}`);try{await api(`/databases/${item.id}`,{method:'DELETE',csrf:session.csrf});await load();}catch(e){setError(e.message);}finally{setBusy('');}};
  const query=async()=>{if(!selected||selected.engine!=='sqlite')return;setBusy('query');setError('');try{const value=await api(`/databases/${selected.id}/query`,{method:'POST',csrf:session.csrf,body:JSON.stringify({sql})});setResult(list(value?.rows));}catch(e){setError(e.message);}finally{setBusy('');}};
  const openTable=async table=>{setBusy('browse');setError('');setEditing(null);try{setBrowser(await api(`/databases/${selected.id}/browse?table=${encodeURIComponent(table)}`));}catch(e){setError(e.message);}finally{setBusy('');}};
  const changedValues=editing?Object.fromEntries(Object.entries(editing.values).filter(([column,value])=>!browser.primary_key.includes(column)&&value!==editing.original[column])):{};
  const saveRow=async()=>{if(!editing||!Object.keys(changedValues).length)return;setBusy('save-row');setError('');try{const key=Object.fromEntries(browser.primary_key.map(column=>[column,browser.rows[editing.index]?.[column]]));await api(`/databases/${selected.id}/rows`,{method:'PATCH',csrf:session.csrf,body:JSON.stringify({table:browser.table,key,changes:changedValues})});await openTable(browser.table);}catch(e){setError(e.message);}finally{setBusy('');}};
  return <>
    <header className="page-header"><div><h1>Databases</h1><p>Browse and edit application MariaDB databases or query customer SQLite databases.</p></div><button className="secondary" onClick={load}>Refresh</button></header>
    <main className="data-workspace">
      {error&&<div className="form-error">{error}</div>}
      <section className="data-summary"><article><span>Total databases</span><b>{databases.length}</b></article><article><span>MariaDB applications</span><b>{databases.filter(x=>x.engine==='mariadb').length}</b></article><article><span>SQLite databases</span><b>{databases.filter(x=>x.engine==='sqlite').length}</b></article></section>
      <section className="data-panel"><header><div><h2>Database inventory</h2><p>Select a database to open its viewer.</p></div><label>Website<select value={domain} onChange={e=>setDomain(e.target.value)}>{domains.map(item=><option key={item.domain}>{item.domain}</option>)}</select></label></header>
        <form className="data-create" onSubmit={create}><div><b>Create lightweight database</b><span>Creates a private SQLite database for custom applications.</span></div><input value={name} onChange={e=>setName(e.target.value)} placeholder="database_name" pattern="[a-z][a-z0-9_]{2,31}" required/><button className="primary" disabled={!domain||busy==='create'}>{busy==='create'?'Creating…':'Create database'}</button></form>
        <div className="database-grid">{visible.map(item=><article key={item.id} className={String(selected?.id)===String(item.id)?'selected':''} onClick={()=>{setSelected(item);setResult([]);}}><div className={`database-engine ${item.engine}`}>{item.engine==='mariadb'?'M':'S'}</div><div><b>{item.name}</b><span>{item.engine==='mariadb'?'MariaDB · managed application':'SQLite · customer database'}</span><small>{item.domain} · {item.owner}</small></div><strong className="data-state">{item.status||'active'}</strong>{!item.managed_application&&<button className="icon-danger" title="Delete database" onClick={e=>{e.stopPropagation();remove(item);}}>×</button>}</article>)}{!visible.length&&<div className="empty">No databases attached to this domain.</div>}</div>
      </section>
      <section className="data-panel query-panel"><header><div><h2>Database viewer</h2><p>{selected?.engine==='mariadb'?'Choose a table, inspect rows and edit records safely.':'Run read-only SELECT queries against a SQLite database.'}</p></div><div className="database-viewer-actions">{selected?.engine==='mariadb'&&<a className="secondary" href={`/api/database-tool/open/${encodeURIComponent(selected.id)}`} target="_blank" rel="noreferrer">Open AdminNeo</a>}{selected&&<span className={`engine-badge ${selected.engine}`}>{selected.engine==='mariadb'?'MariaDB':'SQLite'}</span>}</div></header>
        {!selected?<div className="empty">Select a database above.</div>:selected.engine==='mariadb'?<div className="database-browser">
          <aside><b>Tables</b>{browser.tables.map(table=><button className={browser.table===table?'active':''} key={table} onClick={()=>openTable(table)}>{table}</button>)}{busy==='browse'&&<span>Loading…</span>}</aside>
          <section><header><div><b>{browser.table||selected.name}</b><span>{browser.table?`${browser.rows.length} rows shown · limit ${browser.limit}`:'Choose a table to view its data.'}</span></div>{browser.table&&<button className="secondary" onClick={()=>openTable(browser.table)}>Refresh</button>}</header>
            {browser.table?<div className="table-wrap database-rows"><table><thead><tr>{browser.columns.map(column=><th key={column.Field}>{column.Field}<small>{column.Type}</small></th>)}<th>Actions</th></tr></thead><tbody>{browser.rows.map((row,index)=><tr key={index}>{browser.columns.map(column=><td key={column.Field} title={String(row[column.Field]??'')}>{row[column.Field]===null?'':String(row[column.Field])}</td>)}<td><button className="secondary" disabled={!browser.primary_key.length} title={!browser.primary_key.length?'This table has no primary key':''} onClick={()=>setEditing({index,original:{...row},values:{...row}})}>Edit</button></td></tr>)}</tbody></table></div>:<div className="database-browser-empty" aria-label="No table selected"/>}
          </section></div>:<><textarea className="sql-editor" value={sql} onChange={e=>setSql(e.target.value)} spellCheck="false"/><div className="query-actions"><span>Only SELECT statements are accepted.</span><button className="primary" onClick={query} disabled={busy==='query'}>{busy==='query'?'Running…':'Run query'}</button></div>{result.length?<div className="table-wrap"><table><thead><tr>{columns.map(c=><th key={c}>{c}</th>)}</tr></thead><tbody>{result.map((row,i)=><tr key={i}>{columns.map(c=><td key={c}>{String(row[c]??'')}</td>)}</tr>)}</tbody></table></div>:<div className="empty">No query results yet.</div>}</>}
      </section>
    </main>
    {editing&&<div className="database-edit-modal"><section><header><div><h2>Edit row</h2><span>{browser.table} · primary key: {browser.primary_key.join(', ')}</span></div><button onClick={()=>setEditing(null)}>×</button></header><div className="database-edit-fields">{browser.columns.map(column=><label key={column.Field}><span>{column.Field}<small>{column.Type}</small></span><textarea value={editing.values[column.Field]??''} disabled={browser.primary_key.includes(column.Field)} onChange={e=>setEditing(current=>({...current,values:{...current.values,[column.Field]:e.target.value}}))}/></label>)}</div><footer><button className="secondary" onClick={()=>setEditing(null)}>Cancel</button><button className="primary" disabled={busy==='save-row'||!Object.keys(changedValues).length} onClick={saveRow}>{busy==='save-row'?'Saving…':'Save changes'}</button></footer></section></div>}
  </>;
}
