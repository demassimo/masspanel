import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './roles.css';
import './design.css';
import './hosting.css';
import './cloudflare.css';
import './settings-actions.css';
import './apps.css';
import PanelIcon from './components/PanelIcon.jsx';

const pageLabel = {
  overview: 'Dashboard', users: 'Users', websites: 'Websites', apps: 'App Installer', files: 'File manager',
  tools: 'Hosting tools', store: 'Storefront',
  databases: 'Databases', backups: 'Backups', dns: 'Domains & DNS', email: 'Email & Groupware',
  security: 'Mail security', firewall: 'Firewall', storage: 'Server storage', updates: 'Updates', ssl: 'Certificates', tickets: 'Support', audit: 'Activity', licenses: 'Open source', settings: 'Settings',
};

const ADMIN_PAGES = ['overview', 'users', 'websites', 'apps', 'tools', 'store', 'files', 'databases', 'backups', 'dns', 'email', 'security', 'firewall', 'storage', 'updates', 'ssl', 'tickets', 'audit', 'licenses', 'settings'];
const CLIENT_PAGES = ['overview', 'websites', 'apps', 'tools', 'files', 'databases', 'backups', 'dns', 'email', 'security', 'ssl', 'tickets', 'licenses', 'settings'];
const PAGE_FEATURE = { websites:'websites', apps:'wordpress', files:'files', databases:'databases', backups:'backups', dns:'dns', email:'mail', security:'mail', ssl:'ssl', tickets:'support' };
function pagesForSession(session) {
  if (session.role === 'admin') return ADMIN_PAGES;
  const features = session.features || {};
  return CLIENT_PAGES.filter((page) => page === 'tools' ? (features.cron !== false || features.php !== false || features.websites !== false) : !PAGE_FEATURE[page] || features[PAGE_FEATURE[page]] !== false);
}
const DEFAULT_PRODUCT = { panel_name: 'MassPanel', company_name: '', support_email: '', support_url: '', public_url: '', mail_hostname: '', system_mail_domain: '', footer_text: 'Free and self-hosted hosting control panel', show_powered_by: true };

class PanelErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, message: String(error?.message || 'Panel initialization failed.') };
  }

  componentDidCatch(error, info) {
    console.error('Panel render error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          className="loading"
          style={{
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '100vh',
            flexDirection: 'column',
            gap: '10px',
          }}
        >
          <h1>MassPanel error</h1>
          <p>There was an issue rendering the panel.</p>
          <small>{this.state.message}</small>
          <button className="primary" type="button" onClick={() => window.location.reload()}>
            Reload panel
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

class PageErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Panel page error:', error, info);
    const message = String(error?.message || error || '');
    if (/dynamically imported module|loading chunk|importing a module script|is not a function/i.test(message)) {
      const currentAsset = document.querySelector('script[type="module"]')?.src || 'current-build';
      const retryKey = `masspanel-runtime-retry:${currentAsset}`;
      if (!window.sessionStorage.getItem(retryKey)) {
        window.sessionStorage.setItem(retryKey, '1');
        window.location.reload();
      }
    }
  }

  componentDidUpdate(previousProps) {
    if (this.state.error && previousProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <section className="table-area page-recovery" role="alert">
        <h1>This page could not be displayed</h1>
        <p>{String(this.state.error?.message || 'An unexpected interface error occurred.')}</p>
        <div className="page-actions"><button className="secondary" type="button" onClick={() => window.location.reload()}>Reload this page</button><button className="primary" type="button" onClick={this.props.onRecover}>Back to overview</button></div>
      </section>
    );
  }
}

function FatalErrorScreen({ message }) {
  return (
    <div
      className="loading"
      style={{
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        flexDirection: 'column',
        gap: '10px',
      }}
    >
      <h1>MassPanel error</h1>
      <p>A runtime error interrupted the interface.</p>
      <small>{message || 'Unknown error'}</small>
      <button className="primary" type="button" onClick={() => window.location.reload()}>
        Reload panel
      </button>
    </div>
  );
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeSession(value) {
  if (!value || typeof value !== 'object') return null;
  return {
    username: value.username || '',
    role: value.role === 'admin' ? 'admin' : 'client',
    system_username: value.system_username || null,
    csrf: value.csrf || '',
    impersonating_as: value.impersonating_as || null,
    impersonator: value.impersonator || null,
    features: value.features && typeof value.features === 'object' ? value.features : {},
  };
}

async function api(path, options = {}) {
  const isForm = typeof FormData !== 'undefined' && options.body instanceof FormData;
  const r = await fetch(`/api${path}`, {
    ...options,
    credentials: 'same-origin',
    headers: {
      ...(isForm ? {} : { 'Content-Type': 'application/json' }),
      ...(options.csrf ? { 'X-CSRF-Token': options.csrf } : {}),
      ...(options.headers || {}),
    },
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || 'Request failed');
  return d;
}

function joinPath(base, name) {
  if (!name) return base || '';
  if (!base) return name;
  if (base.endsWith('/')) return `${base}${name}`;
  return `${base}/${name}`;
}

function Login({ onLogin, product = DEFAULT_PRODUCT }) {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      onLogin(await api('/login', { method: 'POST', body: JSON.stringify({ username: u, password: p }) }));
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="brand brand-dark"><span className="brand-mark">{product.panel_name[0]?.toUpperCase()}</span><span>{product.panel_name}</span></div>
        <span className="eyebrow">ADMIN & CLIENT PORTAL</span>
        <h1>Welcome back</h1>
        <p>Sign in to manage your server or websites.</p>
        <form onSubmit={submit}>
          <label>
            Username
            <input autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} required />
          </label>
          <label>
            Password
            <input type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} required />
          </label>
          {error && <div className="form-error">{error}</div>}
          <button className="primary wide" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </form>
        {product.show_powered_by && <small className="powered-by">Powered by MassPanel · Free and self-hosted</small>}
      </section>
    </main>
  );
}

function Sidebar({ session, page, setPage, onLogout, onStopImpersonation, product = DEFAULT_PRODUCT }) {
  const links = pagesForSession(session);
  return (
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">{product.panel_name[0]?.toUpperCase()}</span><span>{product.panel_name}</span></div>
      <nav>
        {links.map((k) => (
          <button key={k} className={page === k ? 'active' : ''} onClick={() => setPage(k)}>
            <i><PanelIcon name={k} /></i>
            <span>{pageLabel[k] || k}</span>
          </button>
        ))}
      </nav>
      <button className="admin-control" onClick={onLogout}>
        <span className="avatar">{(session.username || '?')[0]?.toUpperCase() || '?'}</span>
        <span>
          <b>{session.username}</b>
          <small>{session.role}</small>
        </span>
        <span className="signout">Sign out</span>
      </button>
      {session.impersonating_as && (
        <button className="admin-control" style={{ marginTop: 8 }} onClick={onStopImpersonation}>
          <span className="avatar">↩</span>
          <span>
            <b>Stop impersonation</b>
            <small>Back to {session.impersonator || session.username}</small>
          </span>
        </button>
      )}
    </aside>
  );
}

function Topbar({ session, page, setPage, onLogout }) {
  const [query, setQuery] = useState('');
  const allowed = pagesForSession(session);
  function submit(event) {
    event.preventDefault();
    const match = allowed.find((item) => item.includes(query.trim().toLowerCase()));
    if (match) {
      setPage(match);
      setQuery('');
    }
  }
  return (
    <header className="topbar">
      <div className="topbar-title"><span><PanelIcon name={page} size={20} /></span><b>{pageLabel[page] || page}</b></div>
      <form className="global-search" onSubmit={submit} role="search">
        <span>⌕</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search panel tools…" aria-label="Search panel tools" />
        <kbd>Enter</kbd>
      </form>
      <button className="topbar-user" type="button" onClick={onLogout} title="Sign out">
        <span className="avatar">{(session.username || '?')[0]?.toUpperCase()}</span>
        <span><b>{session.username}</b><small>{session.role === 'admin' ? 'Administrator' : 'Hosting client'}</small></span>
      </button>
    </header>
  );
}

function Drawer({ title, onClose, children, className = '' }) {
  return (
    <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className={`drawer ${className}`.trim()}>
        <header>
          <h2>{title}</h2>
          <button type="button" onClick={onClose} aria-label="Close">×</button>
        </header>
        {children}
      </aside>
    </div>
  );
}

function CreateUser({ session, onClose, onDone }) {
  const [f, setF] = useState({ username: '', display_name: '', password: '', confirm_password: '', shell: '/bin/bash' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function change(e) {
    setF({ ...f, [e.target.name]: e.target.value });
  }
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/users', { method: 'POST', csrf: session.csrf, body: JSON.stringify(f) });
      onDone();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Drawer title="Create client" onClose={onClose}>
      <form onSubmit={submit}>
        <p className="drawer-note">Creates both a Linux account and a client portal login.</p>
        <label>
          Username
          <input name="username" value={f.username} onChange={change} pattern="[a-z][a-z0-9_-]{2,31}" required />
        </label>
        <label>
          Display name
          <input name="display_name" value={f.display_name} onChange={change} />
        </label>
        <label>
          Password
          <input name="password" type="password" minLength="12" value={f.password} onChange={change} required />
        </label>
        <label>
          Confirm password
          <input name="confirm_password" type="password" minLength="12" value={f.confirm_password} onChange={change} required />
        </label>
        <label>
          Shell
          <select name="shell" value={f.shell} onChange={change}>
            <option>/bin/bash</option>
            <option>/bin/sh</option>
            <option>/usr/sbin/nologin</option>
          </select>
        </label>
        {error && <div className="form-error">{error}</div>}
        <footer>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy}>{busy ? 'Creating…' : 'Create client'}</button>
        </footer>
      </form>
    </Drawer>
  );
}

function ConfigureHostingUser({ session, username, onClose, onDone }) {
  const [data, setData] = useState({ account: {}, domains: [] });
  const [packages, setPackages] = useState([]);
  const [packageId, setPackageId] = useState('');
  const [domainLimit, setDomainLimit] = useState(10);
  const [diskLimitMb, setDiskLimitMb] = useState(10240);
  const [allowCreation, setAllowCreation] = useState(true);
  const [featureCatalog, setFeatureCatalog] = useState({});
  const [featureOverrides, setFeatureOverrides] = useState({});
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([api(`/users/${username}/hosting`), api('/packages')])
      .then(([value, packageData]) => {
        setData(value);
        setPackages(asArray(packageData?.packages));
        setPackageId(value?.account?.package_id || '');
        setDomainLimit(value?.account?.domain_limit ?? 10);
        setDiskLimitMb(value?.account?.disk_limit_mb ?? 10240);
        setAllowCreation(Boolean(value?.account?.allow_domain_creation));
        setFeatureCatalog(value?.feature_catalog || {});
        setFeatureOverrides(value?.feature_overrides || {});
      })
      .catch((x) => setError(x.message))
      .finally(() => setBusy(false));
  }, [username]);

  async function save(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api(`/users/${username}/hosting`, {
        method: 'PUT',
        csrf: session.csrf,
        body: JSON.stringify({ domain_limit: Number(domainLimit), disk_limit_mb: Number(diskLimitMb), allow_domain_creation: allowCreation }),
      });
      await api(`/users/${username}/package`, { method:'PUT', csrf:session.csrf, body:JSON.stringify({ package_id:packageId ? Number(packageId) : null }) });
      await api(`/users/${username}/features`, { method:'PUT', csrf:session.csrf, body:JSON.stringify({ overrides:Object.fromEntries(Object.keys(featureCatalog).map((key) => [key, Object.prototype.hasOwnProperty.call(featureOverrides,key) ? featureOverrides[key] : null])) }) });
      onDone();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer title={`Hosting access · ${username}`} onClose={onClose}>
      <form onSubmit={save}>
        <p className="drawer-note">Domains linked here become available throughout this client's Websites, DNS, Files, Databases, Email, Backups, and SSL tools.</p>
        <label>Hosting package<select value={packageId} onChange={(event) => setPackageId(event.target.value)}><option value="">Custom limits</option>{packages.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label>Maximum domains<input type="number" min="0" max="1000" value={domainLimit} onChange={(event) => setDomainLimit(event.target.value)} required /></label>
        <label>Storage allocation MB<input type="number" min="128" max="10485760" value={diskLimitMb} onChange={(event) => setDiskLimitMb(event.target.value)} required /><small>Used by the customer storage indicator when Custom limits is selected.</small></label>
        <label className="switch-row drawer-switch"><span><b>Client can add websites</b><small>New domains are automatically owned by this client.</small></span><input type="checkbox" checked={allowCreation} onChange={(event) => setAllowCreation(event.target.checked)} /></label>
        <fieldset className="domain-assignment"><legend>Feature overrides</legend><p className="drawer-note">Inherit the package setting, or make an exception for this customer.</p>{Object.entries(featureCatalog).map(([key,label]) => <label key={key}>{label}<select value={Object.prototype.hasOwnProperty.call(featureOverrides,key) ? String(featureOverrides[key]) : 'inherit'} onChange={(event) => setFeatureOverrides((current) => { const next={...current}; if(event.target.value==='inherit') delete next[key]; else next[key]=event.target.value==='true'; return next; })}><option value="inherit">Inherit package</option><option value="true">Enabled</option><option value="false">Disabled</option></select></label>)}</fieldset>
        <fieldset className="domain-assignment">
          <legend>Linked domains ({data.domains.length}/{domainLimit || 0})</legend>
          {asArray(data.domains).map((domain) => <div className="linked-domain" key={domain.domain}><span><b>{domain.domain}</b><small>Available across every client hosting tool</small></span><strong>{domain.suspended ? 'Suspended' : 'Active'}</strong></div>)}
          {!data.domains.length && <div className="empty">No domains yet. Add one through the client portal or the Websites page.</div>}
        </fieldset>
        {error && <div className="form-error">{error}</div>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save hosting access'}</button></footer>
      </form>
    </Drawer>
  );
}

function Users({ session, onImpersonate }) {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  const [open, setOpen] = useState(false);
  const [busyUser, setBusyUser] = useState('');
  const [hostingUser, setHostingUser] = useState('');

  const load = () => api('/users').then((d) => setUsers(asArray(d?.users))).catch((x) => setError(x.message));
  useEffect(() => { load(); }, []);

  async function act(u, kind) {
    setError('');
    try {
      if (kind === 'lock') await api(`/users/${u}/lock`, { method: 'POST', csrf: session.csrf });
      else if (kind === 'unlock') await api(`/users/${u}/unlock`, { method: 'POST', csrf: session.csrf });
      else if (kind === 'delete') await api(`/users/${u}`, { method: 'DELETE', csrf: session.csrf });
      else if (kind === 'password') {
        const password = window.prompt(`New password for ${u} (min 12 chars):`);
        if (!password || password.length < 12) return;
        const confirm = window.prompt('Confirm new password:');
        await api(`/users/${u}/password`, { method: 'POST', csrf: session.csrf, body: JSON.stringify({ password, confirm_password: confirm }) });
      } else if (kind === 'impersonate') {
        if (!onImpersonate) throw new Error('Impersonation is unavailable in this view.');
        if (!window.confirm(`Log in as ${u}? All actions will be audited under your admin account.`)) return;
        setBusyUser(u);
        await onImpersonate(u);
      }
      load();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusyUser('');
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Users</h1>
          <p>Linux accounts with client-panel access.</p>
        </div>
        <button className="primary" onClick={() => setOpen(true)}>Create client</button>
      </header>
      <section className="table-area">
        {error && <div className="form-error">{error}</div>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Status</th>
                <th>UID</th>
                <th>Home</th>
                <th>Shell</th>
                <th>Domains</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.username}>
                  <td><b>{u.username}</b>{u.protected && <small>Protected</small>}</td>
                  <td><span className="status"><i />{u.locked ? 'Locked' : 'Active'}</span></td>
                  <td>{u.uid}</td>
                  <td>{u.home}</td>
                  <td>{u.shell}</td>
                  <td>{u.panel_role === 'client' ? `${u.domain_count || 0} / ${u.domain_limit ?? 0}` : '—'}</td>
                  <td>
                    {u.panel_role === 'client' && <button className="secondary" onClick={() => setHostingUser(u.panel_username || u.username)}>Configure hosting</button>}
                    {u.can_impersonate ? (
                      <button className="secondary" disabled={busyUser === u.username} onClick={() => act(u.username, 'impersonate')}>
                        {busyUser === u.username ? 'Opening…' : 'Impersonate'}
                      </button>
                    ) : <small>No active client login</small>}
                    <button className="secondary" onClick={() => act(u.username, u.locked ? 'unlock' : 'lock')}>{u.locked ? 'Unlock' : 'Lock'}</button>
                    <button className="secondary" onClick={() => act(u.username, 'password')}>Set password</button>
                    <button className="secondary" onClick={() => act(u.username, 'delete')}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!users.length && <div className="empty">No users available.</div>}
        </div>
      </section>
      {open && <CreateUser session={session} onClose={() => setOpen(false)} onDone={() => { setOpen(false); load(); }} />}
      {hostingUser && <ConfigureHostingUser session={session} username={hostingUser} onClose={() => setHostingUser('')} onDone={() => { setHostingUser(''); load(); }} />}
    </>
  );
}

function CreateWebsite({ session, users, onClose, onDone }) {
  const [f, setF] = useState({ domain: '', owner: session.role === 'admin' ? (users[0]?.username || '') : (session.system_username || '') });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    api('/domains', { method: 'POST', csrf: session.csrf, body: JSON.stringify(f) })
      .then(onDone)
      .catch((x) => setError(x.message))
      .finally(() => setBusy(false));
  }
  function change(e) {
    setF({ ...f, [e.target.name]: e.target.value });
  }
  return (
    <Drawer title="Add website" onClose={onClose}>
      <form onSubmit={submit}>
        <p className="drawer-note">Websites use a registrable domain such as example.com. To use a child hostname only for email, add it from Email instead of creating another website.</p>
        <label>
          Website domain
          <input value={f.domain} onChange={change} name="domain" placeholder="example.com" required />
        </label>
        {session.role === 'admin' && <label>Client<select name="owner" value={f.owner} onChange={change} required><option value="">Select client</option>{users.filter((u) => u.panel_role === 'client').map((u) => <option key={u.username}>{u.username}</option>)}</select></label>}
        {error && <div className="form-error">{error}</div>}
        <footer>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy}>{busy ? 'Adding…' : 'Add website'}</button>
        </footer>
      </form>
    </Drawer>
  );
}

function Websites({ session }) {
  const [domains, setDomains] = useState([]);
  const [users, setUsers] = useState([]);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(null);
  const [plan, setPlan] = useState({ domain_limit: null, allow_domain_creation: true });
  const [redirectDomain, setRedirectDomain] = useState('');
  const [redirects, setRedirects] = useState([]);
  const [redirectForm, setRedirectForm] = useState({ source_path:'/', target_url:'https://', status_code:301 });

  const load = () => {
    Promise.all([api('/domains'), session.role === 'admin' ? api('/users') : Promise.resolve({ users: [] })]).then(([d, u]) => {
      setDomains(asArray(d?.domains));
      setPlan({ domain_limit: d?.domain_limit, allow_domain_creation: d?.allow_domain_creation !== false });
      setUsers(asArray(u?.users));
      const nextDomains = asArray(d?.domains);
      if (!nextDomains.some((item) => item.domain === redirectDomain)) setRedirectDomain(nextDomains[0]?.domain || '');
    }).catch((x) => setError(x.message));
  };
  useEffect(() => { load(); }, []);
  useEffect(() => { if (redirectDomain) api(`/domains/${encodeURIComponent(redirectDomain)}/redirects`).then((value) => setRedirects(asArray(value?.redirects))).catch((x) => setError(x.message)); else setRedirects([]); }, [redirectDomain]);

  async function addRedirect(event) {
    event.preventDefault(); setBusy('redirect-create'); setError('');
    try { await api(`/domains/${encodeURIComponent(redirectDomain)}/redirects`, { method:'POST', csrf:session.csrf, body:JSON.stringify({ ...redirectForm, status_code:Number(redirectForm.status_code) }) }); setRedirectForm({ source_path:'/', target_url:'https://', status_code:301 }); const value=await api(`/domains/${encodeURIComponent(redirectDomain)}/redirects`); setRedirects(asArray(value?.redirects)); }
    catch (x) { setError(x.message); } finally { setBusy(null); }
  }
  async function removeRedirect(item) {
    if (!window.confirm(`Delete redirect ${item.source_path}?`)) return;
    setBusy(`redirect-${item.id}`); setError('');
    try { await api(`/domains/${encodeURIComponent(redirectDomain)}/redirects/${item.id}`, { method:'DELETE', csrf:session.csrf }); setRedirects((current) => current.filter((entry) => entry.id !== item.id)); }
    catch (x) { setError(x.message); } finally { setBusy(null); }
  }

  async function act(domain, action, body = null) {
    setBusy(`${domain}-${action}`);
    setError('');
    try {
      if (action === 'delete') {
        if (!window.confirm(`Delete ${domain}?`)) return;
        await api(`/domains/${domain}`, { method: 'DELETE', csrf: session.csrf });
      } else if (action === 'suspend') {
        await api(`/domains/${domain}/suspend`, { method: 'POST', csrf: session.csrf });
      } else if (action === 'unsuspend') {
        await api(`/domains/${domain}/unsuspend`, { method: 'POST', csrf: session.csrf });
      } else if (action === 'ssl') {
        await api(`/domains/${domain}/ssl`, { method: 'POST', csrf: session.csrf, body: JSON.stringify(body) });
      }
      load();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Websites</h1>
          <p>{session.role === 'admin' ? 'Provision client websites, web roots and HTTPS.' : 'Manage your websites, web roots and HTTPS.'}</p>
        </div>
        {(session.role === 'admin' || plan.allow_domain_creation) && <button className="primary" onClick={() => setOpen(true)} disabled={session.role !== 'admin' && plan.domain_limit !== null && domains.length >= plan.domain_limit}>Add website</button>}
      </header>
      <section className="table-area">
        {session.role !== 'admin' && <div className="hosting-plan-banner"><span><b>{domains.length}</b> linked website{domains.length === 1 ? '' : 's'}</span><span>Plan limit: <b>{plan.domain_limit ?? '—'}</b></span><span>Domain creation: <b>{plan.allow_domain_creation ? 'Allowed' : 'Managed by administrator'}</b></span></div>}
        {error && <div className="form-error">{error}</div>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                {session.role === 'admin' && <th>Owner</th>}
                <th>Web root</th>
                <th>HTTPS</th>
                <th>State</th>
                <th>SSL mode</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {domains.map((d) => (
                <tr key={d.domain}>
                  <td><b>{d.domain}</b></td>
                  {session.role === 'admin' && <td>{d.owner}</td>}
                  <td>{d.webroot}</td>
                  <td><span className="status"><i />Enabled</span></td>
                  <td><span className="status">{d.suspended ? 'Suspended' : 'Active'}</span></td>
                  <td>
                    <select defaultValue={d.ssl_mode || 'disabled'} onChange={(e) => act(d.domain, 'ssl', { mode: e.target.value })}>
                      <option value="disabled">Disabled</option>
                      <option value="self">Self cert</option>
                      <option value="letsencrypt">Let's Encrypt</option>
                    </select>
                  </td>
                  <td>{d.created_at}</td>
                  <td>
                    {session.role === 'admin' && (
                      <>
                        <button className="secondary" onClick={() => act(d.domain, d.suspended ? 'unsuspend' : 'suspend')} disabled={busy === `${d.domain}-${d.suspended ? 'unsuspend' : 'suspend'}`}>
                          {d.suspended ? 'Unsuspend' : 'Suspend'}
                        </button>
                        <button className="secondary" onClick={() => act(d.domain, 'delete')} disabled={busy === `${d.domain}-delete`}>Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!domains.length && <div className="empty">No websites yet.</div>}
        </div>
      </section>
      {!!domains.length && <section className="table-area"><div className="tools-panel"><header><div><h2>HTTP redirects</h2><p>Send an exact path on a website to another secure web address. Nginx is validated and reloaded automatically.</p></div><select value={redirectDomain} onChange={(event) => setRedirectDomain(event.target.value)}>{domains.map((item) => <option key={item.domain}>{item.domain}</option>)}</select></header><form className="package-form" onSubmit={addRedirect}><label>Source path<input value={redirectForm.source_path} placeholder="/old-page" onChange={(event) => setRedirectForm((current) => ({ ...current, source_path:event.target.value }))} required /></label><label>Destination URL<input type="url" value={redirectForm.target_url} placeholder="https://example.com/new-page" onChange={(event) => setRedirectForm((current) => ({ ...current, target_url:event.target.value }))} required /></label><label>Redirect type<select value={redirectForm.status_code} onChange={(event) => setRedirectForm((current) => ({ ...current, status_code:event.target.value }))}><option value="301">301 Permanent</option><option value="302">302 Temporary</option><option value="307">307 Temporary (preserve method)</option><option value="308">308 Permanent (preserve method)</option></select></label><button className="primary" disabled={busy === 'redirect-create'}>{busy === 'redirect-create' ? 'Applying…' : 'Add redirect'}</button></form><div className="task-list">{redirects.map((item) => <article key={item.id}><code>{item.source_path}</code><span>→</span><code>{item.target_url}</code><strong>{item.status_code}</strong><button className="secondary danger" disabled={busy === `redirect-${item.id}`} onClick={() => removeRedirect(item)}>Delete</button></article>)}{!redirects.length && <div className="empty">No redirects configured for this website.</div>}</div></div></section>}
      {open && <CreateWebsite session={session} users={users} onClose={() => setOpen(false)} onDone={() => { setOpen(false); load(); }} />}
    </>
  );
}

function InstallWordPress({ session, domains, application, onClose, onDone }) {
  const [f, setF] = useState({ domain: domains[0]?.domain || '', title: '', admin_user: '', admin_email: '', admin_password: '', confirm_password: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function change(e) { setF({ ...f, [e.target.name]: e.target.value }); }
  async function submit(e) {
    e.preventDefault();
    if (f.admin_password !== f.confirm_password) { setError('Administrator passwords do not match.'); return; }
    setBusy(true); setError('');
    try {
      await api(`/apps/install/${application?.slug || 'wordpress'}`, { method: 'POST', csrf: session.csrf, body: JSON.stringify(f) });
      onDone();
    } catch (x) { setError(x.message); } finally { setBusy(false); }
  }
  return (
    <Drawer title={`Install ${application?.name || 'WordPress'}`} onClose={onClose}>
      <form onSubmit={submit}>
        <div className="app-drawer-summary"><div className={`app-logo ${application?.slug}`}>{application?.icon}</div><span><b>{application?.name}</b><small>{application?.summary}</small></span></div>
        <div className="app-install-note"><b>Fresh website required</b><span>The installer provisions isolated PHP, a private database and HTTPS, then replaces the placeholder page.</span></div>
        <label>Website<select name="domain" value={f.domain} onChange={change} required>{domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}{session.role === 'admin' ? ` · ${d.owner}` : ''}</option>)}</select></label>
        <label>Site title<input name="title" value={f.title} onChange={change} placeholder="My company" required maxLength="120" /></label>
        <label>Administrator username<input name="admin_user" value={f.admin_user} onChange={change} autoComplete="off" required minLength="3" maxLength="60" /></label>
        <label>Administrator email<input name="admin_email" type="email" value={f.admin_email} onChange={change} required /></label>
        <label>Administrator password<input name="admin_password" type="password" value={f.admin_password} onChange={change} autoComplete="new-password" required minLength="12" /></label>
        <label>Confirm password<input name="confirm_password" type="password" value={f.confirm_password} onChange={change} autoComplete="new-password" required minLength="12" /></label>
        <dl className="app-install-facts"><div><dt>Database</dt><dd>Created automatically</dd></div><div><dt>PHP</dt><dd>Isolated PHP 8.3 pool</dd></div><div><dt>Requirements</dt><dd>{application?.requirements || 'PHP 8.3 · MariaDB'}</dd></div><div><dt>HTTPS</dt><dd>Enabled with a temporary certificate</dd></div></dl>
        {error && <div className="form-error">{error}</div>}
        <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Installing…' : `Install ${application?.name || 'WordPress'}`}</button></footer>
      </form>
    </Drawer>
  );
}

function Applications({ session }) {
  const [apps, setApps] = useState([]);
  const [domains, setDomains] = useState([]);
  const [open, setOpen] = useState(false);
  const [catalog, setCatalog] = useState([]);
  const [selectedApp, setSelectedApp] = useState(null);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('All');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(null);
  const load = () => api('/apps').then((data) => { const nextCatalog=asArray(data?.catalog); setApps(asArray(data?.apps)); setDomains(asArray(data?.available_domains)); setCatalog(nextCatalog); setSelectedApp((current) => current || nextCatalog[0] || null); }).catch((x) => setError(x.message));
  useEffect(() => { load(); }, []);
  async function act(item, action) {
    setBusy(`${item.id}-${action}`); setError('');
    try { await api(`/apps/${item.id}/action`, { method: 'POST', csrf: session.csrf, body: JSON.stringify({ action }) }); await load(); }
    catch (x) { setError(x.message); } finally { setBusy(null); }
  }
  async function openAsAdministrator(item) {
    const popup = window.open('about:blank', '_blank');
    setBusy(`${item.id}-impersonate`); setError('');
    try {
      const result = await api(`/apps/${item.id}/impersonate`, { method: 'POST', csrf: session.csrf, body: '{}' });
      if (popup) popup.location.replace(result.launch_url); else window.location.assign(result.launch_url);
    } catch (x) {
      if (popup) popup.close();
      setError(x.message);
    } finally { setBusy(null); }
  }
  const categories = ['All', ...new Set(catalog.map((item) => item.category))];
  const visibleCatalog = catalog.filter((item) => (category === 'All' || item.category === category) && `${item.name} ${item.summary} ${item.category}`.toLowerCase().includes(search.trim().toLowerCase()));
  const chooseApplication = (item) => { setSelectedApp(item); setOpen(true); };
  return (
    <>
      <header className="page-header app-page-header"><div><h1>App Installer</h1><p>Deploy and manage popular self-hosted applications.</p></div><button className="primary" onClick={() => chooseApplication(catalog[0])} disabled={!domains.length || !catalog.length}>Install application</button></header>
      {error && <div className="form-error">{error}</div>}
      <section className="app-catalog-toolbar"><label className="search-box"><span>⌕</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search applications…" /></label><div className="app-categories">{categories.map((item) => <button key={item} className={`app-category ${category === item ? 'active' : ''}`} onClick={() => setCategory(item)}>{item}</button>)}</div></section>
      {category === 'All' && !search && catalog.find((item) => item.featured) && (() => { const item=catalog.find((entry) => entry.featured); return <section className="featured-application"><div className={`app-logo ${item.slug}`}>{item.icon}</div><div><small className="featured-kicker">Featured application</small><h2>{item.name}</h2><p>{item.summary}</p><span className="app-requirements">{item.requirements}</span></div><button className="primary" onClick={() => chooseApplication(item)} disabled={!domains.length}>Install</button></section>; })()}
      <section className="app-catalog-table"><header className="app-catalog-head"><span>Application</span><span>Category</span><span>Description</span><span>Requirements</span><span>Action</span></header>
        {visibleCatalog.map((item) => <article className="app-catalog-row" key={item.slug}><span className="app-table-name"><i className={`app-logo ${item.slug} small`}>{item.icon}</i><b>{item.name}</b></span><span className="app-category-badge">{item.category}</span><p className="app-catalog-description">{item.summary}</p><span className="app-requirements">{item.requirements}</span><button className="secondary" onClick={() => chooseApplication(item)} disabled={!domains.length}>Install</button></article>)}
        {!visibleCatalog.length && <div className="empty">No applications match this search.</div>}
      </section>
      <section className="table-area installed-apps"><div className="section-heading"><div><h2>Installed applications</h2><p>{apps.length} managed installation{apps.length === 1 ? '' : 's'}</p></div></div><div className="table-wrap"><table><thead><tr><th>Application</th><th>Website</th>{session.role === 'admin' && <th>Owner</th>}<th>Version</th><th>State</th><th>Installed</th><th></th></tr></thead><tbody>{apps.map((item) => <tr key={item.id}><td><span className="app-table-name"><i className={`app-logo ${item.application_slug || 'wordpress'} small`}>{item.catalog?.icon || 'W'}</i><b>{item.catalog?.name || 'Application'}</b></span></td><td><a href={`https://${item.domain}`} target="_blank" rel="noreferrer">{item.domain}</a></td>{session.role === 'admin' && <td>{item.owner}</td>}<td>{item.version}</td><td><span className="status"><i />{item.maintenance ? 'Maintenance' : 'Active'}</span></td><td>{item.installed_at}</td><td className="app-actions">{item.catalog?.engine === 'wordpress' ? <button className="secondary" disabled={busy === `${item.id}-impersonate`} onClick={() => openAsAdministrator(item)}>{busy === `${item.id}-impersonate` ? 'Opening…' : 'Open admin'}</button> : <a className="secondary" href={`https://${item.domain}${item.catalog?.admin_path || '/'}`} target="_blank" rel="noreferrer">Open admin</a>}{item.catalog?.engine !== 'joomla' && <><button className="secondary" disabled={busy === `${item.id}-update`} onClick={() => act(item, 'update')}>Update</button><button className="secondary" disabled={busy?.startsWith(`${item.id}-`)} onClick={() => act(item, item.maintenance ? 'maintenance_off' : 'maintenance_on')}>{item.maintenance ? 'Go live' : 'Maintenance'}</button></>}</td></tr>)}</tbody></table>{!apps.length && <div className="empty">No applications installed yet. Choose a fresh website from the catalog.</div>}</div></section>
      {open && selectedApp && <InstallWordPress session={session} domains={domains} application={selectedApp} onClose={() => setOpen(false)} onDone={() => { setOpen(false); load(); }} />}
    </>
  );
}

function CreateDnsRecord({ session, domains, onClose, onDone }) {
  const [f, setF] = useState({ domain: domains[0]?.domain || '', type: 'A', name: '@', value: '', ttl: '3600' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function change(e) { setF({ ...f, [e.target.name]: e.target.value }); }
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const result = await api('/dns', { method: 'POST', csrf: session.csrf, body: JSON.stringify({ ...f, ttl: Number(f.ttl) }) });
      onDone(result);
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Drawer title="Add DNS record" onClose={onClose}>
      <form onSubmit={submit}>
        <label>
          Hosted DNS zone
          <select name="domain" value={f.domain} onChange={change} required>
            {domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}</option>)}
          </select>
        </label>
        <label>
          Type
          <select name="type" value={f.type} onChange={change}>
            <option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option><option>SPF</option><option>SRV</option>
          </select>
        </label>
        <label>
          Host in this zone
          <input name="name" value={f.name} onChange={change} required />
          <small className="field-help">Use @ for the zone itself, or enter only the relative host name.</small>
        </label>
        <label>
          Value
          <textarea rows="2" name="value" value={f.value} onChange={change} required />
        </label>
        <label>
          TTL
          <select name="ttl" value={f.ttl} onChange={change}>
            <option value="60">60</option><option value="300">300</option><option value="3600">3600</option><option value="86400">86400</option>
          </select>
        </label>
        {error && <div className="form-error">{error}</div>}
        <footer>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save record'}</button>
        </footer>
      </form>
    </Drawer>
  );
}

function DnsManager({ session }) {
  const [records, setRecords] = useState([]);
  const [domains, setDomains] = useState([]);
  const [dnsZones, setDnsZones] = useState([]);
  const [open, setOpen] = useState(false);
  const [cloudflareOpen, setCloudflareOpen] = useState(false);
  const [cloudflareToken, setCloudflareToken] = useState('');
  const [cloudflareAccountId, setCloudflareAccountId] = useState('');
  const [cloudflareLabel, setCloudflareLabel] = useState('');
  const [cloudflareConnections, setCloudflareConnections] = useState([]);
  const [cloudflareConnected, setCloudflareConnected] = useState(false);
  const [selected, setSelected] = useState('');
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [serviceDomains, setServiceDomains] = useState(null);
  const [dnsServer, setDnsServer] = useState(null);

  const load = () => Promise.all([api('/dns'), api('/domains'), api('/mail/domains'), api('/service-domains/status'), api('/dns/server')])
    .then(([d, z, m, s, authoritative]) => { const next = asArray(m?.domains); setRecords(asArray(d?.records)); setDnsZones(asArray(z?.domains)); setDomains(next); setServiceDomains(s); setDnsServer(authoritative); setSelected((current) => next.some((item) => item.domain === current) ? current : next[0]?.domain || ''); })
    .catch((x) => setError(x.message));

  useEffect(() => {
    load();
    if (session.role === 'admin') api('/integrations/cloudflare').then((r) => { setCloudflareConnected(!!r.connected); setCloudflareConnections(asArray(r.connections)); }).catch(() => {});
  }, []);

  function cloudflareResult(result, localMessage) {
    const sync = result?.cloudflare;
    if (!sync || sync.status === 'not_connected' || sync.status === 'skipped') {
      setNotice(`${localMessage} Connect Cloudflare to enable automatic public DNS updates.`);
    } else if (sync.status === 'failed') {
      setError(`${localMessage} Cloudflare auto-sync failed: ${sync.error}. Use Sync now to retry.`);
    } else {
      setNotice(`${localMessage} Cloudflare updated automatically (${sync.records_synced || 0} applied, ${sync.records_deleted || 0} removed).`);
    }
  }

  async function remove(id) {
    setError(''); setNotice('');
    try {
      const result = await api(`/dns/${id}`, { method: 'DELETE', csrf: session.csrf });
      cloudflareResult(result, 'DNS record deleted locally.');
      await load();
    } catch (x) { setError(x.message); }
  }

  async function generateMailDns() {
    if (!selected) return;
    setBusy('generate'); setError(''); setNotice('');
    try {
      const result = await api('/dns/mail-plan', { method:'POST', csrf:session.csrf, body:JSON.stringify({ domain:selected }) });
      const targetZone = domains.find((item) => item.domain === selected)?.dns_parent || selected;
      cloudflareResult(result, `${result.records.length} required mail and groupware records generated in DNS zone ${targetZone}. DKIM signing is active with selector ${result.selector}.`);
      await load();
    } catch (x) { setError(x.message); } finally { setBusy(''); }
  }

  async function connectCloudflare(e) {
    e.preventDefault(); setBusy('connect'); setError('');
    try {
      const result = await api('/integrations/cloudflare', { method:'POST', csrf:session.csrf, body:JSON.stringify({ token:cloudflareToken, account_id:cloudflareAccountId, label:cloudflareLabel }) });
      const failures = asArray(result.reconciled).filter((item) => item.status === 'failed');
      setCloudflareConnected(true); setCloudflareConnections(asArray(result.connections)); setCloudflareToken(''); setCloudflareAccountId(''); setCloudflareLabel('');
      setNotice(failures.length ? `Cloudflare account added, but ${failures.length} zone${failures.length === 1 ? '' : 's'} need a retry.` : 'Cloudflare account added. Matching zones now synchronize automatically.');
    } catch (x) { setError(x.message); } finally { setBusy(''); }
  }

  async function disconnectCloudflare(connectionId) {
    setBusy(`remove-${connectionId}`); setError('');
    try {
      const result = await api(`/integrations/cloudflare/${connectionId}`, { method:'DELETE', csrf:session.csrf });
      setCloudflareConnections(asArray(result.connections)); setCloudflareConnected(!!result.connected);
      setNotice('Cloudflare connection removed. Other connected accounts remain active.');
    } catch (x) { setError(x.message); } finally { setBusy(''); }
  }

  async function syncCloudflare() {
    if (!selected) return;
    setBusy('sync'); setError(''); setNotice('');
    try {
      const result = await api('/dns/cloudflare-sync', { method:'POST', csrf:session.csrf, body:JSON.stringify({ domain:selected }) });
      setNotice(`${result.records_synced} records synchronized with Cloudflare zone ${result.zone}; ${result.records_deleted || 0} stale managed records removed.`);
    } catch (x) { setError(x.message); } finally { setBusy(''); }
  }

  const emailDomains = domains;
  const selectedEmailDomain = emailDomains.find((domain) => domain.domain === selected);
  const selectedDnsZone = selectedEmailDomain?.dns_parent || selected;
  const visibleRecords = selected ? records.filter((record) => record.mail_domain === selected || (!record.mail_domain && record.domain === selected)) : [];
  const purposes = { '@|MX':'Incoming mail', '@|TXT':'SPF sender policy', 'mail._domainkey|TXT':'DKIM signature', '_dmarc|TXT':'DMARC policy', 'autodiscover|CNAME':'Outlook autodiscover', 'autoconfig|CNAME':'Automatic client setup', '_autodiscover._tcp|SRV':'Groupware discovery' };
  const recordPurpose = (record) => {
    if (record.type === 'MX') return 'Incoming mail';
    if (record.type === 'TXT' && record.value.startsWith('v=spf1')) return 'SPF sender policy';
    if (record.name.includes('_domainkey')) return 'DKIM signature';
    if (record.name.includes('_dmarc')) return 'DMARC policy';
    if (record.name.includes('autodiscover')) return 'Outlook and groupware discovery';
    if (record.name.includes('autoconfig')) return 'Automatic client setup';
    return purposes[`${record.name}|${record.type}`] || 'Custom record';
  };
  const requirements = [
    ['MX', visibleRecords.some((r) => r.type === 'MX')],
    ['SPF', visibleRecords.some((r) => r.type === 'TXT' && r.value.startsWith('v=spf1'))],
    ['DKIM', visibleRecords.some((r) => r.type === 'TXT' && r.name.includes('mail._domainkey'))],
    ['DMARC', visibleRecords.some((r) => r.type === 'TXT' && r.name.includes('_dmarc'))],
    ['Autodiscover', visibleRecords.some((r) => (r.name.includes('autodiscover') || r.name.includes('autoconfig')))],
  ];

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Domains &amp; DNS</h1>
          <p>Manage website and mail records. Connected Cloudflare zones update automatically after every DNS change.</p>
        </div>
        <button className="primary" onClick={() => setOpen(true)} disabled={!dnsZones.length}>Add record</button>
      </header>
      <section className="table-area">
        {error && <div className="form-error">{error}</div>}
        {notice && <div className="notice">{notice}</div>}
        {dnsServer && <div className="dns-authoritative-card"><div><i><PanelIcon name="dns" size={26} /></i><span><small>Authoritative DNS</small><b>{dnsServer.engine}</b></span></div><div><small>Service</small><b className={dnsServer.active && dnsServer.listening ? 'status-pass' : 'status-warn'}>{dnsServer.active && dnsServer.listening ? 'Online · TCP/UDP 53' : 'Needs attention'}</b></div><div><small>Hosted zones</small><b>{dnsServer.zone_count}</b></div><div><small>Primary nameserver</small><b className={dnsServer.primary_ready ? 'status-pass' : 'status-warn'}>{dnsServer.primary_ns || 'Configure the panel URL'}</b></div><div><small>Secondary nameserver</small><b className={dnsServer.secondary_ready ? 'status-pass' : 'status-warn'}>{dnsServer.secondary_ns || 'Configure the panel URL'}</b></div></div>}
        {serviceDomains && <div className="service-domain-strip">
          <div><i><PanelIcon name="dns" size={24} /></i><section><small>Panel domain</small><b>{serviceDomains.panel_hostname || 'Not configured'}</b><span className={serviceDomains.checks?.panel_a ? 'status-pass' : 'status-warn'}>{serviceDomains.checks?.panel_a ? 'Points to this server' : 'Choose a domain in Settings'}</span></section></div>
          <div><i><PanelIcon name="email" size={24} /></i><section><small>Mail server</small><b>{serviceDomains.mail_hostname || 'Not configured'}</b><span className={serviceDomains.checks?.mail_a ? 'status-pass' : 'status-warn'}>{serviceDomains.checks?.mail_a ? 'Ready for customer mail' : `Must point to ${serviceDomains.server_ip}`}</span></section></div>
          <div><i><PanelIcon name="ssl" size={24} /></i><section><small>Reverse DNS</small><b>{serviceDomains.ptr?.[0] || 'Missing'}</b><span className={serviceDomains.checks?.mail_ptr ? 'status-pass' : 'status-warn'}>{serviceDomains.checks?.mail_ptr ? 'Matches mail server' : 'Ask the IP provider to correct it'}</span></section></div>
        </div>}
        {serviceDomains?.warnings?.map((warning) => <div className="form-error" key={warning}>{warning}</div>)}
        <div className="dns-workspace-heading"><div><h2>Email domain DNS</h2><p>Hosted domains and mail-only subdomains can both receive email. A subdomain's records are stored in its parent hosted DNS zone.</p></div><div className="dns-connection-note">Selected email domain: <b>{selected || 'None'}</b><br />DNS zone: <b>{selectedDnsZone || 'None'}</b><br />Mail server: <b>{serviceDomains?.mail_hostname || 'Not configured'}</b></div></div>
        {selectedDnsZone && dnsServer && <div className="notice">At the registrar, delegate <b>{selectedDnsZone}</b> to <b>{dnsServer.primary_ns}</b> and <b>{dnsServer.secondary_ns}</b>. The nameserver A records at the panel's base domain must be DNS-only and point to <b>{dnsServer.server_ip}</b>. The second nameserver currently shares this server; use another server and IP later for production redundancy.</div>}
        <div className="dns-toolbar">
          <label><span>Email domain</span><select value={selected} onChange={(e) => setSelected(e.target.value)} disabled={!emailDomains.length}>{emailDomains.length ? emailDomains.map((domain) => <option key={domain.domain} value={domain.domain}>{domain.domain}{domain.mail_only ? ` · mail-only · DNS ${domain.dns_parent}` : ' · hosted domain'}{session.role === 'admin' ? ` · ${domain.owner}` : ''}</option>) : <option>No email domains configured</option>}</select></label>
          <button className="primary" onClick={generateMailDns} disabled={!selected || !!busy}>{busy === 'generate' ? 'Generating…' : 'Generate required records'}</button>
          {session.role === 'admin' && <button className="secondary cloudflare-button" onClick={() => setCloudflareOpen(true)}>{cloudflareConnected ? `${cloudflareConnections.length} Cloudflare connection${cloudflareConnections.length === 1 ? '' : 's'}` : 'Connect Cloudflare'}</button>}
          {session.role === 'admin' && cloudflareConnected && <button className="primary" onClick={syncCloudflare} disabled={!selected || !!busy}>{busy === 'sync' ? 'Syncing…' : 'Sync now'}</button>}
        </div>
        {!emailDomains.length && <div className="form-error">Add a website first. Its domain becomes available for email automatically, and you can add mail-only subdomains from the Email page.</div>}
        <div className="mail-dns-guide">{requirements.map(([label, ready]) => <span key={label} className={ready ? 'requirement-ready' : ''}><b>{ready ? '✓' : '○'}</b>{label}<small>{ready ? 'OK' : 'Needed'}</small></span>)}</div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Type</th><th>Host in zone</th><th>Value</th><th>Purpose</th><th>DNS zone</th><th>TTL</th><th></th></tr>
            </thead>
            <tbody>
              {visibleRecords.map((r) => (
                <tr key={r.id}>
                  <td><b>{r.type}</b></td>
                  <td>{r.name}</td>
                  <td className="dns-value">{r.value}</td>
                  <td>{recordPurpose(r)}</td>
                  <td>{r.domain}</td>
                  <td>{r.ttl}</td>
                  <td><button className="secondary" onClick={() => remove(r.id)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!visibleRecords.length && <div className="empty">No records yet. Generate the required mail records or add one manually.</div>}
        </div>
      </section>
      {open && <CreateDnsRecord session={session} domains={dnsZones} onClose={() => setOpen(false)} onDone={(result) => { setOpen(false); cloudflareResult(result, 'DNS record saved locally.'); load(); }} />}
      {cloudflareOpen && <Drawer title="Cloudflare connections" onClose={() => setCloudflareOpen(false)}><form onSubmit={connectCloudflare} className="cloudflare-connection-form"><p className="field-help">Add one connection for each Cloudflare account. Use a token with Zone Read and DNS Write. For account-owned tokens, the Account ID is required; standard user API tokens can leave it blank.</p>{cloudflareConnections.length > 0 && <section className="cloudflare-connections"><h3>Connected accounts</h3>{cloudflareConnections.map((connection) => <article key={connection.id}><span><b>{connection.label}</b><small>{connection.account_name || (connection.token_type === 'account' ? `Account …${connection.account_id.slice(-6)}` : 'User API token')} · {asArray(connection.zones).length} visible zone{asArray(connection.zones).length === 1 ? '' : 's'}</small></span><button type="button" className="secondary" disabled={busy === `remove-${connection.id}`} onClick={() => disconnectCloudflare(connection.id)}>{busy === `remove-${connection.id}` ? 'Removing…' : 'Remove'}</button></article>)}</section>}<h3>Add another account</h3><label>Connection name<input autoComplete="off" value={cloudflareLabel} onChange={(e) => setCloudflareLabel(e.target.value)} placeholder="Main Cloudflare account" maxLength="80" /></label><label>Account ID <small>Required for account-owned tokens beginning with cfat_</small><input autoComplete="off" value={cloudflareAccountId} onChange={(e) => setCloudflareAccountId(e.target.value.trim())} placeholder="32-character Account ID" minLength="32" maxLength="32" /></label><label>API token<input type="password" autoComplete="new-password" value={cloudflareToken} onChange={(e) => setCloudflareToken(e.target.value)} required minLength="20" /></label><footer><button type="button" className="secondary" onClick={() => setCloudflareOpen(false)}>Close</button><button className="primary" disabled={busy === 'connect'}>{busy === 'connect' ? 'Verifying…' : 'Add connection'}</button></footer></form></Drawer>}
    </>
  );
}

function FileEditor({ session, item, onClose, onSaved }) {
  const [content, setContent] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [encoding, setEncoding] = useState('');
  const [readOnly, setReadOnly] = useState(false);

  useEffect(() => {
    setBusy(true);
    setError('');
    api(`/files/content?domain=${encodeURIComponent(item.domain)}&path=${encodeURIComponent(item.path)}`)
      .then((d) => {
        setContent(d?.content || '');
        setEncoding(d?.encoding || 'utf-8');
        setReadOnly(!!d?.is_binary);
      })
      .catch((x) => {
        setError(x.message);
        setReadOnly(true);
      })
      .finally(() => setBusy(false));
  }, [item.domain, item.path]);

  async function save() {
    if (readOnly) return;
    setBusy(true);
    setError('');
    try {
      await api('/files', {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({ action: 'write_file', domain: item.domain, path: item.path, content }),
      });
      onSaved();
      onClose();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer title={`Edit ${item.name}`} onClose={onClose}>
      <div style={{ padding: '0 30px 20px' }}>
        <p className="form-error" style={{ marginTop: 0 }}>{`${item.path}`}</p>
        <p style={{ margin: '0 0 14px', color: '#647083', fontSize: 13 }}>Encoding: {encoding || 'unknown'} {readOnly ? ' (read-only)' : ''}</p>
        {error && <div className="form-error">{error}</div>}
      </div>
      <textarea
        value={busy ? 'Loading…' : content}
        onChange={(e) => setContent(e.target.value)}
        rows={20}
        disabled={busy || readOnly}
        style={{ margin: '0 30px', width: 'calc(100% - 60px)', minHeight: '50vh', border: '1px solid #ccd5e0', borderRadius: 4, padding: '10px', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace' }}
      />
      <footer>
        <button type="button" className="secondary" onClick={onClose}>Close</button>
        <button className="primary" disabled={busy || readOnly} onClick={save}>{busy ? 'Saving…' : 'Save file'}</button>
      </footer>
    </Drawer>
  );
}

function Files({ session }) {
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [path, setPath] = useState('');
  const [data, setData] = useState({ domain: '', path: '', root: '', parent: '', items: [] });
  const [editor, setEditor] = useState(null);
  const [error, setError] = useState('');
  const [uploading, setUploading] = useState(false);
  const uploadInput = useRef(null);

  useEffect(() => {
    api('/domains')
      .then((d) => {
        const rows = asArray(d?.domains);
        setDomains(rows);
        if (!selectedDomain && rows[0]) setSelectedDomain(rows[0].domain);
      })
      .catch((x) => setError(x.message));
  }, []);

  const reload = () => {
    if (!selectedDomain) return;
    setError('');
    const params = new URLSearchParams({ domain: selectedDomain, path });
    api(`/files?${params}`)
      .then((d) => setData({ ...d, items: asArray(d?.items) }))
      .catch((x) => setError(x.message));
  };

  useEffect(() => {
    reload();
  }, [selectedDomain, path]);

  function setDomain(d) {
    setSelectedDomain(d);
    setPath('');
    setError('');
  }

  function goToChild(itemName) {
    setPath(joinPath(path, itemName));
  }

  function goUp() {
    if (data.parent) setPath(data.parent);
  }

  async function createFolder() {
    const name = window.prompt('Folder name');
    if (!name) return;
    setError('');
    try {
      await api('/files', {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({ domain: selectedDomain, path: joinPath(path, name), action: 'mkdir' }),
      });
      reload();
    } catch (x) {
      setError(x.message);
    }
  }

  async function createFile() {
    const name = window.prompt('File name');
    if (!name) return;
    setError('');
    try {
      await api('/files', {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({ domain: selectedDomain, path: joinPath(path, name), action: 'create_file', content: '' }),
      });
      reload();
      setEditor({ domain: selectedDomain, path: joinPath(path, name), name });
    } catch (x) {
      setError(x.message);
    }
  }

  async function uploadFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file || !selectedDomain) return;
    setUploading(true);
    setError('');
    const body = new FormData();
    body.append('domain', selectedDomain);
    body.append('path', path);
    body.append('file', file, file.name);
    try {
      await api('/files/upload', { method: 'POST', csrf: session.csrf, body });
      reload();
    } catch (x) {
      setError(x.message);
    } finally {
      setUploading(false);
    }
  }

  async function renameItem(item) {
    const fresh = window.prompt('New name', item.name);
    if (!fresh || fresh === item.name) return;
    setError('');
    try {
      await api('/files', {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({ domain: selectedDomain, path: joinPath(path, item.name), action: 'rename', new_name: fresh }),
      });
      reload();
    } catch (x) {
      setError(x.message);
    }
  }

  async function deleteItem(item) {
    if (!window.confirm(`Delete ${item.name}?`)) return;
    setError('');
    try {
      await api('/files', {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({ domain: selectedDomain, path: joinPath(path, item.name), action: 'delete' }),
      });
      reload();
    } catch (x) {
      setError(x.message);
    }
  }

  function openItem(item) {
    if (item.type === 'dir') {
      return goToChild(item.name);
    }
    setEditor({ domain: selectedDomain, path: joinPath(path, item.name), name: item.name });
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Files</h1>
          <p>Browse and edit domain files in a lightweight file manager.</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <input ref={uploadInput} type="file" hidden onChange={uploadFile} />
          <button className="secondary" disabled={!selectedDomain || uploading} onClick={() => uploadInput.current?.click()}>
            {uploading ? 'Uploading…' : 'Upload'}
          </button>
          <button className="secondary" disabled={!selectedDomain} onClick={createFolder}>New folder</button>
          <button className="secondary" disabled={!selectedDomain} onClick={createFile}>New file</button>
        </div>
      </header>
      <section className="table-area">
        {error && <div className="form-error">{error}</div>}
        {!domains.length && (
          <div className="empty-state-card">
            <PanelIcon name="files" size={28} />
            <h2>No website files yet</h2>
            <p>Create a website first. Its document root will then appear here automatically for browsing, uploads and editing.</p>
          </div>
        )}
        {!!domains.length && <>
        <div style={{ padding: '0 0 14px', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <label style={{ display: 'grid', gap: 6 }}>
            <small style={{ color: '#647083', fontSize: 12 }}>Domain</small>
            <select value={selectedDomain} onChange={(e) => setDomain(e.target.value)}>
              {domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}</option>)}
            </select>
          </label>
          <label style={{ display: 'grid', gap: 6, minWidth: 240 }}>
            <small style={{ color: '#647083', fontSize: 12 }}>Path</small>
            <input
              value={path || '/'}
              readOnly
              aria-label="Current folder"
            />
          </label>
          <button className="secondary" onClick={() => reload()}>Refresh</button>
          {data.parent && <button className="secondary" onClick={goUp}>Up</button>}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Item</th><th>Type</th><th>Size</th><th>Modified</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {data.items.map((item) => (
                <tr key={item.name}>
                  <td>
                    <button className="secondary" style={{ border: '0', padding: 0 }} onClick={() => openItem(item)}>{item.name}</button>
                  </td>
                  <td>{item.type}</td>
                  <td>{item.size || 0}</td>
                  <td>{item.mtime}</td>
                  <td>
                    <button className="secondary" onClick={() => renameItem(item)}>Rename</button>
                    <button className="secondary" onClick={() => deleteItem(item)}>Delete</button>
                    {item.type === 'file' && <a className="secondary" href={`/api/files/download?domain=${encodeURIComponent(selectedDomain)}&path=${encodeURIComponent(joinPath(path, item.name))}`}>Download</a>}
                    {item.type === 'file' && <button className="secondary" onClick={() => openItem(item)}>Edit</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data.items.length && <div className="empty">No files or directories.</div>}
        </div>
        </>}
      </section>
      {editor && <FileEditor session={session} item={editor} onClose={() => setEditor(null)} onSaved={() => reload()} />}
    </>
  );
}

function Databases({ session }) {
  const [rows, setRows] = useState([]);
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [form, setForm] = useState({ domain: '', name: '' });
  const [editor, setEditor] = useState({ database: null, sql: 'SELECT name FROM sqlite_master LIMIT 20;' });
  const [queryResult, setQueryResult] = useState([]);
  const [queryError, setQueryError] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState('');

  const load = () => {
    Promise.all([api('/databases'), api('/domains')])
      .then(([d, m]) => {
        const dbRows = asArray(d?.databases);
        const domRows = asArray(m?.domains);
        setRows(dbRows);
        setDomains(domRows);
        if (!selectedDomain && domRows[0]) {
          const firstDomain = domRows[0].domain;
          setSelectedDomain(firstDomain);
          setForm((f) => ({ ...f, domain: firstDomain }));
        }
      })
      .catch((x) => setError(x.message));
  };
  useEffect(() => { load(); }, []);

  const filtered = selectedDomain ? rows.filter((r) => r.domain === selectedDomain) : rows;

  async function createDatabase(e) {
    e.preventDefault();
    setError('');
    setBusy('create');
    try {
      const fd = {
        domain: form.domain || selectedDomain,
        name: form.name.trim(),
      };
      if (!fd.domain || !fd.name) throw new Error('Both domain and name are required.');
      await api('/databases', { method: 'POST', csrf: session.csrf, body: JSON.stringify(fd) });
      setForm((p) => ({ ...p, name: '' }));
      await load();
      setBusy(null);
    } catch (x) {
      setBusy(null);
      setError(x.message);
    }
  }

  async function removeDatabase(database) {
    if (!window.confirm(`Delete ${database.domain}/${database.name}?`)) return;
    setBusy(`delete-${database.id}`);
    try {
      await api(`/databases/${database.id}`, { method: 'DELETE', csrf: session.csrf });
      await load();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(null);
    }
  }

  async function runQuery(database) {
    setBusy(`query-${database.id}`);
    setQueryError('');
    setQueryResult([]);
    try {
      const d = await api(`/databases/${database.id}/query`, {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({ sql: editor.sql }),
      });
      setEditor((p) => ({ ...p, database }));
      setQueryResult(asArray(d?.rows));
    } catch (x) {
      setQueryError(x.message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Databases</h1>
          <p>Manage lightweight SQLite databases per domain.</p>
        </div>
      </header>
      <section className="table-area">
        {error && <div className="form-error">{error}</div>}
        <div style={{ padding: '0 0 14px', display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <label style={{ display: 'grid', gap: 6, minWidth: 220 }}>
            <small style={{ color: '#647083', fontSize: 12 }}>Domain</small>
            <select
              value={selectedDomain}
              onChange={(e) => {
                const next = e.target.value;
                setSelectedDomain(next);
                setForm((p) => ({ ...p, domain: next }));
              }}
            >
              {domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}</option>)}
            </select>
          </label>
          <form onSubmit={createDatabase} style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
            <label style={{ display: 'grid', gap: 6 }}>
              <small style={{ color: '#647083', fontSize: 12 }}>Database name</small>
              <input
                value={form.name}
                placeholder="example_db"
                required
                onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              />
            </label>
            <button className="secondary" disabled={busy === 'create'}>{busy === 'create' ? 'Creating…' : 'Create database'}</button>
          </form>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Database</th><th>Domain</th><th>Owner</th><th>Created</th><th>Creator</th><th>Path</th><th></th></tr>
            </thead>
            <tbody>
              {filtered.map((database) => (
                <tr key={database.id}>
                  <td><b>{database.name}</b></td>
                  <td>{database.domain}</td>
                  <td>{database.owner}</td>
                  <td>{database.created_at}</td>
                  <td>{database.created_by}</td>
                  <td>{database.path}</td>
                  <td>
                    <button className="secondary" onClick={() => runQuery(database)} disabled={busy === `query-${database.id}`}>
                      {busy === `query-${database.id}` ? 'Running…' : 'Run query'}
                    </button>
                    <button className="secondary" onClick={() => removeDatabase(database)} disabled={busy === `delete-${database.id}`}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && <div className="empty">No databases found for this domain.</div>}
        </div>
      </section>

      <section className="table-area">
        <header className="page-header" style={{ padding: 0, marginBottom: 12 }}>
          <div>
            <h2>SQL query</h2>
            <p>Runs only SELECT statements.</p>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <input
              value={editor.database ? `${editor.database.domain}/${editor.database.name}` : 'Select a database to run a query'}
              readOnly
              style={{ minWidth: 300 }}
            />
            <button
              className="primary"
              disabled={!editor.database}
              onClick={() => editor.database && runQuery(editor.database)}
            >
              Run current SQL
            </button>
          </div>
        </header>
        <div className="table-wrap">
          {queryError && <div className="form-error">{queryError}</div>}
          <label>
            SQL
            <textarea
              rows={5}
              value={editor.sql}
              onChange={(e) => setEditor((p) => ({ ...p, sql: e.target.value }))}
            />
          </label>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table>
              <thead>
                <tr>
                  {queryResult[0] && Object.keys(queryResult[0]).map((col) => <th key={col}>{col}</th>)}
                </tr>
              </thead>
              <tbody>
                {queryResult.length === 0 ? (
                  <tr>
                    <td colSpan={queryResult[0] ? Object.keys(queryResult[0]).length || 1 : 1} className="empty">
                      No rows returned yet.
                    </td>
                  </tr>
                ) : (
                  queryResult.map((row, ridx) => (
                    <tr key={ridx}>
                      {Object.keys(row).map((col) => <td key={`${ridx}-${col}`}>{String(row[col] ?? '')}</td>)}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </>
  );
}

function CreateMailDomain({ session, users, onClose, onDone }) {
  const availableClients = users.filter((user) => user.panel_role === 'client' && user.panel_active !== false && Number(user.domain_count || 0) > 0);
  const [f, setF] = useState({ domain:'', owner:session.role === 'admin' ? (availableClients[0]?.username || '') : (session.system_username || '') });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault(); setBusy(true); setError('');
    try { await api('/mail/domains', { method:'POST', csrf:session.csrf, body:JSON.stringify(f) }); onDone(); }
    catch (x) { setError(x.message); } finally { setBusy(false); }
  }
  return <Drawer title="Add mail-only subdomain" onClose={onClose}><form onSubmit={submit}>
    <div className="mailbox-address-preview"><small>Email namespace</small><b>{f.domain || 'accounts.example.com'}</b><span>This creates a Grommunio email domain and maps its DNS records into the owned parent zone. It does not create a website.</span></div>
    <label>Mail-only subdomain<input name="domain" value={f.domain} onChange={(e) => setF({...f,domain:e.target.value})} placeholder="accounts.example.com" required /></label>
    {session.role === 'admin' && <label>Client<select name="owner" value={f.owner} onChange={(e) => setF({...f,owner:e.target.value})} required><option value="">Select a client with a website</option>{availableClients.map((u) => <option key={u.username} value={u.username}>{u.username}</option>)}</select></label>}
    <p className="field-help">The subdomain must sit below one of this client's hosted website domains. Its records are saved in that parent DNS zone, while its MX points to the central mail server.</p>
    {error && <div className="form-error">{error}</div>}
    <footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Adding…' : 'Add mail-only domain'}</button></footer>
  </form></Drawer>;
}

function strongMailboxPassword(length = 24) {
  const groups = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%*-_=+'];
  const all = groups.join('');
  const pick = (chars) => chars[crypto.getRandomValues(new Uint32Array(1))[0] % chars.length];
  const result = groups.map(pick);
  while (result.length < length) result.push(pick(all));
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result.join('');
}

function PasswordEditor({ value, onChange, required = false, placeholder = '' }) {
  const [visible, setVisible] = useState(false);
  const generate = () => onChange(strongMailboxPassword());
  return <div className="mail-password-editor"><input type={visible ? 'text' : 'password'} autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} minLength="12" required={required} placeholder={placeholder} /><div><button type="button" className="secondary" onClick={generate}>Generate strong password</button><button type="button" className="secondary" onClick={() => setVisible(!visible)}>{visible ? 'Hide' : 'Show'}</button><button type="button" className="secondary" disabled={!value} onClick={() => navigator.clipboard?.writeText(value)}>Copy</button></div></div>;
}

function CreateEmailAccount({ session, domains, onClose, onDone }) {
  const initialPassword = strongMailboxPassword();
  const [f, setF] = useState({ domain: domains[0]?.domain || '', localpart: '', quota: '0', destination: '', password: initialPassword, confirm_password: initialPassword });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function change(e) { setF({ ...f, [e.target.name]: e.target.value }); }
  async function submit(e) {
    e.preventDefault();
    if (!f.destination && f.password !== f.confirm_password) {
      setError('Mailbox passwords do not match.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await api('/emails', { method: 'POST', csrf: session.csrf, body: JSON.stringify({ ...f, quota_mb: Number(f.quota) }) });
      onDone();
    } catch (x) {
      setError(x.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Drawer title="Create email account" onClose={onClose}>
      <form onSubmit={submit}>
        <div className="mailbox-address-preview"><small>New address</small><b>{f.localpart || 'name'}@{f.domain || 'your-domain.example'}</b><span>Choose a hosted domain or a mail-only subdomain.</span></div>
        <label>
          Domain
          <select name="domain" value={f.domain} onChange={change} required>
            {domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}{d.mail_only ? ` · mail-only · DNS ${d.dns_parent}` : ' · hosted domain'}</option>)}
          </select>
        </label>
        <label>
          Mailbox
          <input name="localpart" placeholder="info" value={f.localpart} onChange={change} required />
        </label>
        <label>
          Mailbox quota MB
          <input name="quota" type="number" min="0" max="1048576" value={f.quota} onChange={change} />
        </label>
        <label>
          Forward to (optional)
          <input name="destination" value={f.destination} onChange={change} placeholder="target@example.com" />
        </label>
        {!f.destination && <><label>Mailbox password<PasswordEditor value={f.password} onChange={(password) => setF({...f,password,confirm_password:password})} required /></label><p className="field-help">A strong password is suggested automatically. Copy it before creating the mailbox.</p></>}
        {error && <div className="form-error">{error}</div>}
        <footer>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Create mailbox'}</button>
        </footer>
      </form>
    </Drawer>
  );
}

function EditEmailAccount({ session, email, onClose, onDone }) {
  const forwardingOnly = Boolean(email.destination);
  const [f, setF] = useState({ quota_mb:String(email.quota_mb || 0), destination:email.destination || '', forward_copy:email.forward_copy || '', password:'', confirm_password:'', allow_smtp:Boolean(email.allow_smtp), allow_imap:Boolean(email.allow_imap), allow_web:Boolean(email.allow_web), allow_dav:Boolean(email.allow_dav), allow_eas:Boolean(email.allow_eas) });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault();
    if (f.password !== f.confirm_password) return setError('New mailbox passwords do not match.');
    setBusy(true); setError('');
    try { await api(`/emails/${email.id}`, {method:'PUT',csrf:session.csrf,body:JSON.stringify({...f,quota_mb:Number(f.quota_mb)})}); onDone(); }
    catch (x) { setError(x.message); } finally { setBusy(false); }
  }
  const toggle = (name, label, help) => <label className="mail-setting-toggle"><span><b>{label}</b><small>{help}</small></span><input type="checkbox" checked={f[name]} onChange={(e) => setF({...f,[name]:e.target.checked})} /></label>;
  return <Drawer title={`Edit ${email.full_email}`} onClose={onClose}><form onSubmit={submit}>
    <div className="mailbox-address-preview"><small>{forwardingOnly ? 'Forwarding address' : 'Grommunio mailbox'}</small><b>{email.full_email}</b><span>The email address cannot be renamed. Create a new address if it must change.</span></div>
    <label>Mailbox quota MB<input type="number" min="0" max="1048576" value={f.quota_mb} onChange={(e) => setF({...f,quota_mb:e.target.value})} /></label>
    {forwardingOnly ? <label>Forward to<input value={f.destination} onChange={(e) => setF({...f,destination:e.target.value})} required placeholder="target@example.com" /></label> : <>
      <label>Forward a copy to (optional)<input value={f.forward_copy} onChange={(e) => setF({...f,forward_copy:e.target.value})} placeholder="target@example.com" /></label>
      <p className="field-help">Comma-separate up to four addresses. Grommunio keeps the original message in this mailbox.</p>
      <label>Set a new password<PasswordEditor value={f.password} onChange={(password) => setF({...f,password,confirm_password:password})} placeholder="Leave blank to keep the current password" /></label>
      <div className="mail-setting-list"><h3>Grommunio access</h3>{toggle('allow_smtp','SMTP sending','Allow this account to send mail.')}{toggle('allow_imap','IMAP and POP','Allow desktop and mobile mail clients.')}{toggle('allow_web','Grommunio Web','Allow login to webmail.')}{toggle('allow_dav','CalDAV and CardDAV','Allow calendar and contact synchronisation.')}{toggle('allow_eas','ActiveSync','Allow Exchange ActiveSync mobile access.')}</div>
    </>}
    {error && <div className="form-error">{error}</div>}<footer><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save changes'}</button></footer>
  </form></Drawer>;
}

function Emails({ session }) {
  const [emails, setEmails] = useState([]);
  const [domains, setDomains] = useState([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [domainOpen, setDomainOpen] = useState(false);
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [mailStatus, setMailStatus] = useState({ hostname: '', ports: {}, ready: false });
  const [ownerMail, setOwnerMail] = useState({ destination: '', addresses: [], domains: [] });

  const load = () => Promise.all([api('/emails'), api('/mail/domains'), api('/mail/status'), session.role === 'admin' ? api('/users') : Promise.resolve({users:[]}), session.role === 'admin' ? api('/mail/owner-addresses') : Promise.resolve({destination:'',addresses:[],domains:[]})]).then(([d, dom, status, u, owner]) => {
    setEmails(asArray(d?.emails));
    setDomains(asArray(dom?.domains));
    setUsers(asArray(u?.users));
    setMailStatus(status || { hostname: '', ports: {}, ready: false });
    setOwnerMail(owner || { destination: '', addresses: [], domains: [] });
  }).catch((x) => setError(x.message));

  useEffect(() => { load(); }, []);

  const remove = async (email) => {
    if (!window.confirm(`Delete ${email.full_email}? This permanently removes the mailbox or forwarding address.`)) return;
    setBusy(`email-${email.id}`); setError('');
    try { await api(`/emails/${email.id}`, { method: 'DELETE', csrf: session.csrf }); await load(); }
    catch (x) { setError(x.message); }
    finally { setBusy(''); }
  };
  const removeDomain = async (item) => {
    if (!window.confirm(`Delete the mail-only domain ${item.domain}? Delete its mailboxes first. Generated records will be removed from DNS zone ${item.dns_parent} and from Cloudflare automatically when connected.`)) return;
    setBusy(`domain-${item.domain}`); setError('');
    try { await api(`/mail/domains/${encodeURIComponent(item.domain)}`, { method:'DELETE', csrf:session.csrf }); await load(); }
    catch (x) { setError(x.message); }
    finally { setBusy(''); }
  };
  const openAsMailbox = async (email) => {
    const popup = window.open('', '_blank');
    if (popup) {
      popup.document.title = `Opening ${email.full_email}`;
      popup.document.body.innerHTML = `<main style="font:16px system-ui;display:grid;place-items:center;min-height:80vh;color:#172033"><div><strong>Opening ${email.full_email}</strong><p>Please wait while MassPanel creates a secure one-time session…</p></div></main>`;
    }
    setBusy(`open-${email.id}`); setError('');
    try {
      const result = await api(`/emails/${email.id}/impersonate`, { method: 'POST', csrf: session.csrf, body: '{}' });
      if (popup) popup.location = result.launch_url;
      else window.location.assign(result.launch_url);
    } catch (x) { if (popup) popup.close(); setError(x.message); }
    finally { setBusy(''); }
  };
  const applyOwnerAddresses = async () => {
    setBusy('owner-addresses'); setError('');
    try { await api('/mail/owner-addresses', { method:'PUT', csrf:session.csrf, body:'{}' }); await load(); }
    catch (x) { setError(x.message); }
    finally { setBusy(''); }
  };
  const openSystemMailbox = async () => {
    const popup = window.open('', '_blank');
    setBusy('system-mailbox'); setError('');
    try { const result = await api('/mail/system/impersonate', {method:'POST',csrf:session.csrf,body:'{}'}); if (popup) popup.location=result.launch_url; else window.location.assign(result.launch_url); }
    catch (x) { if (popup) popup.close(); setError(x.message); }
    finally { setBusy(''); }
  };

  const mailParentAvailable = session.role === 'admin'
    ? users.some((user) => user.panel_role === 'client' && user.panel_active !== false && Number(user.domain_count || 0) > 0)
    : domains.some((domain) => !domain.mail_only);

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Grommunio Mail</h1>
          <p>Manage Grommunio groupware mailboxes, aliases, IMAP, SMTP, EWS and ActiveSync.</p>
        </div>
        <div className="page-actions"><button className="secondary" onClick={() => setDomainOpen(true)} disabled={!mailParentAvailable}>Add mail-only subdomain</button><button className="primary" onClick={() => setOpen(true)} disabled={!domains.length}>Create mailbox</button></div>
      </header>
      <section className="table-area">
        <div className="mail-service-rail"><div><i><PanelIcon name="email" size={24} /></i><span><small>{mailStatus.platform || 'Grommunio Mail'}</small><b>{mailStatus.hostname || 'Not configured'}</b></span></div><div><small>Secure IMAP</small><b className={mailStatus.ports?.imaps ? 'status-pass' : 'status-warn'}>{mailStatus.ports?.imaps ? 'Online · port 993' : 'Offline'}</b></div><div><small>Mail submission</small><b className={mailStatus.ports?.submission ? 'status-pass' : 'status-warn'}>{mailStatus.ports?.submission ? 'Online · port 587' : 'Offline'}</b></div>{mailStatus.webmail_url && <a className="primary" href={mailStatus.webmail_url} target="_blank" rel="noreferrer">Open Grommunio Web</a>}</div>
        <p className="mail-domain-note">Mailboxes can use any hosted domain or mail-only subdomain. Their MX record always points to <b>{mailStatus.hostname || 'the configured mail server'}</b>; the panel stores every record in the correct parent DNS zone.</p>
        {error && <div className="form-error">{error}</div>}
        {session.role === 'admin' && <section className="owner-mail-card"><div><h2>Panel system inbox</h2><p>Hidden service addresses deliver to the customer’s primary mailbox and archive a copy here. The archive is receive-only and ordinary customer mail remains private.</p></div><div className="page-actions"><button className="secondary" onClick={applyOwnerAddresses} disabled={!!busy}>{busy === 'owner-addresses' ? 'Updating…' : 'Update routing'}</button><button className="primary" onClick={openSystemMailbox} disabled={!!busy || !ownerMail.system_mailbox_configured}>{busy === 'system-mailbox' ? 'Opening…' : 'Open system inbox'}</button></div><small>Routing active for {ownerMail.domains.length} mail domain(s) · service aliases are hidden from customer mailbox lists</small></section>}
        <section className="mail-domain-manager"><header><div><h2>Email domains</h2><p>Hosted website domains are linked automatically. Add a mail-only subdomain here without creating another website.</p></div></header><div>{domains.map((domain) => <article key={domain.domain}><span><b>{domain.domain}</b><small>{session.role === 'admin' ? `Client: ${domain.owner} · ` : ''}DNS zone: {domain.dns_parent}</small></span><strong>{domain.mail_only ? 'Mail-only subdomain' : 'Hosted domain'}</strong>{domain.mail_only && <button className="secondary" onClick={() => removeDomain(domain)} disabled={!!busy}>{busy === `domain-${domain.domain}` ? 'Deleting…' : 'Delete email domain'}</button>}</article>)}{!domains.length && <div className="empty">No email domains yet. Add a website before creating mailboxes or mail-only subdomains.</div>}</div></section>
        <h2 className="table-section-title">Mailboxes and forwarding</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Email</th><th>Domain</th><th>Destination</th><th>Quota MB</th><th>Status</th><th>Created</th><th></th></tr>
            </thead>
            <tbody>
              {emails.map((e) => (
                <tr key={e.id}>
                  <td><b>{e.full_email}</b></td>
                  <td>{e.domain}</td>
                  <td>{e.destination || '—'}</td>
                  <td>{e.quota_mb}</td>
                  <td>{e.status}</td>
                  <td>{e.created_at}</td>
                  <td><div className="table-actions">{session.role === 'admin' && !e.destination && <button className="secondary" onClick={() => openAsMailbox(e)} disabled={!!busy}>{busy === `open-${e.id}` ? 'Opening…' : 'Open mailbox'}</button>}<button className="secondary" onClick={() => setEditing(e)} disabled={!!busy}>Edit</button><button className="secondary" onClick={() => remove(e)} disabled={!!busy}>{busy === `email-${e.id}` ? 'Deleting…' : 'Delete'}</button></div></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!emails.length && <div className="empty">No mailbox accounts yet.</div>}
        </div>
      </section>
      {open && <CreateEmailAccount session={session} domains={domains} onClose={() => setOpen(false)} onDone={() => { setOpen(false); load(); }} />}
      {editing && <EditEmailAccount session={session} email={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); load(); }} />}
      {domainOpen && <CreateMailDomain session={session} users={users} onClose={() => setDomainOpen(false)} onDone={() => { setDomainOpen(false); load(); }} />}
    </>
  );
}

function Backups({ session }) {
  const [backups, setBackups] = useState([]);
  const [domains, setDomains] = useState([]);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState('');
  const [domain, setDomain] = useState('');
  const load = () => Promise.all([api('/backups'), api('/domains')])
    .then(([b, d]) => {
      const domainRows = asArray(d?.domains);
      setBackups(asArray(b?.backups));
      setDomains(domainRows);
      if (!domain && domainRows[0]) setDomain(domainRows[0].domain);
    })
    .catch((x) => setError(x.message));
  useEffect(() => { load(); }, []);

  async function createBackup() {
    if (!domain) return;
    setBusy('create');
    setError('');
    try {
      await api('/backups', { method: 'POST', csrf: session.csrf, body: JSON.stringify({ domain }) });
      load();
    } catch (x) { setError(x.message); }
    setBusy(null);
  }
  async function del(id) {
    setBusy(`del-${id}`);
    try {
      await api(`/backups/${id}`, { method: 'DELETE', csrf: session.csrf });
      load();
    } catch (x) { setError(x.message); }
    setBusy(null);
  }
  async function restore(id) {
    if (!window.confirm('Restore this backup to domain root?')) return;
    setBusy(`restore-${id}`);
    try {
      await api(`/backups/${id}/restore`, { method: 'POST', csrf: session.csrf });
    } catch (x) { setError(x.message); }
    setBusy(null);
  }
  return (
    <>
      <header className="page-header">
        <div>
          <h1>Backups</h1>
          <p>Create a backup of website files for every domain.</p>
        </div>
        <div>
          <select value={domain} onChange={(e) => setDomain(e.target.value)}>
            {domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}</option>)}
          </select>
          <button className="primary" onClick={createBackup} disabled={!domain || busy === 'create'}>
            {busy === 'create' ? 'Creating…' : 'Create backup'}
          </button>
        </div>
      </header>
      <section className="table-area">
        {error && <div className="form-error">{error}</div>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Domain</th><th>Size</th><th>Creator</th><th>Created</th><th></th></tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.id}>
                  <td>{b.domain}</td>
                  <td>{(b.size_bytes / 1024 / 1024).toFixed(2)} MB</td>
                  <td>{b.created_by}</td>
                  <td>{b.created_at}</td>
                  <td>
                    <a href={`/api/backups/${b.id}/download`} className="secondary" onClick={() => {}}>Download</a>
                    {session.role === 'admin' && <button className="secondary" onClick={() => restore(b.id)} disabled={busy === `restore-${b.id}`}>Restore</button>}
                    <button className="secondary" onClick={() => del(b.id)} disabled={busy === `del-${b.id}`}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!backups.length && <div className="empty">No backups yet.</div>}
        </div>
      </section>
    </>
  );
}

function Ssl({ session }) {
  const [rows, setRows] = useState([]);
  const [services, setServices] = useState([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState('');
  const [modeByDomain, setModeByDomain] = useState({});
  const load = () => api('/ssl').then((d) => {
    const vals = {};
    asArray(d?.items).forEach((r) => {
      vals[r.domain] = r.ssl_mode || 'disabled';
    });
    setRows(asArray(d?.items));
    setServices(asArray(d?.services));
    setModeByDomain(vals);
  }).catch((x) => setError(x.message));
  useEffect(() => { load(); }, []);

  function change(domain, mode) {
    setModeByDomain((p) => ({ ...p, [domain]: mode }));
  }
  async function save(domain) {
    setError('');
    try {
      await api('/domains/' + domain + '/ssl', { method: 'POST', csrf: session.csrf, body: JSON.stringify({ mode: modeByDomain[domain] || 'disabled' }) });
      load();
    } catch (x) {
      setError(x.message);
    }
  }
  async function regenerate(domain) {
    if (!window.confirm(`Force a new Let's Encrypt certificate for ${domain}? This can be rate-limited by the certificate authority.`)) return;
    setError(''); setNotice(''); setBusy(domain);
    try {
      await api(`/ssl/${domain}/regenerate`, { method:'POST', csrf:session.csrf, body:'{}' });
      setNotice(`Certificate for ${domain} was regenerated and Nginx reloaded successfully.`);
      await load();
    } catch (x) { setError(x.message); } finally { setBusy(''); }
  }
  async function regenerateService(item) {
    if (!window.confirm(`Configure Nginx and force a new Let's Encrypt certificate for ${item.domain}?`)) return;
    setError(''); setNotice(''); setBusy(`service-${item.kind}`);
    try {
      const result = await api(`/ssl/service/${item.kind}/regenerate`, { method:'POST', csrf:session.csrf, body:'{}' });
      setNotice(`${item.label} certificate for ${result.hostname} was regenerated and Nginx reloaded.`);
      await load();
    } catch (x) { setError(x.message); } finally { setBusy(''); }
  }
  return (
    <>
      <header className="page-header">
        <div>
          <h1>Certificates</h1>
          <p>Configure HTTPS and regenerate existing Let's Encrypt certificates.</p>
        </div>
      </header>
      <section className="table-area">
        {error && <div className="form-error">{error}</div>}
        {notice && <div className="notice">{notice}</div>}
        {!!services.length && <><h2 className="table-section-title">Server service certificates</h2><div className="table-wrap"><table><thead><tr><th>Service</th><th>Hostname</th><th>Status</th><th></th></tr></thead><tbody>{services.map((item) => <tr key={item.kind}><td><b>{item.label}</b></td><td>{item.domain}</td><td><span className={item.tls_ready ? 'status-pass' : 'status-warn'}>{item.tls_ready ? 'Valid public certificate' : 'Certificate needs attention'}</span></td><td className="certificate-actions">{session.role === 'admin' && <button className="secondary" onClick={() => regenerateService(item)} disabled={busy === `service-${item.kind}`}>{busy === `service-${item.kind}` ? 'Regenerating…' : item.tls_ready ? 'Regenerate certificate' : 'Configure Nginx & certificate'}</button>}</td></tr>)}</tbody></table></div><h2 className="table-section-title">Website certificates</h2></>}
        <div className="table-wrap">
          <table>
            <thead><tr><th>Domain</th><th>Mode</th><th></th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.domain}>
                  <td>{r.domain}</td>
                  <td>
                    <select value={modeByDomain[r.domain]} onChange={(e) => change(r.domain, e.target.value)}>
                      <option value="disabled">Disabled</option>
                      <option value="self">Self-signed</option>
                      <option value="letsencrypt">Let's Encrypt</option>
                    </select>
                  </td>
                  <td className="certificate-actions"><button className="primary" onClick={() => save(r.domain)} disabled={busy === r.domain}>Save</button>{r.ssl_mode === 'letsencrypt' && <button className="secondary" onClick={() => regenerate(r.domain)} disabled={busy === r.domain}>{busy === r.domain ? 'Regenerating…' : 'Regenerate certificate'}</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <div className="empty">No domains to manage.</div>}
        </div>
      </section>
    </>
  );
}

function Overview({ session, setPage }) {
  const [health, setHealth] = useState({ cpu: 0, memory: 0, disk: 0 });
  const [domains, setDomains] = useState([]);
  const [users, setUsers] = useState([]);
  const [activity, setActivity] = useState([]);
  const [error, setError] = useState('');
  useEffect(() => {
    Promise.all([
      api('/health'),
      api('/domains'),
      session.role === 'admin' ? api('/users') : Promise.resolve({ users: [] }),
      session.role === 'admin' ? api('/audit') : Promise.resolve({ items: [] }),
    ])
      .then(([h, d, u, a]) => {
        setHealth(h);
        setDomains(asArray(d?.domains));
        setUsers(asArray(u?.users));
        setActivity(asArray(a?.items).slice(0, 6));
      })
      .catch((x) => setError(x.message));
  }, []);
  return (
    <>
      <header className="page-header overview-heading">
        <div>
          <h1>Dashboard</h1>
          <p>Welcome back, {session.username}. Here is what is happening on your server.</p>
        </div>
        <span className="live-indicator"><i /> Server online</span>
      </header>
      {error && <div className="form-error">{error}</div>}
      <div className="dashboard-canvas">
        <section className="dashboard-section health-section">
          <div className="section-title"><h2>Server health</h2><small>Live resource usage</small></div>
          <div className="health-cards">
            {[['CPU', health.cpu, 'Processor load'], ['Memory', health.memory, 'System memory'], ['Disk', health.disk, 'Storage used']].map(([label, value, detail]) => (
              <article className="health-card" key={label}>
                <div className="health-card-icon">{label === 'CPU' ? '⌘' : label === 'Memory' ? '▤' : '▱'}</div>
                <div className="health-card-copy"><span>{label}</span><strong>{value}%</strong><small>{detail}</small></div>
                <div className="health-meter"><i style={{ width: `${Math.min(100, Number(value) || 0)}%` }} /></div>
              </article>
            ))}
          </div>
        </section>
        <div className="dashboard-columns">
          <div className="dashboard-main">
            <section className="dashboard-section">
              <div className="section-title"><h2>Hosting summary</h2></div>
              <div className="summary-row">
                {session.role === 'admin' && <div><span className="summary-icon blue">♙</span><small>Users</small><strong>{users.filter((u) => !u.protected).length}</strong></div>}
                <div><span className="summary-icon green">⌂</span><small>Websites</small><strong>{domains.length}</strong></div>
                <div><span className="summary-icon violet">🔒</span><small>SSL enabled</small><strong>{domains.filter((d) => d.ssl_mode && d.ssl_mode !== 'disabled').length}</strong></div>
                <div><span className="summary-icon amber">◫</span><small>Healthy resources</small><strong>{[health.cpu, health.memory, health.disk].filter((v) => v < 80).length}/3</strong></div>
              </div>
            </section>
            <section className="dashboard-section">
              <div className="section-title"><h2>Quick access</h2><small>Your most-used hosting tools</small></div>
              <div className="quick-tools">
                {(session.role === 'admin' ? ['users', 'websites', 'files', 'databases', 'backups', 'dns', 'email', 'ssl'] : ['websites', 'files', 'databases', 'backups', 'dns', 'email', 'ssl', 'tickets']).map((item) => (
                  <button key={item} onClick={() => setPage(item)}><i><PanelIcon name={item} size={20} /></i><span>{pageLabel[item] || item}</span><small>Open tool →</small></button>
                ))}
              </div>
            </section>
            {session.role === 'admin' && (
              <section className="dashboard-section activity-panel">
                <div className="section-title"><h2>Recent activity</h2><button onClick={() => setPage('audit')}>View audit log</button></div>
                {activity.map((item) => <div className="activity-row" key={item.id}><i /><time>{item.created_at}</time><b>{item.action}</b><span>{item.target || '—'}</span><small>{item.outcome}</small></div>)}
                {!activity.length && <div className="empty">No recent activity.</div>}
              </section>
            )}
          </div>
          <aside className="dashboard-side">
            <section className="dashboard-section service-panel">
              <div className="section-title"><h2>Service status</h2></div>
              <div><span>Nginx web server</span><b className="service-ok">● Running</b></div>
              <div><span>Panel API</span><b className="service-ok">● Running</b></div>
              <div><span>Website hosting</span><b className="service-ok">● Running</b></div>
              <div><span>Grommunio mail &amp; groupware</span><b className="service-ok">● Running</b></div>
            </section>
            <section className="dashboard-section account-panel">
              <div className="section-title"><h2>Account</h2></div>
              <span className="large-avatar">{session.username[0]?.toUpperCase()}</span>
              <strong>{session.username}</strong><small>{session.role === 'admin' ? 'Full server administration' : 'Hosting client access'}</small>
              {session.impersonating_as && <div className="impersonation-note">Supporting {session.impersonating_as}<br />as {session.impersonator}</div>}
            </section>
          </aside>
        </div>
      </div>
    </>
  );
}

function Tickets({ session }) {
  const [tickets, setTickets] = useState([]);
  const [support, setSupport] = useState({ domains: [], customers: [], overview: {}, can_contact_owner: false });
  const [filter, setFilter] = useState('all');
  const [error, setError] = useState('');
  const [open, setOpen] = useState(false);
  const [replyFor, setReplyFor] = useState(null);
  const [reply, setReply] = useState('');
  const [form, setForm] = useState({ domain: '', subject: '', body: '', priority: 'normal', contact_owner: false });
  const [viewing, setViewing] = useState(null);
  const load = () => api('/tickets').then((d) => { setTickets(asArray(d?.tickets)); setSupport({ domains: asArray(d?.domains), customers: asArray(d?.customers), overview: d?.overview || {}, can_contact_owner: Boolean(d?.can_contact_owner) }); }).catch((x) => setError(x.message));
  useEffect(() => { load(); }, []);

  async function createTicket(e) {
    e.preventDefault();
    try {
      await api('/tickets', { method: 'POST', csrf: session.csrf, body: JSON.stringify(form) });
      setOpen(false);
      setForm({ domain: '', subject: '', body: '', priority: 'normal', contact_owner: false });
      load();
    } catch (x) {
      setError(x.message);
    }
  }
  async function replyTicket(tid) {
    if (!reply.trim()) return;
    try {
      await api(`/tickets/${tid}/reply`, { method: 'POST', csrf: session.csrf, body: JSON.stringify({ message: reply }) });
      setReply('');
      setReplyFor(null);
      load();
    } catch (x) {
      setError(x.message);
    }
  }

  async function openTicket(ticketId) {
    setError('');
    try {
      const data = await api(`/tickets/${ticketId}`);
      setViewing({
        ticket: data?.ticket || null,
        replies: asArray(data?.replies),
      });
      setReply('');
      setReplyFor(null);
    } catch (x) {
      setError(x.message);
    }
  }

  async function deleteTicket(ticketId) {
    if (!window.confirm(`Delete ticket #${ticketId}? This cannot be undone.`)) return;
    setError('');
    try {
      await api(`/tickets/${ticketId}`, { method: 'DELETE', csrf: session.csrf });
      if (replyFor === ticketId) setReplyFor(null);
      if (viewing?.ticket?.id === ticketId) setViewing(null);
      load();
    } catch (x) {
      setError(x.message);
    }
  }

  async function updateStatus(tid, status) {
    try {
      await api(`/tickets/${tid}/status`, { method: 'POST', csrf: session.csrf, body: JSON.stringify({ status }) });
      load();
    } catch (x) {
      setError(x.message);
    }
  }

  const shownTickets = filter === 'all' ? tickets : filter === 'urgent' ? tickets.filter((ticket) => ticket.priority === 'urgent' && ticket.status !== 'closed') : tickets.filter((ticket) => ticket.status === filter);
  const openNew = (owner = false) => { setForm({ domain: '', subject: owner ? 'Reseller support request' : '', body: '', priority: 'normal', contact_owner: owner }); setOpen(true); };

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{session.role === 'admin' ? 'Support overview' : 'Support'}</h1>
          <p>{session.role === 'admin' ? 'View and manage every customer support request.' : session.role === 'reseller' ? 'Support your customers and contact the server owner when you need help.' : 'Get help with the domains and services linked to your account.'}</p>
        </div>
        <div className="page-actions">{support.can_contact_owner && <button className="secondary" onClick={() => openNew(true)}>Contact server owner</button>}<button className="primary" onClick={() => openNew(false)}>New ticket</button></div>
      </header>
      <section className="support-workspace">
        {error && <div className="form-error">{error}</div>}
        <div className="support-metrics">
          <div><small>All tickets</small><strong>{support.overview.all || 0}</strong></div>
          <div><small>Open</small><strong>{support.overview.open || 0}</strong></div>
          <div><small>In progress</small><strong>{support.overview.in_progress || 0}</strong></div>
          <div><small>Urgent</small><strong>{support.overview.urgent || 0}</strong></div>
        </div>
        <div className="support-main">
          <aside className="support-filters"><h3>Tickets</h3>{[['all','All tickets'],['open','Open'],['in_progress','In progress'],['urgent','Urgent'],['closed','Closed']].map(([value,label]) => <button key={value} className={filter === value ? 'active' : ''} onClick={() => setFilter(value)}><span>{label}</span><b>{support.overview[value] || 0}</b></button>)}{support.domains.length > 0 && <div className="support-linked"><h3>Linked domains</h3>{support.domains.map((item) => <span key={item.domain}>{item.domain}</span>)}</div>}{session.role === 'reseller' && <div className="support-linked"><h3>Your customers</h3>{support.customers.map((item) => <span key={item.username}>{item.username}<small>{item.active ? 'Active' : 'Suspended'}</small></span>)}</div>}</aside>
          <div className="table-wrap support-ticket-list">
          <table>
            <thead>
              <tr><th>ID</th><th>Subject</th><th>Requester</th><th>Domain</th><th>Priority</th><th>Status</th><th>Updated</th><th></th></tr>
            </thead>
            <tbody>
              {shownTickets.map((t) => (
                <tr key={t.id}>
                  <td>#{t.id}</td>
                  <td><b>{t.subject}</b><div>{t.body?.slice(0, 60)}</div></td>
                  <td><b>{t.requester}</b>{t.target_role === 'owner' && <small className="owner-escalation">Server owner</small>}</td>
                  <td>{t.domain || '—'}</td>
                  <td>{t.priority}</td>
                  <td>
                    <select value={t.status} onChange={(e) => updateStatus(t.id, e.target.value)}>
                      <option value="open">Open</option>
                      <option value="in_progress">In progress</option>
                      <option value="closed">Closed</option>
                    </select>
                  </td>
                  <td>{t.updated_at}</td>
                  <td>
                    <button className="secondary" onClick={() => { setReplyFor(t.id); }}>Reply</button>
                    <button className="secondary" onClick={() => openTicket(t.id)}>View</button>
                    <button className="secondary" onClick={() => deleteTicket(t.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!shownTickets.length && <div className="empty-state-card"><h2>No tickets in this view</h2><p>Choose another filter or create a support request.</p></div>}
          </div>
        </div>
      </section>

      {open && (
        <Drawer title={form.contact_owner ? 'Contact server owner' : 'New support ticket'} onClose={() => setOpen(false)}>
          <form onSubmit={createTicket}>
            <label>
              Linked domain (optional)
              <select value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })}><option value="">General support</option>{support.domains.map((item) => <option key={item.domain} value={item.domain}>{item.domain}</option>)}</select>
            </label>
            <label>
              Subject
              <input value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} required />
            </label>
            <label>
              Priority
              <select value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
                <option>low</option><option>normal</option><option>high</option><option>urgent</option>
              </select>
            </label>
            <label>
              Message
              <textarea rows="4" value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} required />
            </label>
            <footer>
              <button className="secondary" type="button" onClick={() => setOpen(false)}>Cancel</button>
              <button className="primary">Create ticket</button>
            </footer>
          </form>
        </Drawer>
      )}
      {replyFor && (
        <Drawer title={`Reply to ticket #${replyFor}`} onClose={() => { setReplyFor(null); setReply(''); }}>
          <form onSubmit={(e) => { e.preventDefault(); replyTicket(replyFor); }}>
            <label>
              Message
              <textarea rows="6" value={reply} onChange={(e) => setReply(e.target.value)} />
            </label>
            <footer>
              <button type="button" className="secondary" onClick={() => { setReplyFor(null); setReply(''); }}>Cancel</button>
              <button className="primary">Post reply</button>
            </footer>
          </form>
        </Drawer>
      )}
      {viewing?.ticket && (
        <Drawer title={`Support ticket #${viewing.ticket.id}`} className="ticket-drawer" onClose={() => setViewing(null)}>
          <div className="ticket-workspace">
            <section className="ticket-summary">
              <div className="ticket-summary-heading">
                <div><span className="ticket-kicker">{viewing.ticket.domain || 'General support'}</span><h3>{viewing.ticket.subject}</h3></div>
                <span className={`ticket-status ticket-status-${viewing.ticket.status}`}>{viewing.ticket.status.replace('_', ' ')}</span>
              </div>
              <dl>
                <div><dt>Requester</dt><dd>{viewing.ticket.requester}</dd></div>
                <div><dt>Priority</dt><dd className={`ticket-priority ticket-priority-${viewing.ticket.priority}`}>{viewing.ticket.priority}</dd></div>
                <div><dt>Opened</dt><dd>{viewing.ticket.created_at}</dd></div>
              </dl>
            </section>

            <section className="ticket-thread" aria-label="Ticket conversation">
              <div className="ticket-thread-label"><span>Conversation</span><b>{viewing.replies.length + 1} message{viewing.replies.length ? 's' : ''}</b></div>
              <article className="ticket-message">
                <div className="ticket-message-avatar">{(viewing.ticket.requester || '?')[0].toUpperCase()}</div>
                <div className="ticket-message-content">
                  <header><b>{viewing.ticket.requester}</b><time>{viewing.ticket.created_at}</time></header>
                  <p>{viewing.ticket.body}</p>
                </div>
              </article>
              {viewing.replies.map((item) => {
                const ownMessage = item.author === session.username;
                return (
                  <article className={`ticket-message${ownMessage ? ' is-own' : ''}`} key={item.id}>
                    <div className="ticket-message-avatar">{(item.author || '?')[0].toUpperCase()}</div>
                    <div className="ticket-message-content">
                      <header><b>{item.author}</b><time>{item.created_at}</time></header>
                      <p>{item.message}</p>
                    </div>
                  </article>
                );
              })}
              {!viewing.replies.length && <p className="ticket-awaiting">No replies yet — write the first response below.</p>}
            </section>
          </div>
          <form className="ticket-composer" onSubmit={(event) => { event.preventDefault(); replyTicket(viewing.ticket.id).then(() => openTicket(viewing.ticket.id)); }}>
            <label htmlFor="ticket-reply">Reply</label>
            <textarea id="ticket-reply" rows="4" value={reply} onChange={(event) => setReply(event.target.value)} placeholder="Write a helpful response…" />
            <footer><span>{reply.length ? `${reply.length} characters` : 'The requester will be notified'}</span><button className="primary" disabled={!reply.trim()}>Send reply</button></footer>
          </form>
        </Drawer>
      )}
    </>
  );
}

function Audit() {
  const [x, setX] = useState([]);
  const [error, setError] = useState('');
  useEffect(() => {
    api('/audit').then((d) => setX(asArray(d?.items))).catch((x) => setError(x.message));
  }, []);
  return (
    <>
      <header className="page-header">
        <div>
          <h1>Audit log</h1>
          <p>Recent administrative activity.</p>
        </div>
      </header>
      {error && <div className="form-error">{error}</div>}
      <section className="audit-list">
        {x.map((i) => (
          <div key={i.id}>
            <time>{i.created_at}</time>
            <b>{i.action}</b>
            <span>{i.target || '—'}</span>
            <small>{i.outcome}</small>
          </div>
        ))}
      </section>
    </>
  );
}

const THIRD_PARTY_COMPONENTS = [
  { name: 'MassPanel', version: 'Current release', purpose: 'Hosting control panel and installer', license: 'AGPL-3.0-or-later', status: 'Deployed · source available', source: '/masspanel-corresponding-source.tar.gz' },
  { name: 'AdminNeo', version: '5.7.0', purpose: 'Integrated MariaDB browser and editor', license: 'Apache-2.0 or GPL-2.0', status: 'Deployed · MassPanel SSO', source: 'https://github.com/adminneo-org/adminneo' },
  { name: 'FileBrowser Quantum', version: '1.5.3-stable', purpose: 'Advanced hosting file manager', license: 'Apache-2.0', status: 'Deployed · MassPanel SSO', source: 'https://github.com/gtsteffaniak/filebrowser' },
  { name: 'Gromox', version: '3.9', purpose: 'Primary groupware store, IMAP and EWS backend', license: 'AGPL-3.0-or-later', status: 'Deployed', source: 'https://github.com/grommunio/gromox/tree/gromox-3.9' },
  { name: 'grommunio Web', version: 'f26f375c3', purpose: 'Primary webmail and groupware client', license: 'AGPL-3.0-or-later', status: 'Deployed · modified by MassPanel', source: '/masspanel-corresponding-source.tar.gz' },
  { name: 'WordPress', version: 'Stable', purpose: 'Optional website application', license: 'GPL-2.0-or-later', status: 'Installed on demand', source: 'https://wordpress.org/download/source/' },
  { name: 'WP-CLI', version: 'Distribution package', purpose: 'WordPress lifecycle manager', license: 'MIT', status: 'Deployed', source: 'https://github.com/wp-cli/wp-cli' },
  { name: 'React', version: '19.1.1', purpose: 'Panel browser interface', license: 'MIT', status: 'Deployed', source: 'https://github.com/facebook/react' },
  { name: 'Lucide', version: '1.8.0', purpose: 'Panel navigation and interface icons', license: 'ISC', status: 'Vendored · deployed', source: 'https://github.com/lucide-icons/lucide' },
  { name: 'Flask', version: '3.1.2', purpose: 'Panel API framework', license: 'BSD-3-Clause', status: 'Deployed', source: 'https://github.com/pallets/flask/tree/3.1.2' },
];

function Licenses() {
  return (
    <>
      <header className="page-header"><div><h1>Open-source components</h1><p>Source, version, licence and deployment status for code used or prepared by MassPanel.</p></div></header>
      <section className="table-area">
        <div className="hosting-plan-banner"><span><b>Source transparency</b> · MassPanel is AGPL-3.0-or-later. The complete deployed source, Grommunio modification and licence notices are available without charge.</span><span><a className="secondary" href="https://github.com/demassimo/masspanel" target="_blank" rel="noreferrer">GitHub</a> <a className="secondary" href="/masspanel-corresponding-source.tar.gz">Exact source</a></span></div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Component</th><th>Purpose</th><th>Licence</th><th>Status</th><th>Source</th></tr></thead>
            <tbody>{THIRD_PARTY_COMPONENTS.map((item) => <tr key={item.name}><td><b>{item.name}</b><br /><small>{item.version}</small></td><td>{item.purpose}</td><td>{item.license}</td><td>{item.status}</td><td><a href={item.source} target="_blank" rel="noreferrer">{item.source.startsWith('/') ? 'Download source' : 'Upstream repository'}</a></td></tr>)}</tbody>
          </table>
        </div>
        <p className="field-help">The distribution also includes THIRD_PARTY.md, exact source archives, SHA-256 checksums and upstream licence files.</p>
      </section>
    </>
  );
}

function Settings({ session, product, onProductChange }) {
  const [settings, setSettings] = useState({ ...DEFAULT_PRODUCT, ...product });
  const [loading, setLoading] = useState(true);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [saveSuccess, setSaveSuccess] = useState('');
  const [pw, setPw] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });
  const [pwError, setPwError] = useState('');
  const [pwSuccess, setPwSuccess] = useState('');
  const [pwBusy, setPwBusy] = useState(false);
  const [serviceStatus, setServiceStatus] = useState(null);
  const [license, setLicense] = useState(null);
  const [licenseKey, setLicenseKey] = useState('');
  const [licenseBusy, setLicenseBusy] = useState(false);
  const [licenseMessage, setLicenseMessage] = useState('');
  const [licenseError, setLicenseError] = useState('');

  useEffect(() => {
    Promise.all([
      api('/settings'),
      api('/service-domains/status'),
      session.role === 'admin' ? api('/license') : Promise.resolve(null),
    ])
      .then(([value, service, entitlement]) => {
        setSettings((current) => ({ ...current, ...value }));
        setServiceStatus(service);
        setLicense(entitlement);
      })
      .catch((error) => setSaveError(error.message))
      .finally(() => setLoading(false));
  }, [session.role]);

  function changeSetting(event) {
    const { name, value, type, checked } = event.target;
    setSettings((current) => ({ ...current, [name]: type === 'checkbox' ? checked : value }));
  }

  async function savePanelSettings(event) {
    event.preventDefault();
    setSaveBusy(true);
    setSaveError('');
    setSaveSuccess('');
    try {
      const next = await api('/settings', { method: 'PUT', csrf: session.csrf, body: JSON.stringify(settings) });
      setSettings((current) => ({ ...current, ...next }));
      onProductChange?.(next);
      const cloudflareFailures = asArray(next.cloudflare_sync).filter((item) => item.status === 'failed');
      setSaveSuccess(next.mail_hostname_changed
        ? `Settings saved and ${next.mail_dns_updated || 0} generated mail DNS records updated${cloudflareFailures.length ? `; Cloudflare auto-sync needs attention for ${cloudflareFailures.length} zone${cloudflareFailures.length === 1 ? '' : 's'}` : ' and synchronized with connected Cloudflare zones'}. Check public readiness, then regenerate the mail certificate.`
        : `Customer-facing settings saved${cloudflareFailures.length ? '; a Cloudflare auto-sync retry is needed' : ''}. Check the public readiness tests before changing certificates.`);
      setServiceStatus(await api('/service-domains/status'));
    } catch (error) {
      setSaveError(error.message);
    } finally {
      setSaveBusy(false);
    }
  }

  async function changePassword(e) {
    e.preventDefault();
    setPwError('');
    setPwSuccess('');
    if (pw.new_password !== pw.confirm_password) {
      setPwError('Passwords do not match.');
      return;
    }
    if (pw.new_password.length < 12) {
      setPwError('Password must be at least 12 characters.');
      return;
    }
    setPwBusy(true);
    try {
      await api('/account/password', {
        method: 'POST',
        csrf: session.csrf,
        body: JSON.stringify({
          username: session.username,
          current_password: session.role === 'admin' ? '' : pw.current_password,
          password: pw.new_password,
          confirm_password: pw.confirm_password,
        }),
      });
      setPwSuccess('Password updated successfully.');
      setPw({ current_password: '', new_password: '', confirm_password: '' });
    } catch (x) {
      setPwError(x.message);
    } finally {
      setPwBusy(false);
    }
  }

  async function activateLicense(event) {
    event.preventDefault();
    setLicenseBusy(true);
    setLicenseError('');
    setLicenseMessage('');
    try {
      const next = await api('/license/activate', {
        method: 'POST', csrf: session.csrf, body: JSON.stringify({ license_key: licenseKey.trim() }),
      });
      setLicense(next);
      setLicenseKey('');
      setLicenseMessage('MassPanel Unlimited is active on this server.');
    } catch (error) {
      setLicenseError(error.message);
    } finally {
      setLicenseBusy(false);
    }
  }

  async function refreshLicense() {
    setLicenseBusy(true);
    setLicenseError('');
    setLicenseMessage('');
    try {
      const next = await api('/license/refresh', { method: 'POST', csrf: session.csrf, body: '{}' });
      setLicense(next);
      setLicenseMessage('Licence status refreshed.');
    } catch (error) {
      setLicenseError(error.message);
    } finally {
      setLicenseBusy(false);
    }
  }

  async function removeLicense() {
    if (!window.confirm('Remove MassPanel Unlimited from this server and return to the free Community edition? Websites, mail and the Server ID will not be changed.')) return;
    setLicenseBusy(true);
    setLicenseError('');
    setLicenseMessage('');
    try {
      const next = await api('/license/remove', { method: 'POST', csrf: session.csrf, body: '{}' });
      setLicense(next);
      setLicenseMessage('Unlimited licence removed. This server is now using the Community edition.');
    } catch (error) {
      setLicenseError(error.message);
    } finally {
      setLicenseBusy(false);
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Settings</h1>
          <p>{session.role === 'admin' ? 'Brand and configure the panel for your customers.' : 'Manage your account and get support.'}</p>
        </div>
      </header>
      <div className="settings-layout">
        {session.role === 'admin' && (
          <form className="settings-panel settings-form" onSubmit={savePanelSettings}>
            <header><div><h2>Brand and service domains</h2><p>Choose the customer panel hostname and the central mail/groupware hostname.</p></div><span className="settings-icon">◎</span></header>
            {saveError && <div className="form-error">{saveError}</div>}
            {saveSuccess && <div className="notice">{saveSuccess}</div>}
            <div className="form-grid">
              <label>Panel name<input name="panel_name" maxLength="48" value={settings.panel_name || ''} onChange={changeSetting} required /></label>
              <label>Company name<input name="company_name" maxLength="80" value={settings.company_name || ''} onChange={changeSetting} placeholder="Your hosting company" /></label>
              <label>Support email<input name="support_email" type="email" value={settings.support_email || ''} onChange={changeSetting} placeholder="support@example.com" /></label>
              <label>Support website<input name="support_url" type="url" value={settings.support_url || ''} onChange={changeSetting} placeholder="https://support.example.com" /></label>
              <label className="full-field">Panel domain URL<input name="public_url" type="url" value={settings.public_url || ''} onChange={changeSetting} placeholder="https://panel.example.com" /><small className="field-help">Nginx serves the owner and customer portal on this domain.</small></label>
              <label className="full-field">Mail server domain<input name="mail_hostname" value={settings.mail_hostname || ''} onChange={changeSetting} placeholder="mail.example.com" /><small className="field-help">Every customer-domain MX record uses this server for SMTP, IMAP, webmail, EWS, ActiveSync and discovery.</small></label>
              <label className="full-field">Owner system mail domain<input name="system_mail_domain" value={settings.system_mail_domain || ''} onChange={changeSetting} placeholder="mail.example.com" /><small className="field-help">MassPanel automatically creates a hidden, receive-only owner inbox on this domain for root, postmaster, abuse and website notices. The mailbox address is never shown to customers.</small></label>
              <label className="full-field">Footer message<input name="footer_text" maxLength="180" value={settings.footer_text || ''} onChange={changeSetting} /></label>
            </div>
            <label className="switch-row"><span><b>Show “Powered by MassPanel”</b><small>Keep attribution visible when distributing the free edition.</small></span><input name="show_powered_by" type="checkbox" checked={Boolean(settings.show_powered_by)} onChange={changeSetting} /></label>
            {serviceStatus && <div className="service-readiness"><h3>Public readiness tests</h3><p><span className={serviceStatus.checks?.panel_a ? 'status-pass' : 'status-warn'}>Panel domain {serviceStatus.checks?.panel_a ? 'points to this server' : 'needs configuration'}</span><span className={serviceStatus.checks?.mail_a ? 'status-pass' : 'status-warn'}>Mail server {serviceStatus.checks?.mail_a ? 'is ready' : 'needs configuration'}</span><span className={serviceStatus.checks?.mail_ptr ? 'status-pass' : 'status-warn'}>Reverse DNS {serviceStatus.checks?.mail_ptr ? 'matches' : 'must be set by IP provider'}</span></p>{serviceStatus.warnings?.map((warning) => <small key={warning}>{warning}</small>)}</div>}
            <footer><button className="primary" disabled={loading || saveBusy}>{saveBusy ? 'Saving…' : 'Save customer settings'}</button></footer>
          </form>
        )}
        <aside className="settings-stack">
          <section className="settings-panel account-summary">
            <header><div><h2>Your account</h2><p>Signed-in profile and installation details.</p></div><span className="settings-icon">♙</span></header>
            <dl><div><dt>Username</dt><dd>{session.username}</dd></div><div><dt>Access level</dt><dd>{session.role}</dd></div><div><dt>Server</dt><dd>{settings.server_hostname || window.location.hostname}</dd></div><div><dt>Panel address</dt><dd>{settings.public_url || window.location.origin}</dd></div></dl>
            {settings.support_email && <a className="support-link" href={`mailto:${settings.support_email}`}>Contact support</a>}
          </section>
          <form className="settings-panel settings-form compact" onSubmit={changePassword}>
            <header><div><h2>Security</h2><p>Use a unique password with at least 12 characters.</p></div><span className="settings-icon">◇</span></header>
            {pwError && <div className="form-error">{pwError}</div>}
            {pwSuccess && <div className="notice">{pwSuccess}</div>}
          {session.role !== 'admin' && (
            <label>
              Current password
              <input
                type="password"
                value={pw.current_password}
                minLength="12"
                required
                onChange={(e) => setPw((p) => ({ ...p, current_password: e.target.value }))}
              />
            </label>
          )}
          <label>
            New password
            <input
              type="password"
              value={pw.new_password}
              minLength="12"
              required
              onChange={(e) => setPw((p) => ({ ...p, new_password: e.target.value }))}
            />
          </label>
          <label>
            Confirm new password
            <input
              type="password"
              value={pw.confirm_password}
              minLength="12"
              required
              onChange={(e) => setPw((p) => ({ ...p, confirm_password: e.target.value }))}
            />
          </label>
          <button className="secondary" disabled={pwBusy}>
            {pwBusy ? 'Saving…' : 'Update password'}
          </button>
          </form>
          {session.role === 'admin' && <section className="settings-panel distribution-card">
            <header><div><h2>{license?.edition === 'unlimited' ? 'MassPanel Unlimited' : 'MassPanel Community'}</h2><p>{license?.edition === 'unlimited' ? 'Unlimited hosted root domains on this server.' : 'Includes up to 20 hosted root domains at no cost.'}</p></div><span className="settings-icon">↗</span></header>
            {licenseError && <div className="form-error">{licenseError}</div>}
            {licenseMessage && <div className="notice">{licenseMessage}</div>}
            {license && <dl>
              <div><dt>Domain usage</dt><dd><strong>{license.domain_count}</strong>{license.domain_limit ? ` of ${license.domain_limit}` : ' · Unlimited'}</dd></div>
              <div><dt>Licence status</dt><dd><span className={`licence-status ${license.status === 'active' ? 'is-active' : ''}`}>{license.status}</span></dd></div>
              {license.subscription_expires_at && <div><dt>Paid until</dt><dd>{new Date(license.subscription_expires_at).toLocaleDateString()}</dd></div>}
              <div><dt>Server ID</dt><dd className="mono licence-installation-id">{license.installation_id}</dd></div>
            </dl>}
            {license?.edition === 'unlimited' ? (
              <><p>Licences are renewed manually. Existing websites and mail stay online if a licence expires.</p><div className="licence-actions"><button type="button" className="secondary" disabled={licenseBusy} onClick={refreshLicense}>{licenseBusy ? 'Refreshing…' : 'Refresh licence'}</button><button type="button" className="secondary licence-remove" disabled={licenseBusy} onClick={removeLicense}>Remove licence</button></div></>
            ) : (
              <form className="settings-form compact" onSubmit={activateLicense}>
                <p><b>Need more than 20 domains?</b><br />Unlimited is $5 USD per server each month and is activated manually. Your existing websites and email are never disabled if a licence needs attention.</p>
                <label>Activation key<input type="password" value={licenseKey} onChange={(event) => setLicenseKey(event.target.value)} placeholder="MPU-…" required /></label>
                <button className="primary" disabled={licenseBusy}>{licenseBusy ? 'Activating…' : 'Activate Unlimited plan'}</button>
              </form>
            )}
          </section>}
        </aside>
      </div>
    </>
  );
}

export function LegacyApp() {
  const [s, setS] = useState(null);
  const [product, setProduct] = useState(DEFAULT_PRODUCT);
  const [check, setCheck] = useState(true);
  const [page, setPage] = useState('overview');
  const [fatalError, setFatalError] = useState('');

  useEffect(() => {
    const onError = (event) => {
      const message = String(event?.error?.message || event?.message || 'Unexpected runtime error.');
      setFatalError(message);
    };
    const onUnhandledRejection = (event) => {
      const reason = event?.reason;
      const message = String(reason?.message || reason || 'Unhandled promise rejection.');
      setFatalError(message);
    };

    window.addEventListener('error', onError);
    window.addEventListener('unhandledrejection', onUnhandledRejection);
    return () => {
      window.removeEventListener('error', onError);
      window.removeEventListener('unhandledrejection', onUnhandledRejection);
    };
  }, []);

  useEffect(() => {
    Promise.allSettled([api('/session'), api('/product')]).then(([sessionResult, productResult]) => {
      if (sessionResult.status === 'fulfilled') setS(normalizeSession(sessionResult.value));
      if (productResult.status === 'fulfilled') setProduct((current) => ({ ...current, ...productResult.value }));
      setCheck(false);
    });
  }, []);

  useEffect(() => {
    document.title = product.panel_name || 'MassPanel';
  }, [product.panel_name]);

  useEffect(() => {
    if (!s) return;
    const allowedPages = s.role === 'admin' ? ADMIN_PAGES : CLIENT_PAGES;
    if (!allowedPages.includes(page)) setPage('overview');
  }, [s?.role, page]);

  if (check) return <div className="loading">MassPanel</div>;
  if (!s) return <Login product={product} onLogin={(n) => setS(normalizeSession(n))} />;
  if (fatalError) return <FatalErrorScreen message={fatalError} />;

  async function logout() {
    try { await api('/logout', { method: 'POST', csrf: s.csrf, body: '{}' }); }
    finally { setS(null); }
  }

  async function impersonate(username) {
    try {
      const next = await api(`/users/${username}/impersonate`, {
        method: 'POST',
        csrf: s.csrf,
      });
      setS(normalizeSession(next));
      setPage('overview');
    } catch (x) {
      window.alert(x.message);
    }
  }

  async function stopImpersonation() {
    try {
      const next = await api('/impersonation/stop', { method: 'POST', csrf: s.csrf });
      setS(normalizeSession(next));
      setPage('overview');
    } catch (x) {
      window.alert(x.message);
    }
  }

  const allowed = s.role === 'admin' ? ADMIN_PAGES : CLIENT_PAGES;
  const safePage = allowed.includes(page) ? page : 'overview';
  const content =
      safePage === 'overview' ? <Overview session={s} setPage={setPage} /> :
      safePage === 'users' ? <Users session={s} onImpersonate={impersonate} /> :
        safePage === 'websites' ? <Websites session={s} /> :
          safePage === 'apps' ? <Applications session={s} /> :
          safePage === 'files' ? <Files session={s} /> :
            safePage === 'databases' ? <Databases session={s} /> :
              safePage === 'backups' ? <Backups session={s} /> :
            safePage === 'dns' ? <DnsManager session={s} /> :
              safePage === 'email' ? <Emails session={s} /> :
                safePage === 'ssl' ? <Ssl session={s} /> :
                    safePage === 'tickets' ? <Tickets session={s} /> :
                      safePage === 'audit' ? <Audit /> :
                        safePage === 'licenses' ? <Licenses /> : <Settings session={s} product={product} onProductChange={(next) => setProduct((current) => ({ ...current, ...next }))} />;

  return (
    <div className="app-shell">
      <Sidebar
        session={s}
        page={page}
        setPage={setPage}
        onLogout={logout}
        onStopImpersonation={stopImpersonation}
        product={product}
      />
      <main className="content">
        <Topbar session={s} page={safePage} setPage={setPage} onLogout={logout} />
        <PageErrorBoundary resetKey={safePage} onRecover={() => setPage('overview')}>
          {content}
        </PageErrorBoundary>
      </main>
    </div>
  );
}

export {
  api, asArray, normalizeSession, DEFAULT_PRODUCT, ADMIN_PAGES, CLIENT_PAGES, pagesForSession,
  PanelErrorBoundary, PageErrorBoundary, FatalErrorScreen, Login, Sidebar, Topbar,
  Overview, Users, Websites, Applications, Files, Databases, Backups, DnsManager,
  Emails, Ssl, Tickets, Audit, Licenses, Settings,
};
