import React, { lazy, Suspense, useEffect, useState } from 'react';
import {
  api, normalizeSession, DEFAULT_PRODUCT, pagesForSession,
  FatalErrorScreen, Login, Sidebar, Topbar, PageErrorBoundary,
} from '../legacy.jsx';
import { navigate, pageFromPath, ROUTES } from './routes.js';
import '../database-viewer.css';
import '../tool-links.css';

const pages = {
  overview: lazy(() => import('../pages/DashboardPage.jsx')),
  users: lazy(() => import('../pages/UsersPage.jsx')),
  websites: lazy(() => import('../pages/WebsitesPage.jsx')),
  apps: lazy(() => import('../pages/WordPressPage.jsx')),
  tools: lazy(() => import('../pages/HostingToolsPage.jsx')),
  store: lazy(() => import('../pages/StorePage.jsx')),
  files: lazy(() => import('../pages/FilesPage.jsx')),
  databases: lazy(() => import('../pages/DatabasesPage.jsx')),
  backups: lazy(() => import('../pages/BackupsPage.jsx')),
  dns: lazy(() => import('../pages/DomainsPage.jsx')),
  email: lazy(() => import('../pages/MailPage.jsx')),
  security: lazy(() => import('../pages/MailSecurityPage.jsx')),
  firewall: lazy(() => import('../pages/FirewallPage.jsx')),
  storage: lazy(() => import('../pages/StoragePage.jsx')),
  updates: lazy(() => import('../pages/UpdatesPage.jsx')),
  ssl: lazy(() => import('../pages/CertificatesPage.jsx')),
  tickets: lazy(() => import('../pages/SupportPage.jsx')),
  audit: lazy(() => import('../pages/ActivityPage.jsx')),
  licenses: lazy(() => import('../pages/OpenSourcePage.jsx')),
  settings: lazy(() => import('../pages/SettingsPage.jsx')),
};

export default function App() {
  const [session, setSession] = useState(null);
  const [product, setProduct] = useState(DEFAULT_PRODUCT);
  const [checking, setChecking] = useState(true);
  const [page, setPageState] = useState(() => pageFromPath(window.location.pathname));
  const [fatalError, setFatalError] = useState('');
  const setPage = (next, replace = false) => navigate(next, replace);

  useEffect(() => {
    const syncRoute = () => setPageState(pageFromPath(window.location.pathname));
    window.addEventListener('popstate', syncRoute);
    if (window.location.pathname === '/') navigate('overview', true);
    return () => window.removeEventListener('popstate', syncRoute);
  }, []);

  useEffect(() => {
    const onError = (event) => setFatalError(String(event?.error?.message || event?.message || 'Unexpected runtime error.'));
    const onRejection = (event) => setFatalError(String(event?.reason?.message || event?.reason || 'Unhandled promise rejection.'));
    window.addEventListener('error', onError);
    window.addEventListener('unhandledrejection', onRejection);
    return () => {
      window.removeEventListener('error', onError);
      window.removeEventListener('unhandledrejection', onRejection);
    };
  }, []);

  useEffect(() => {
    Promise.allSettled([api('/session'), api('/product')]).then(([sessionResult, productResult]) => {
      if (sessionResult.status === 'fulfilled') setSession(normalizeSession(sessionResult.value));
      if (productResult.status === 'fulfilled') setProduct((current) => ({ ...current, ...productResult.value }));
      setChecking(false);
    });
  }, []);

  useEffect(() => { document.title = `${product.panel_name || 'MassPanel'} · ${page}`; }, [product.panel_name, page]);

  if (checking) return <div className="loading">MassPanel</div>;
  if (!session) return <Login product={product} onLogin={(next) => { setSession(normalizeSession(next)); setPage('overview', true); }} />;
  if (fatalError) return <FatalErrorScreen message={fatalError} />;

  const allowed = pagesForSession(session);
  const safePage = allowed.includes(page) ? page : 'overview';
  if (safePage !== page) setTimeout(() => setPage('overview', true), 0);
  const Page = pages[safePage];

  async function logout() {
    try { await api('/logout', { method: 'POST', csrf: session.csrf, body: '{}' }); }
    finally { setSession(null); window.history.replaceState({}, '', '/'); }
  }

  async function impersonate(username) {
    try {
      setSession(normalizeSession(await api(`/users/${username}/impersonate`, { method: 'POST', csrf: session.csrf })));
      setPage('overview');
    } catch (error) { window.alert(error.message); }
  }

  async function stopImpersonation() {
    try {
      setSession(normalizeSession(await api('/impersonation/stop', { method: 'POST', csrf: session.csrf })));
      setPage('overview');
    } catch (error) { window.alert(error.message); }
  }

  const pageProps = safePage === 'overview' ? { session, setPage }
    : safePage === 'users' ? { session, onImpersonate: impersonate }
      : safePage === 'settings' ? { session, product, onProductChange: (next) => setProduct((current) => ({ ...current, ...next })) }
        : safePage === 'audit' || safePage === 'licenses' ? {} : { session };

  return (
    <div className="app-shell">
      <Sidebar session={session} page={safePage} setPage={setPage} onLogout={logout} onStopImpersonation={stopImpersonation} product={product} />
      <main className="content">
        <Topbar session={session} page={safePage} setPage={setPage} onLogout={logout} />
        <PageErrorBoundary resetKey={safePage} onRecover={() => window.location.assign(ROUTES.overview)}>
          <Suspense fallback={<div className="loading">Loading {safePage}…</div>}><Page {...pageProps} /></Suspense>
        </PageErrorBoundary>
      </main>
    </div>
  );
}
