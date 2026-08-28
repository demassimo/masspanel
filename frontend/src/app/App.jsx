import React, { useEffect, useState } from 'react';
import {
  api, normalizeSession, DEFAULT_PRODUCT, pagesForSession,
  FatalErrorScreen, Login, Sidebar, Topbar, PageErrorBoundary,
} from '../legacy.jsx';
import { navigate, pageFromPath, ROUTES } from './routes.js';
import DashboardPage from '../pages/DashboardPage.jsx';
import UsersPage from '../pages/UsersPage.jsx';
import WebsitesPage from '../pages/WebsitesPage.jsx';
import WordPressPage from '../pages/WordPressPage.jsx';
import HostingToolsPage from '../pages/HostingToolsPage.jsx';
import StorePage from '../pages/StorePage.jsx';
import FilesPage from '../pages/FilesPage.jsx';
import DatabasesPage from '../pages/DatabasesPage.jsx';
import BackupsPage from '../pages/BackupsPage.jsx';
import DomainsPage from '../pages/DomainsPage.jsx';
import MailPage from '../pages/MailPage.jsx';
import MailSecurityPage from '../pages/MailSecurityPage.jsx';
import FirewallPage from '../pages/FirewallPage.jsx';
import StoragePage from '../pages/StoragePage.jsx';
import UpdatesPage from '../pages/UpdatesPage.jsx';
import '../database-viewer.css';
import '../tool-links.css';
import CertificatesPage from '../pages/CertificatesPage.jsx';
import SupportPage from '../pages/SupportPage.jsx';
import ActivityPage from '../pages/ActivityPage.jsx';
import OpenSourcePage from '../pages/OpenSourcePage.jsx';
import SettingsPage from '../pages/SettingsPage.jsx';

const pages = {
  overview: DashboardPage,
  users: UsersPage,
  websites: WebsitesPage,
  apps: WordPressPage,
  tools: HostingToolsPage,
  store: StorePage,
  files: FilesPage,
  databases: DatabasesPage,
  backups: BackupsPage,
  dns: DomainsPage,
  email: MailPage,
  security: MailSecurityPage,
  firewall: FirewallPage,
  storage: StoragePage,
  updates: UpdatesPage,
  ssl: CertificatesPage,
  tickets: SupportPage,
  audit: ActivityPage,
  licenses: OpenSourcePage,
  settings: SettingsPage,
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
        <PageErrorBoundary resetKey={safePage} onRecover={() => setPage('overview')}>
          <Page {...pageProps} />
        </PageErrorBoundary>
      </main>
    </div>
  );
}
