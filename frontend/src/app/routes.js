export const ROUTES = {
  overview: '/dashboard',
  users: '/users',
  websites: '/websites',
  apps: '/applications',
  tools: '/tools',
  store: '/storefront',
  files: '/files',
  databases: '/databases',
  backups: '/backups',
  dns: '/domains',
  email: '/mail',
  security: '/mail-security',
  firewall: '/firewall',
  storage: '/storage',
  updates: '/updates',
  ssl: '/certificates',
  tickets: '/support',
  audit: '/activity',
  licenses: '/open-source',
  settings: '/settings',
};

export const pageFromPath = (pathname) => {
  if (pathname === '/wordpress' || pathname.startsWith('/wordpress/')) return 'apps';
  return Object.entries(ROUTES).find(([, path]) => pathname === path || pathname.startsWith(`${path}/`))?.[0] || 'overview';
};

export function navigate(page, replace = false) {
  const path = ROUTES[page] || ROUTES.overview;
  if (window.location.pathname === path) return;
  window.location[replace ? 'replace' : 'assign'](path);
}
