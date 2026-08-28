import React from 'react';
import LayoutDashboard from '../vendor/lucide/layout-dashboard.js';
import Users from '../vendor/lucide/users.js';
import Monitor from '../vendor/lucide/monitor.js';
import Blocks from '../vendor/lucide/blocks.js';
import Folder from '../vendor/lucide/folder.js';
import Database from '../vendor/lucide/database.js';
import ArchiveRestore from '../vendor/lucide/archive-restore.js';
import Globe from '../vendor/lucide/globe.js';
import Mail from '../vendor/lucide/mail.js';
import ShieldCheck from '../vendor/lucide/shield-check.js';
import LifeBuoy from '../vendor/lucide/life-buoy.js';
import Activity from '../vendor/lucide/activity.js';
import Scale from '../vendor/lucide/scale.js';
import Settings from '../vendor/lucide/settings.js';

const icons = {
  overview: LayoutDashboard, users: Users, websites: Monitor, apps: Blocks, tools: Settings, store: Globe, files: Folder,
  databases: Database, backups: ArchiveRestore, dns: Globe, email: Mail, security: ShieldCheck, firewall: ShieldCheck, ssl: ShieldCheck,
  tickets: LifeBuoy, audit: Activity, licenses: Scale, storage: Database, updates: ArchiveRestore, settings: Settings,
};

export default function PanelIcon({ name, size = 18, strokeWidth = 1.8, ...props }) {
  const nodes = icons[name] || LayoutDashboard;
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"
      aria-hidden="true" focusable="false" {...props}>
      {nodes.map(([tag, attributes], index) => React.createElement(tag, { ...attributes, key: index }))}
    </svg>
  );
}
