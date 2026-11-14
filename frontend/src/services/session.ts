/** Reset user data whenever the authenticated session changes. */
const SESSION_RESET_EVENT = 'dns-panel:session-reset';
const preferenceKeys = [
  'dns_dashboard_sync_tasks', 'dns_dashboard_alert_rules', 'dns_dashboard_alert_events',
  'dns_dashboard_saved_views', 'dns_dashboard_domain_tags',
];
const cacheKeys = [
  'dns_cached_credentials', 'dns_selected_provider', 'dns_selected_credential',
  'ssl_selected_credential',
];

export function onSessionReset(handler: () => void): () => void {
  window.addEventListener(SESSION_RESET_EVENT, handler);
  return () => window.removeEventListener(SESSION_RESET_EVENT, handler);
}

export function readSessionUser<T extends { id: number }>(): T | null {
  try {
    const user = JSON.parse(localStorage.getItem('user') || 'null');
    return user && typeof user === 'object' && Number.isFinite(user.id) ? user : null;
  } catch {
    return null;
  }
}

let observedToken = localStorage.getItem('token');
let observedUserId = readSessionUser()?.id ?? null;
let reloadRequested = false;

function rememberSession(): void {
  observedToken = localStorage.getItem('token');
  observedUserId = readSessionUser()?.id ?? null;
}

window.addEventListener('storage', (event: StorageEvent) => {
  if (event.storageArea !== localStorage || ![null, 'token', 'user'].includes(event.key)) return;
  if (localStorage.getItem('token') === observedToken && (readSessionUser()?.id ?? null) === observedUserId) return;
  rememberSession();
  // Reset this document only: the other tab already owns the shared session.
  // Reload also discards user data held in mounted components outside stores.
  window.dispatchEvent(new Event(SESSION_RESET_EVENT));
  if (!reloadRequested) {
    reloadRequested = true;
    window.location.reload();
  }
});

export function clearSession(): void {
  const user = readSessionUser();
  // Preserve local dashboard edits for their owner instead of carrying them
  // into the next account or deleting them at logout.
  if (user) {
    const preferences: Record<string, string> = {};
    for (const key of preferenceKeys) {
      const value = localStorage.getItem(key);
      if (value !== null) preferences[key] = value;
    }
    try {
      localStorage.setItem(`dns_user_preferences:${user.id}`, JSON.stringify(preferences));
    } catch { /* Storage quota must never prevent clearing authentication. */ }
  }
  for (const key of [...cacheKeys, ...preferenceKeys, 'token', 'user']) {
    localStorage.removeItem(key);
  }
  rememberSession();
  window.dispatchEvent(new Event(SESSION_RESET_EVENT));
}

export function saveSession<T extends { id: number }>(token: string, user: T): void {
  const previous = readSessionUser();
  const changed = previous?.id !== user.id || localStorage.getItem('token') !== token;
  if (changed) clearSession();
  localStorage.setItem('token', token);
  localStorage.setItem('user', JSON.stringify(user));
  if (changed) {
    try {
      const preferences = JSON.parse(localStorage.getItem(`dns_user_preferences:${user.id}`) || '{}');
      for (const key of preferenceKeys) {
        if (typeof preferences?.[key] === 'string') localStorage.setItem(key, preferences[key]);
      }
    } catch { /* A damaged optional snapshot must not prevent login. */ }
  }
  rememberSession();
}
