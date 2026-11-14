import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const { createPinia, setActivePinia } = require('pinia');

function harness(overrides = {}, browser = {}) {
  const values = browser.values || new Map();
  const storage = browser.storage || {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
  };
  const window = browser.window || new EventTarget();
  const modules = new Map();
  function load(relative) {
    const url = new URL(relative, import.meta.url);
    if (modules.has(url.href)) return modules.get(url.href);
    const source = readFileSync(url, 'utf8').replace('import.meta.env.BASE_URL', "'/'");
    const code = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
    }).outputText;
    const module = { exports: {} };
    const resolve = name => {
      if (Object.hasOwn(overrides, name)) return overrides[name];
      if (name === './api') return { default: {} };
      if (name.startsWith('@/')) return load(`../src/${name.slice(2)}.ts`);
      if (name.startsWith('.')) return load(new URL(`${name}.ts`, url).href);
      return require(name);
    };
    new Function('require', 'module', 'exports', 'localStorage', 'window', code)(resolve, module, module.exports, storage, window);
    modules.set(url.href, module.exports);
    return module.exports;
  }
  const auth = load('../src/services/auth.ts');
  return { values, storage, window, auth, load };
}

function sharedBrowser() {
  const values = new Map();
  const tabs = [];
  const pending = [];
  function tab(overrides = {}) {
    const window = new EventTarget();
    let reloads = 0;
    window.location = { reload: () => { reloads += 1; } };
    const storage = {
      getItem: key => values.get(key) ?? null,
      setItem(key, value) {
        const oldValue = storage.getItem(key);
        const newValue = String(value);
        values.set(key, newValue);
        if (oldValue !== newValue) notify(key, oldValue, newValue);
      },
      removeItem(key) {
        const oldValue = storage.getItem(key);
        values.delete(key);
        if (oldValue !== null) notify(key, oldValue, null);
      },
      clear() { values.clear(); notify(null, null, null); },
    };
    function notify(key, oldValue, newValue) {
      for (const other of tabs) {
        if (other.window === window) continue;
        pending.push(() => other.window.dispatchEvent(Object.assign(new Event('storage'), {
          key, oldValue, newValue, storageArea: other.storage,
        })));
      }
    }
    const result = { ...harness(overrides, { values, storage, window }), reloads: () => reloads };
    tabs.push(result);
    return result;
  }
  return { tab, flush: () => { while (pending.length) pending.shift()(); } };
}

test('logout removes cached credentials and active user data', () => {
  const { auth, storage } = harness();
  auth.saveAuthData('first-token', { id: 1 });
  storage.setItem('dns_cached_credentials', '[{"id":7,"name":"private account"}]');
  storage.setItem('ssl_selected_credential', '7');
  storage.setItem('dns-panel-theme', 'dark');
  auth.clearAuthData();
  assert.equal(storage.getItem('token'), null);
  assert.equal(storage.getItem('dns_cached_credentials'), null);
  assert.equal(storage.getItem('ssl_selected_credential'), null);
  assert.equal(storage.getItem('dns-panel-theme'), 'dark');
});

test('dashboard preferences stay with their owner across account switches', () => {
  const { auth, storage } = harness();
  auth.saveAuthData('one', { id: 1 });
  storage.setItem('dns_dashboard_domain_tags', '{"private.example":["mine"]}');
  auth.clearAuthData();
  auth.saveAuthData('two', { id: 2 });
  assert.equal(storage.getItem('dns_dashboard_domain_tags'), null);
  auth.clearAuthData();
  auth.saveAuthData('one-again', { id: 1 });
  assert.equal(storage.getItem('dns_dashboard_domain_tags'), '{"private.example":["mine"]}');
});

test('saving settings for the current session preserves its cache', () => {
  const { auth, storage } = harness();
  auth.saveAuthData('one', { id: 1 });
  storage.setItem('dns_cached_credentials', '[{"id":7}]');
  auth.saveAuthData('one', { id: 1, username: 'renamed' });
  assert.equal(storage.getItem('dns_cached_credentials'), '[{"id":7}]');
});

test('corrupt saved user data does not crash navigation', () => {
  const { auth, storage } = harness();
  storage.setItem('user', '{broken');
  assert.equal(auth.getStoredUser(), null);
});

test('logout clears Pinia credentials and ignores an old in-flight response', async () => {
  let resolveCredentials;
  const pending = new Promise(resolve => { resolveCredentials = resolve; });
  const { auth, load, storage } = harness({
    '@/services/dnsCredentials': {
      getProviders: async () => ({ data: { providers: [{ type: 'cloudflare', capabilities: { supportsRecordManagement: true } }] } }),
      getDnsCredentials: () => pending,
    },
  });
  auth.saveAuthData('one', { id: 1 });
  setActivePinia(createPinia());
  const store = load('../src/stores/provider.ts').useProviderStore();
  store.credentials = [{ id: 7, provider: 'cloudflare' }];
  const loading = store.loadData();
  auth.clearAuthData();
  assert.deepEqual(store.credentials, []);
  auth.saveAuthData('two', { id: 2 });
  resolveCredentials({ data: { credentials: [{ id: 7, provider: 'cloudflare' }] } });
  await loading;
  assert.deepEqual(store.credentials, []);
  assert.equal(storage.getItem('dns_cached_credentials'), null);
});

test('a delayed unauthorized response cannot log out a newer session', async () => {
  const { auth, load, storage } = harness();
  const api = load('../src/services/api.ts').default;
  auth.saveAuthData('old-session', { id: 1 });
  let rejectRequest;
  let started;
  const adapterStarted = new Promise(resolve => { started = resolve; });
  api.defaults.adapter = config => new Promise((_resolve, reject) => {
    rejectRequest = () => reject({ config, response: { status: 401, data: { message: '无效或过期的令牌' } } });
    started();
  });
  const request = api.get('/auth/me').catch(() => undefined);
  await adapterStarted;
  auth.saveAuthData('new-session', { id: 2 });
  rejectRequest();
  await request;
  assert.equal(storage.getItem('token'), 'new-session');
});

test('session reset clears the query cache used by the application', () => {
  let queryClient;
  const app = { use(_plugin, options) { if (options?.queryClient) queryClient = options.queryClient; }, config: {}, mount() {} };
  const { auth, load } = harness({
    vue: { createApp: () => app },
    './App.vue': {}, './router': {}, './main.scss': {},
  });
  load('../src/main.ts');
  auth.saveAuthData('one', { id: 1 });
  queryClient.setQueryData(['ssl-certificates'], [{ domain: 'private.example' }]);
  auth.clearAuthData();
  assert.equal(queryClient.getQueryData(['ssl-certificates']), undefined);
});

test('a full preference archive cannot prevent logout', () => {
  const { auth, storage } = harness();
  auth.saveAuthData('one', { id: 1 });
  const setItem = storage.setItem;
  storage.setItem = (key, value) => {
    if (key.startsWith('dns_user_preferences:')) throw new Error('QuotaExceededError');
    setItem(key, value);
  };
  assert.doesNotThrow(() => auth.clearAuthData());
  assert.equal(storage.getItem('token'), null);
});

test('upstream authentication errors preserve the panel session', async () => {
  const { auth, load, storage } = harness();
  const api = load('../src/services/api.ts').default;
  auth.saveAuthData('valid-panel-session', { id: 1 });
  api.defaults.adapter = config => Promise.reject({ config, response: { status: 401, data: { message: '云服务认证失败，请更新服务商密钥' } } });
  await assert.rejects(api.get('/dns-records/zones'));
  assert.equal(storage.getItem('token'), 'valid-panel-session');
});

test('another tab changing accounts clears private stores and queries without deleting its new session', async (t) => {
  const browser = sharedBrowser();
  let resolveCredentials;
  const credentials = new Promise(resolve => { resolveCredentials = resolve; });
  let resolveQuery;
  const pendingQuery = new Promise(resolve => { resolveQuery = resolve; });
  let queryClient;
  t.after(() => queryClient?.clear());
  const app = { use(_plugin, options) { if (options?.queryClient) queryClient = options.queryClient; }, config: {}, mount() {} };
  const first = browser.tab({
    vue: { ...require('vue'), createApp: () => app },
    './App.vue': {}, './router': {}, './main.scss': {},
    '@/services/dnsCredentials': {
      getProviders: async () => ({ data: { providers: [{ type: 'cloudflare', capabilities: { supportsRecordManagement: true } }] } }),
      getDnsCredentials: () => credentials,
    },
  });
  first.auth.saveAuthData('account-a', { id: 1 });
  first.load('../src/main.ts');
  setActivePinia(createPinia());
  const store = first.load('../src/stores/provider.ts').useProviderStore();
  store.credentials = [{ id: 7, provider: 'cloudflare', name: 'account A private credential' }];
  queryClient.setQueryData(['ssl-certificates'], [{ domain: 'account-a.example' }]);
  const querying = queryClient.fetchQuery({ queryKey: ['private-dns-records'], queryFn: () => pendingQuery, gcTime: Infinity }).catch(() => undefined);
  const loading = store.loadData();
  const second = browser.tab();
  second.auth.clearAuthData();
  second.auth.saveAuthData('account-b', { id: 2 });
  second.storage.setItem('dns_cached_credentials', '[{"id":8,"name":"account B credential"}]');
  browser.flush();

  assert.deepEqual(store.credentials, []);
  assert.equal(queryClient.getQueryData(['ssl-certificates']), undefined);
  assert.equal(first.reloads(), 1, 'the old document must discard mounted account-specific state');
  assert.equal(second.reloads(), 0, 'the writing tab does not receive storage events');
  assert.equal(first.storage.getItem('token'), 'account-b');
  assert.equal(first.auth.getStoredUser().id, 2);
  assert.equal(first.storage.getItem('dns_cached_credentials'), '[{"id":8,"name":"account B credential"}]');

  resolveCredentials({ data: { credentials: [{ id: 7, provider: 'cloudflare', name: 'late account A credential' }] } });
  resolveQuery([{ name: 'late.account-a.example' }]);
  await Promise.all([loading, querying]);
  assert.deepEqual(store.credentials, []);
  assert.equal(queryClient.getQueryData(['private-dns-records']), undefined);
  assert.equal(first.storage.getItem('dns_cached_credentials'), '[{"id":8,"name":"account B credential"}]');
});

test('another tab logging out or clearing storage resets the active tab once', () => {
  for (const mode of ['logout', 'clear']) {
    const browser = sharedBrowser();
    const first = browser.tab();
    first.auth.saveAuthData('account-a', { id: 1 });
    const second = browser.tab();
    let resets = 0;
    first.load('../src/services/session.ts').onSessionReset(() => { resets += 1; });
    if (mode === 'logout') second.auth.clearAuthData();
    else second.storage.clear();
    browser.flush();
    assert.equal(resets, 1, mode);
    assert.equal(first.reloads(), 1, mode);
    assert.equal(first.storage.getItem('token'), null, mode);
  }
});

test('another tab editing the same user profile or preferences keeps the current view', () => {
  const browser = sharedBrowser();
  const first = browser.tab();
  first.auth.saveAuthData('account-a', { id: 1, username: 'before' });
  const second = browser.tab();
  let resets = 0;
  first.load('../src/services/session.ts').onSessionReset(() => { resets += 1; });
  second.auth.saveAuthData('account-a', { id: 1, username: 'after' });
  second.storage.setItem('dns_dashboard_domain_tags', '{}');
  browser.flush();
  assert.equal(resets, 0);
  assert.equal(first.reloads(), 0);
  assert.equal(first.auth.getStoredUser().username, 'after');
});

test('another tab changing the stored user identity resets even if the token is unchanged', () => {
  const browser = sharedBrowser();
  const first = browser.tab();
  first.auth.saveAuthData('shared-token', { id: 1 });
  const second = browser.tab();
  let resets = 0;
  first.load('../src/services/session.ts').onSessionReset(() => { resets += 1; });
  second.storage.setItem('user', JSON.stringify({ id: 2 }));
  browser.flush();
  assert.equal(resets, 1);
  assert.equal(first.reloads(), 1);
  assert.equal(first.storage.getItem('token'), 'shared-token');
});

test('a storage event for another storage area does not reset authentication', () => {
  const { auth, load, window, storage } = harness();
  auth.saveAuthData('account-a', { id: 1 });
  let resets = 0;
  load('../src/services/session.ts').onSessionReset(() => { resets += 1; });
  window.dispatchEvent(Object.assign(new Event('storage'), { key: 'token', oldValue: null, newValue: 'unrelated', storageArea: {} }));
  assert.equal(resets, 0);
  assert.equal(storage.getItem('token'), 'account-a');
});
