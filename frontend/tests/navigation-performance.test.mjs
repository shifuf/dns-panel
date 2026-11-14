import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const vueRouter = require('vue-router');
const tick = () => new Promise(setImmediate);
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

function harness({ request, component } = {}) {
  const values = new Map();
  const storage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
  };
  const window = new EventTarget();
  window.setTimeout = setTimeout;
  const calls = [];
  const chunks = [];
  const api = {
    get: path => {
      calls.push(path);
      return request?.(path) ?? Promise.resolve({ data: path === '/auth/setup-status' ? { setupComplete: true } : { user: { id: 1 } } });
    },
    post: async () => ({ data: { token: 'new-token', user: { id: 1 } } }),
  };
  const modules = new Map();
  function load(relative) {
    const url = new URL(relative, import.meta.url);
    if (modules.has(url.href)) return modules.get(url.href);
    let source = readFileSync(url, 'utf8');
    if (url.pathname.endsWith('/router/index.ts')) source += '\nexports.testSession = hasValidSession;';
    const code = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
    }).outputText;
    const module = { exports: {} };
    modules.set(url.href, module.exports);
    const resolve = name => {
      if (name === 'vue-router') return { ...vueRouter, createWebHistory: vueRouter.createMemoryHistory };
      if (name === './api') return { default: api };
      if (name === '@/services/api') return { onUnauthorized: () => () => {} };
      if (name === '@/services/logs') return { logPageAccess: async () => {} };
      if (name.endsWith('.vue')) {
        chunks.push(name);
        return component?.(name) ?? { default: { name, render: () => null } };
      }
      if (name.startsWith('@/')) return load(`../src/${name.slice(2)}.ts`);
      if (name.startsWith('.')) return load(new URL(`${name}.ts`, url).href);
      return require(name);
    };
    new Function('require', 'module', 'exports', 'localStorage', 'window', 'document', code)(
      resolve, module, module.exports, storage, window, { title: 'Test' },
    );
    return module.exports;
  }
  const auth = load('../src/services/auth.ts');
  const routes = load('../src/router/index.ts');
  return { auth, routes, router: routes.default, calls, chunks, storage };
}

test('warm route guards reuse setup and session checks instead of repeating network requests', async () => {
  const h = harness();
  h.auth.saveAuthData('token', { id: 1 });
  await h.router.push('/settings');
  await h.router.push('/logs');
  await h.router.push('/ssl');
  assert.equal(h.calls.filter(path => path === '/auth/setup-status').length, 1);
  assert.equal(h.calls.filter(path => path === '/auth/me').length, 1);
});

test('concurrent cold setup checks share a single request', async () => {
  const gate = deferred();
  const h = harness({ request: path => path === '/auth/setup-status' ? gate.promise : undefined });
  const waiting = [h.auth.getSetupStatus(), h.auth.getSetupStatus(), h.auth.getSetupStatus()];
  assert.equal(h.calls.length, 1);
  gate.resolve({ data: { setupComplete: true } });
  await Promise.all(waiting);
});

test('cold navigation loads its page while setup is pending but waits for session validation before entering', async () => {
  const setup = deferred();
  const session = deferred();
  const page = deferred();
  const h = harness({
    request: path => path === '/auth/setup-status' ? setup.promise : session.promise,
    component: name => name.includes('SettingsPage') ? page.promise : undefined,
  });
  h.auth.saveAuthData('token', { id: 1 });
  const navigating = h.routes.navigation.navigate('/settings');
  await tick();
  assert.equal(h.chunks.filter(name => name.includes('SettingsPage')).length, 1);
  assert.deepEqual(h.calls, ['/auth/setup-status']);
  assert.notEqual(h.router.currentRoute.value.name, 'Settings');
  setup.resolve({ data: { setupComplete: true } });
  await tick();
  assert.deepEqual(h.calls, ['/auth/setup-status', '/auth/me']);
  page.resolve({ default: { render: () => null } });
  await tick();
  assert.notEqual(h.router.currentRoute.value.name, 'Settings');
  session.resolve({ data: { user: { id: 1 } } });
  assert.equal(await navigating, true);
  assert.equal(h.router.currentRoute.value.name, 'Settings');
  assert.equal(h.chunks.filter(name => name.includes('SettingsPage')).length, 1);
});

test('early page loading still redirects unfinished setup without probing authentication', async () => {
  const h = harness({ request: path => path === '/auth/setup-status' ? Promise.resolve({ data: { setupComplete: false } }) : undefined });
  h.auth.saveAuthData('token', { id: 1 });
  await h.router.push('/settings');
  assert.equal(h.router.currentRoute.value.name, 'Setup');
  assert.deepEqual(h.calls, ['/auth/setup-status']);
});

test('early page loading preserves public registration access and rejects invalid private sessions', async () => {
  const publicPage = harness();
  await publicPage.router.push('/register');
  assert.equal(publicPage.router.currentRoute.value.name, 'Register');
  assert.deepEqual(publicPage.calls, ['/auth/setup-status']);

  const privatePage = harness({ request: path => path === '/auth/me' ? Promise.reject(new Error('Invalid token')) : undefined });
  privatePage.auth.saveAuthData('invalid-token', { id: 1 });
  await privatePage.router.push('/settings');
  assert.equal(privatePage.router.currentRoute.value.name, 'Login');
  assert.equal(privatePage.router.currentRoute.value.query.redirect, '/settings');
});

test('a pre-initialization setup response cannot overwrite completed setup', async () => {
  const gate = deferred();
  const h = harness({ request: path => path === '/auth/setup-status' ? gate.promise : undefined });
  const stale = h.auth.getSetupStatus();
  await h.auth.initializeSetup({ username: 'test', password: 'test-only' });
  gate.resolve({ data: { setupComplete: false } });
  await stale;
  assert.equal((await h.auth.getSetupStatus()).data.setupComplete, true);
});

test('a new session starts its own probe while the previous session is still pending', async () => {
  const probes = [];
  const h = harness({ request: path => {
    if (path !== '/auth/me') return;
    const gate = deferred();
    probes.push(gate);
    return gate.promise;
  } });
  h.auth.saveAuthData('old', { id: 1 });
  const oldProbe = h.routes.testSession();
  h.auth.saveAuthData('new', { id: 2 });
  const newProbe = h.routes.testSession();
  assert.equal(probes.length, 2);
  probes[0].resolve({ data: { user: { id: 1 } } });
  assert.equal(await oldProbe, false);
  const sameProbe = h.routes.testSession();
  assert.equal(probes.length, 2, 'Old completion must not clear the newer in-flight probe');
  probes[1].resolve({ data: { user: { id: 2 } } });
  assert.equal(await newProbe, true);
  assert.equal(await sameProbe, true);
});

test('a completed old probe never marks a replacement session verified', async () => {
  const gate = deferred();
  const h = harness({ request: path => path === '/auth/me' ? gate.promise : undefined });
  h.auth.saveAuthData('old', { id: 1 });
  const oldProbe = h.routes.testSession();
  h.auth.saveAuthData('new', { id: 2 });
  gate.resolve({ data: { user: { id: 1 } } });
  assert.equal(await oldProbe, false);
});

test('intent prefetch deduplicates a pending page import and shares it with navigation', async () => {
  const gate = deferred();
  const h = harness({ component: name => name.includes('SettingsPage') ? gate.promise : undefined });
  h.auth.saveAuthData('token', { id: 1 });
  assert.ok(h.routes.navigation, 'Navigation controller must expose intent prefetch');
  const loads = [h.routes.navigation.prefetch('/settings'), h.routes.navigation.prefetch('/settings')];
  await tick();
  assert.equal(h.chunks.filter(name => name.includes('SettingsPage')).length, 1);
  const navigating = h.routes.navigation.navigate('/settings');
  await tick();
  assert.equal(h.chunks.filter(name => name.includes('SettingsPage')).length, 1);
  gate.resolve({ default: { render: () => null } });
  assert.deepEqual(await Promise.all(loads), [true, true]);
  assert.equal(await navigating, true);
});

test('a failed speculative import stays silent and can be retried', async () => {
  let attempt = 0;
  const h = harness({ component: name => {
    if (name.includes('SettingsPage') && ++attempt === 1) throw new Error('Temporary chunk failure');
  } });
  assert.ok(h.routes.navigation, 'Navigation controller must expose intent prefetch');
  assert.equal(await h.routes.navigation.prefetch('/settings'), false);
  assert.equal(h.routes.navigation.state.error, '');
  assert.equal(await h.routes.navigation.prefetch('/settings'), true);
  assert.equal(attempt, 2);
});

test('navigation feedback starts at click time and ends after the target page loads', async () => {
  const gate = deferred();
  const h = harness({ component: name => name.includes('SettingsPage') ? gate.promise : undefined });
  h.auth.saveAuthData('token', { id: 1 });
  assert.ok(h.routes.navigation, 'Navigation controller must expose pending feedback');
  const navigating = h.routes.navigation.navigate('/settings');
  assert.equal(h.routes.navigation.state.pendingPath, '/settings');
  gate.resolve({ default: { render: () => null } });
  assert.equal(await navigating, true);
  assert.equal(h.routes.navigation.state.pendingPath, '');
  assert.equal(h.routes.navigation.state.error, '');
});

test('failed page navigation stops the pending state and provides a working retry', async () => {
  let available = false;
  const h = harness({ component: name => {
    if (name.includes('SettingsPage') && !available) throw new Error('Temporary chunk failure');
  } });
  h.auth.saveAuthData('token', { id: 1 });
  assert.ok(h.routes.navigation, 'Navigation controller must expose retry feedback');
  assert.equal(await h.routes.navigation.navigate('/settings'), false);
  assert.equal(h.routes.navigation.state.pendingPath, '');
  assert.ok(h.routes.navigation.state.error);
  available = true;
  assert.equal(await h.routes.navigation.retry(), true);
  assert.equal(h.routes.navigation.state.error, '');
});

test('an older cancelled navigation cannot clear feedback for the newest click', async () => {
  const h = harness();
  h.auth.saveAuthData('token', { id: 1 });
  assert.ok(h.routes.navigation, 'Navigation controller must preserve the current intent');
  const settings = deferred();
  const logs = deferred();
  h.router.beforeEach(to => to.path === '/settings' ? settings.promise : logs.promise);
  const first = h.routes.navigation.navigate('/settings');
  await tick();
  const second = h.routes.navigation.navigate('/logs');
  await tick();
  settings.resolve(true);
  await first;
  assert.equal(h.routes.navigation.state.pendingPath, '/logs');
  logs.resolve(true);
  assert.equal(await second, true);
  assert.equal(h.routes.navigation.state.pendingPath, '');
});

test('double-clicking the same slow page keeps feedback until its newest navigation completes', async () => {
  const h = harness();
  h.auth.saveAuthData('token', { id: 1 });
  const guards = [];
  h.router.beforeEach(() => { const gate = deferred(); guards.push(gate); return gate.promise; });
  const first = h.routes.navigation.navigate('/settings');
  await tick();
  const second = h.routes.navigation.navigate('/settings');
  await tick();
  guards[0].resolve(true);
  await first;
  assert.equal(h.routes.navigation.state.pendingPath, '/settings');
  guards[1].resolve(true);
  await second;
  assert.equal(h.routes.navigation.state.pendingPath, '');
});

test('clicking the current page does not leave a pending indicator behind', async () => {
  const h = harness();
  h.auth.saveAuthData('token', { id: 1 });
  await h.routes.navigation.navigate('/settings');
  assert.equal(await h.routes.navigation.navigate('/settings'), true);
  assert.equal(h.routes.navigation.state.pendingPath, '');
});
