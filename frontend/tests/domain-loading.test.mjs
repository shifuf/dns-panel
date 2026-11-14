import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import ts from 'typescript';
import * as vue from 'vue';
import { QueryClient, QueryObserver } from '@tanstack/vue-query';
import { parse } from '@vue/compiler-sfc';

const require = createRequire(import.meta.url);

// Execute the production TypeScript with only its external boundaries replaced.
function loadSource(relativePath, dependencies, expose = '') {
  const path = new URL(relativePath, import.meta.url);
  const source = readFileSync(path, 'utf8');
  const script = relativePath.endsWith('.vue') ? parse(source).descriptor.scriptSetup.content : source;
  const compiled = ts.transpileModule(`${script}\n${expose}`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const module = { exports: {} };
  new Function('require', 'module', 'exports', 'localStorage', 'defineProps', 'defineEmits', 'withDefaults', compiled)(
    (name) => Object.hasOwn(dependencies, name) ? dependencies[name] : require(name),
    module, module.exports, { getItem: () => null, setItem() {} },
    () => ({ show: false, credentials: [] }), () => () => {}, (props, defaults) => ({ ...defaults, ...props }),
  );
  return module.exports;
}

function loadFunction(relativePath, functionName, bindings) {
  const source = parse(readFileSync(new URL(relativePath, import.meta.url), 'utf8')).descriptor.scriptSetup.content;
  const ast = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === functionName);
  assert.ok(declaration, `Missing ${functionName}`);
  const compiled = ts.transpileModule(declaration.getText(ast), {
    compilerOptions: { target: ts.ScriptTarget.ES2020 },
  }).outputText;
  return new Function(...Object.keys(bindings), `${compiled}\nreturn ${functionName};`)(...Object.values(bindings));
}

function observeCachedDomains(t) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } } });
  const innerKey = ['domains-cred', 1];
  const outerKey = ['domains', 'cloudflare', 'all'];
  client.setQueryData(innerKey, [zone(1)]);
  client.setQueryData(outerKey, [zone(1)]);
  const observer = new QueryObserver(client, {
    queryKey: outerKey,
    queryFn: () => client.fetchQuery({ queryKey: innerKey, queryFn: async () => [1, 2, 3, 4, 5].map(zone) }),
  });
  const unsubscribe = observer.subscribe(() => {});
  t.after(() => { unsubscribe(); client.clear(); });
  return { client, result: () => client.getQueryData(outerKey) };
}

const zone = (id) => ({ id: String(id), name: `zone-${id}.example`, status: 'active' });
const credential = (id = 1, updatedAt = '2026-11-14T00:00:00Z') => ({
  id, name: `Account ${id}`, provider: 'cloudflare', updatedAt,
});

function loadDomains(getPage) {
  return loadSource('../src/services/domains.ts', {
    './api': { default: { get: (_path, { params }) => getPage(params) } },
  }).getDomains;
}

function loadDashboard(t, { getDomains, refetch, store } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
  const queries = [];
  const notifications = [];
  const scope = vue.effectScope();
  store ??= vue.reactive({
    selectedProvider: 'cloudflare', selectedCredentialId: 'all', isLoading: false, error: null,
    credentials: [credential()], providers: [],
    getCredentialsByProvider(provider) { return this.credentials.filter(c => c.provider === provider); },
  });
  const services = new Proxy({}, { get: () => async () => ({ data: {} }) });
  const dependencies = {
    vue: { ...vue, onMounted() {} },
    'vue-router': { useRouter: () => ({ push() {} }), useRoute: () => ({ query: {} }) },
    '@tanstack/vue-query': {
      useQueryClient: () => client,
      useMutation: () => ({}),
      useQuery: options => {
        queries.push(options);
        return {
          data: vue.ref(undefined), isLoading: vue.ref(false), isFetching: vue.ref(false), error: vue.ref(null),
          refetch: queries.length === 1 ? (refetch ?? (async () => ({ data: await options.queryFn() }))) : async () => ({}),
        };
      },
    },
    'naive-ui': {
      useMessage: () => Object.fromEntries(['success', 'warning', 'error'].map(level => [level, text => notifications.push({ level, text })])),
      useDialog: () => ({}),
    },
    'lucide-vue-next': {},
    '@/stores/provider': { useProviderStore: () => store },
    '@/stores/breadcrumb': { useBreadcrumbStore: () => ({}) },
    '@/composables/useResponsive': { useResponsive: () => ({ isMobile: vue.ref(false) }) },
    '@/services/domains': { getDomains: getDomains ?? (async () => ({ data: { domains: [zone(1)] } })), refreshDomains: async () => ({}) },
    '@/services/aliyunEsa': { ESA_SUPPORTED_REGIONS: [] },
    '@/services/auth': { getStoredUser: () => null },
    '@/utils/constants': { TABLE_PAGE_SIZE: 20 },
    '@/utils/provider': { getProviderDisplayName: provider => provider },
    '@/utils/formatters': {},
  };
  for (const name of ['logs', 'domainExpiry', 'dashboard', 'ssl']) dependencies[`@/services/${name}`] = services;
  for (const name of ['ProviderAccountTabs', 'AddEsaSiteDialog', 'AddDnsCredentialDialog']) dependencies[`@/components/Dashboard/${name}.vue`] = {};
  const loaded = scope.run(() => loadSource('../src/pages/DashboardPage.vue', dependencies,
    'exports.testApi = { fetchCredentialDomains, handleRefresh, handleBatchRefresh, domainsData, domainsError, domainLoadError };'));
  t.after(() => { scope.stop(); client.clear(); });
  return { ...loaded.testApi, client, queries, notifications, store };
}

test('loads every reported domain when upstream returns a smaller first page', async () => {
  const getDomains = loadDomains(({ page }) => ({ data: { zones: [zone(page)], total: 5, pageSize: 1 } }));
  const result = await getDomains(7);
  assert.deepEqual(result.data.domains.map(d => d.id), ['1', '2', '3', '4', '5']);
  assert.ok(result.data.domains.every(d => d.credentialId === 7));
});

test('does not turn an incomplete paginated response into a successful list', async () => {
  const getDomains = loadDomains(({ page }) => ({ data: { zones: page === 1 ? [zone(1)] : [], total: 5 } }));
  await assert.rejects(() => getDomains(1), /不完整|incomplete/i);
});

test('stops a provider that repeats pages instead of duplicating domains', async () => {
  const getDomains = loadDomains(() => ({ data: { zones: [zone(1)], total: 5 } }));
  await assert.rejects(() => getDomains(1), /不完整|incomplete/i);
});

test('propagates a later page error instead of returning partial domains', async () => {
  const getDomains = loadDomains(({ page }) => {
    if (page > 1) throw new Error('upstream unavailable');
    return { data: { zones: [zone(1)], total: 5 } };
  });
  await assert.rejects(() => getDomains(1), /upstream unavailable/);
});

test('reports the one zone actually visible to the token', async () => {
  const getDomains = loadDomains(() => ({ data: { zones: [zone(1)], total: 1 } }));
  assert.equal((await getDomains(1)).data.domains.length, 1);
});

test('retains a reported total when a later page omits pagination metadata', async () => {
  const getDomains = loadDomains(({ page }) => ({ data: page === 1
    ? { zones: [zone(1)], total: 5 }
    : { zones: [] } }));
  await assert.rejects(() => getDomains(1), /不完整|incomplete/i);
});

test('walks unknown totals until an empty page instead of trusting short batches', async () => {
  const getDomains = loadDomains(({ page }) => ({ data: { zones: page <= 3 ? [zone(page)] : [] } }));
  assert.deepEqual((await getDomains(1)).data.domains.map(d => d.id), ['1', '2', '3']);
});

test('rejects malformed responses instead of showing an empty domain list', async () => {
  const getDomains = loadDomains(() => ({ data: {} }));
  await assert.rejects(() => getDomains(1), /响应格式/);
});

test('refreshing invalidated credential data replaces one cached zone with five', async t => {
  let rows = [zone(1)];
  const app = loadDashboard(t, { getDomains: async () => ({ data: { domains: rows } }) });
  await app.fetchCredentialDomains(credential());
  rows = [1, 2, 3, 4, 5].map(zone);
  await app.client.invalidateQueries({ queryKey: ['domains-cred'] });
  const result = await app.fetchCredentialDomains(credential());
  assert.equal(result.length, 5);
});

test('updating a credential does not reuse the previous token domain list', async t => {
  let rows = [zone(1)];
  const app = loadDashboard(t, { getDomains: async () => ({ data: { domains: rows } }) });
  await app.fetchCredentialDomains(credential());
  rows = [1, 2, 3, 4, 5].map(zone);
  const result = await app.fetchCredentialDomains(credential(1, '2026-11-14T01:00:00Z'));
  assert.equal(result.length, 5);
});

test('adding a credential changes the aggregate query identity', t => {
  const app = loadDashboard(t);
  const before = JSON.stringify(vue.unref(app.queries[0].queryKey));
  app.store.credentials.push(credential(2));
  const after = JSON.stringify(vue.unref(app.queries[0].queryKey));
  assert.notEqual(before, after);
});

test('a failed refresh is reported as failed, never as refreshed', async t => {
  const app = loadDashboard(t, {
    refetch: async options => {
      const error = new Error('upstream unavailable');
      if (options?.throwOnError) throw error;
      return { error, isError: true };
    },
  });
  await app.handleRefresh();
  assert.ok(app.notifications.some(n => n.level === 'error' && n.text.includes('upstream unavailable')));
  assert.equal(app.notifications.some(n => n.level === 'success'), false);
});

test('batch refresh invalidates cached domain lists in other account scopes', async t => {
  const app = loadDashboard(t);
  app.domainsData.value = [{ ...zone(1), credentialId: 1 }];
  const otherScope = ['domains', null, 'all'];
  app.client.setQueryData(otherScope, [zone(1)]);
  await app.handleBatchRefresh();
  assert.equal(app.client.getQueryState(otherScope).isInvalidated, true);
});

test('domain query failures remain visible even when older data exists', t => {
  const app = loadDashboard(t);
  app.domainsData.value = [zone(1)];
  app.domainsError.value = new Error('Cloudflare request failed');
  assert.equal(app.domainLoadError.value, 'Cloudflare request failed');
});

test('retrying after a credential loading failure reloads the credentials', async t => {
  const app = loadDashboard(t);
  app.store.error = '加载凭证失败';
  app.store.loadData = async () => { app.store.error = null; };
  await app.handleRefresh();
  assert.equal(app.domainLoadError.value, '');
});

test('adding zones refreshes child cache before the active aggregate query', async t => {
  const { client, result } = observeCachedDomains(t);
  let mutation;
  const scope = vue.effectScope();
  t.after(() => scope.stop());
  scope.run(() => loadSource('../src/components/Dashboard/AddZoneDialog.vue', {
    vue, 'naive-ui': {}, '@/services/domains': {}, '@/utils/constants': { TABLE_PAGE_SIZE: 20 },
    '@tanstack/vue-query': { useQueryClient: () => client, useMutation: options => { mutation = options; return {}; } },
  }));
  await mutation.onSuccess({ data: { results: [] } });
  await new Promise(setImmediate);
  assert.equal(result().length, 5);
});

test('restoring a backup refreshes credential caches before aggregate domains', async t => {
  const { client, result } = observeCachedDomains(t);
  const refresh = loadFunction('../src/pages/SettingsPage.vue', 'refreshRestoredData', {
    queryClient: client, providerStore: { loadData: async () => {} },
    dnsCredentialPanelKey: vue.ref(0), window: { dispatchEvent() {} }, CustomEvent: class {},
  });
  await refresh();
  assert.equal(result().length, 5);
});

test('updating credentials invalidates cached domains even when timestamps match', async t => {
  const { client, result } = observeCachedDomains(t);
  const submitError = vue.ref('');
  const submit = loadFunction('../src/components/Settings/DnsCredentialManagement.vue', 'handleSubmit', {
    queryClient: client, formName: vue.ref('Account'), formSecrets: vue.ref({ apiToken: 'replacement-test-token' }),
    formProvider: vue.ref('cloudflare'), selectedProviderConfig: vue.ref({ authFields: [] }),
    editing: vue.ref(credential()), submitting: vue.ref(false), submitError,
    updateDnsCredential: async () => {}, createDnsCredential: async () => {},
    loadData: async () => {}, providerStore: { loadData: async () => {} },
    closeDialog() {}, emit() {}, message: { success() {} },
  });
  await submit();
  assert.equal(submitError.value, '');
  assert.equal(result().length, 5);
});

test('successful credential verification refreshes changed remote token permissions', async t => {
  const { client, result } = observeCachedDomains(t);
  const verify = loadFunction('../src/components/Settings/DnsCredentialManagement.vue', 'handleVerify', {
    queryClient: client, verifying: vue.ref(null), verifyResults: vue.ref({}), verifyDetails: vue.ref({}),
    verifyDnsCredential: async () => ({ data: { valid: true, zoneCount: 5 } }),
    message: { success() {}, warning() {} },
  });
  await verify(1);
  assert.equal(result().length, 5);
});

for (const action of ['create', 'dashboard-create', 'update', 'verify', 'delete', 'restore']) {
  test(`${action} credentials discards the previous Tunnel account before returning to the page`, async t => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } } });
    t.after(() => client.clear());
    const keys = [
      ['tunnel-credentials'], ['tunnel-accounts', 1], ['tunnel-zones', 1, 'old-account'],
      ['tunnels', 1, 'old-account'], ['tunnel-config', 1, 'old-account', 'tunnel-1'],
      ['tunnel-cidr-routes', 'tunnel-1', 1, 'old-account'],
      ['tunnel-hostname-routes', 'tunnel-1', 1, 'old-account'],
    ];
    for (const key of keys) client.setQueryData(key, { data: { accounts: [{ id: 'old-account' }] } });
    client.setQueryData(['unrelated-query'], 'keep');
    const common = {
      queryClient: client, loadData: async () => {}, providerStore: { loadData: async () => {} },
      message: { success() {}, warning() {}, error(text) { assert.fail(text); } }, emit() {},
    };
    if (action === 'create' || action === 'dashboard-create' || action === 'update') {
      const submitError = vue.ref('');
      const component = action === 'dashboard-create'
        ? '../src/components/Dashboard/AddDnsCredentialDialog.vue'
        : '../src/components/Settings/DnsCredentialManagement.vue';
      const submit = loadFunction(component, 'handleSubmit', {
        ...common, formName: vue.ref('Account'), formSecrets: vue.ref({ apiToken: 'replacement-test-token' }),
        formProvider: vue.ref('cloudflare'), selectedProviderConfig: vue.ref({ authFields: [] }),
        editing: vue.ref(action === 'update' ? credential() : null), submitting: vue.ref(false), submitError,
        updateDnsCredential: async () => {}, createDnsCredential: async () => {}, closeDialog() {}, close() {},
      });
      await submit();
      assert.equal(submitError.value, '');
    } else if (action === 'verify') {
      const verify = loadFunction('../src/components/Settings/DnsCredentialManagement.vue', 'handleVerify', {
        ...common, verifying: vue.ref(null), verifyResults: vue.ref({}), verifyDetails: vue.ref({}),
        verifyDnsCredential: async () => ({ data: { valid: true } }),
      });
      await verify(1);
    } else if (action === 'delete') {
      let dialog;
      const confirmDelete = loadFunction('../src/components/Settings/DnsCredentialManagement.vue', 'confirmDelete', {
        ...common, deleteDnsCredential: async () => {}, dlg: { warning(options) { dialog = options; } },
      });
      confirmDelete(credential());
      await dialog.onPositiveClick();
    } else {
      const restore = loadFunction('../src/pages/SettingsPage.vue', 'refreshRestoredData', {
        ...common, dnsCredentialPanelKey: vue.ref(0), window: { dispatchEvent() {} }, CustomEvent: class {},
      });
      await restore();
    }
    const accountQuery = {
      queryKey: ['tunnel-accounts', 1],
      queryFn: async () => ({ data: { accounts: [{ id: 'new-account' }] } }),
    };
    const returningPage = new QueryObserver(client, accountQuery);
    assert.notEqual(returningPage.getCurrentResult().data?.data.accounts[0].id, 'old-account',
      'A returning Tunnel page must not select an Account ID from the previous credential');
    for (const key of keys) assert.equal(client.getQueryData(key), undefined, `Old context retained: ${key[0]}`);
    assert.equal((await client.fetchQuery(accountQuery)).data.accounts[0].id, 'new-account');
    assert.equal(client.getQueryData(['unrelated-query']), 'keep');
  });
}
