import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import ts from 'typescript';
import * as vue from 'vue';
import { parse } from '@vue/compiler-sfc';

const require = createRequire(import.meta.url);
function loadPage(t, credentialService = async () => ({})) {
  const source = parse(readFileSync(new URL('../src/pages/TunnelsPage.vue', import.meta.url), 'utf8')).descriptor.scriptSetup.content;
  const queries = [];
  const refreshed = [];
  const dependencies = {
    vue,
    '@tanstack/vue-query': {
      useQuery(options) {
        const index = queries.length;
        const result = { data: vue.ref(undefined), isLoading: vue.ref(false), isFetching: vue.ref(false), error: vue.ref(null), async refetch() { refreshed.push(index); return {}; } };
        queries.push({ options, ...result });
        return result;
      },
      useMutation(options) { return { ...options, isPending: vue.ref(false) }; },
    },
    'naive-ui': { useMessage: () => ({}), useDialog: () => ({}) },
    'lucide-vue-next': {},
    '@/services/tunnels': {},
    '@/services/dnsCredentials': { getDnsCredentials: credentialService },
    '@/stores/provider': { useProviderStore: () => ({ selectedProvider: 'dnspod', selectedCredentialId: 'all' }) },
    '@/composables/useResponsive': { useResponsive: () => ({ isMobile: vue.ref(true) }) },
    '@/utils/formatters': {},
    '@/utils/constants': { TABLE_PAGE_SIZE: 20 },
    '@/components/Tunnels/TunnelDetailsPanel.vue': {},
    '@/components/Tunnels/TunnelPublicHostnamesDialog.vue': {},
  };
  const script = ts.transpileModule(source + '\nmodule.exports = { credentialId, accountId, ready, page, expandedId, publicHostnamesTunnel, toggleExpand, refetch };', {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const module = { exports: {} };
  const scope = vue.effectScope();
  scope.run(() => new Function('require', 'module', 'exports', script)(name => dependencies[name] ?? require(name), module, module.exports));
  t.after(() => scope.stop());
  return { ...module.exports, queries, refreshed };
}

test('credential loading requests DNS credentials without passing Vue Query context as category', async t => {
  const categories = [];
  const page = loadPage(t, async category => { categories.push(category); return {}; });
  await page.queries[0].options.queryFn({ queryKey: ['tunnel-credentials'] });
  assert.deepEqual(categories, ['dns']);
});

test('Tunnel selection works while global provider is another service and credentials are set to all', async t => {
  const page = loadPage(t);
  page.queries[0].data.value = { data: { credentials: [
    { id: 1, provider: 'dnspod', name: 'Other' },
    { id: 2, provider: 'cloudflare', name: 'CF', isDefault: true },
  ] } };
  await vue.nextTick();
  assert.equal(page.credentialId.value, 2);
  page.queries[1].data.value = { data: { accounts: [{ id: 'account', name: 'Account' }] } };
  await vue.nextTick();
  assert.equal(page.accountId.value, 'account');
  assert.equal(page.ready.value, true);
  assert.equal(page.queries[2].options.enabled.value, true);
});

test('changing account closes old tunnel details and route editor and resets pagination', async t => {
  const page = loadPage(t);
  page.expandedId.value = 'old-tunnel';
  page.publicHostnamesTunnel.value = { id: 'old-tunnel' };
  page.page.value = 3;
  page.accountId.value = 'new-account';
  await vue.nextTick();
  assert.equal(page.expandedId.value, null);
  assert.equal(page.publicHostnamesTunnel.value, null);
  assert.equal(page.page.value, 1);
});

test('refresh retries failed credential discovery before requesting a tunnel list', async t => {
  const page = loadPage(t);
  page.queries[0].error.value = new Error('credentials temporarily unavailable');
  await page.refetch();
  assert.deepEqual(page.refreshed, [0]);
});
