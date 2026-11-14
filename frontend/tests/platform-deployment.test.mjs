import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import ts from 'typescript';
import * as vue from 'vue';
import { parse } from '@vue/compiler-sfc';

const require = createRequire(import.meta.url);
function harness(t, extra = {}) {
  const props = vue.reactive({ show: false, initialCertId: 'wildcard-cert' });
  const certs = vue.ref([{ id: 15, remoteCertId: 'wildcard-cert', domain: '*.example.com', san: '["*.example.com"]', status: 'issued' }]);
  const messages = [];
  const events = [];
  const calls = [];
  const services = {
    deployCertToPlatform: params => { calls.push(params); return Promise.resolve({}); },
    ...extra,
  };
  const deps = {
    vue,
    '@tanstack/vue-query': {
      useQuery: options => ({ data: options.queryKey[0] === 'ssl-all-issued-certs' ? certs : vue.ref(undefined) }),
      useMutation: options => ({ ...options, isPending: vue.ref(false) }),
      useQueryClient: () => ({ invalidateQueries() {} }),
    },
    'naive-ui': { useMessage: () => Object.fromEntries(['success', 'warning', 'error'].map(level => [level, text => messages.push({ level, text })])) },
    'lucide-vue-next': {},
    '@/services/ssl': services,
  };
  function loadHelper(name) {
    const source = readFileSync(new URL('../src/' + name.slice(2) + '.ts', import.meta.url), 'utf8');
    const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
    const module = { exports: {} };
    new Function('module', 'exports', code)(module, module.exports);
    return module.exports;
  }
  const source = parse(readFileSync(new URL('../src/components/SSL/PlatformDeployModal.vue', import.meta.url), 'utf8')).descriptor.scriptSetup.content;
  const code = ts.transpileModule(source + '\nmodule.exports={pdDomains,pdCertId,pdCredId,deployMutation,certNames,toggleSecrets,secretsData,showSecrets,secretsLoading};', { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
  const module = { exports: {} };
  const scope = vue.effectScope();
  scope.run(() => new Function('require', 'module', 'exports', 'defineProps', 'defineEmits', code)(
    name => deps[name] ?? (name.startsWith('@/utils/') ? loadHelper(name) : require(name)), module, module.exports, () => props, () => (...args) => events.push(args),
  ));
  t.after(() => scope.stop());
  return { ...module.exports, props, certs, messages, events, calls };
}

test('opening a wildcard certificate does not invent a CDN deployment target', async t => {
  const h = harness(t); h.props.show = true; await vue.nextTick();
  assert.equal(h.pdDomains.value, '');
  assert.deepEqual(h.certNames.value, ['*.example.com']);
});

test('one-level wildcard allows a covered actual CDN hostname', async t => {
  const h = harness(t); h.pdCertId.value = 'wildcard-cert'; h.pdCredId.value = 3; h.pdDomains.value = 'CDN.Example.com.';
  await h.deployMutation.mutationFn();
  assert.deepEqual(h.calls[0].domains, ['cdn.example.com']);
});

test('Qiniu accepts its existing leading-dot wildcard domain notation', async t => {
  const h = harness(t); h.pdCertId.value = 'wildcard-cert'; h.pdCredId.value = 3; h.pdDomains.value = '.example.com';
  await h.deployMutation.mutationFn();
  assert.deepEqual(h.calls[0].domains, ['.example.com']);
});

for (const domain of ['example.com', 'cdn.oss.example.com', 'https://cdn.example.com/path', 'unrelated.example.net']) {
  test('deployment rejects an uncovered or invalid target: ' + domain, t => {
    const h = harness(t); h.pdCertId.value = 'wildcard-cert'; h.pdCredId.value = 3; h.pdDomains.value = domain;
    assert.throws(() => h.deployMutation.mutationFn());
    assert.equal(h.calls.length, 0);
  });
}

test('partial binding failure remains visible instead of closing with a success toast', t => {
  const h = harness(t);
  h.deployMutation.onSuccess({ message: 'Uploaded; binding failed', data: { platformCertId: 'uploaded', results: [{ domain: 'cdn.example.com', ok: false, error: 'upstream rejected binding' }] } });
  assert.ok(h.messages.some(m => m.level === 'warning'));
  assert.ok(!h.messages.some(m => m.level === 'success'));
  assert.ok(!h.events.some(e => e[0] === 'update:show' && e[1] === false));
});

test('late secret response cannot repopulate another selected credential', async t => {
  let resolve;
  const h = harness(t, { getPlatformCredentialSecrets: () => new Promise(r => { resolve = r; }) });
  h.props.show = true; h.pdCredId.value = 3; await vue.nextTick();
  const pending = h.toggleSecrets();
  h.pdCredId.value = 4; await vue.nextTick();
  resolve({ data: { id: 3, secrets: { secretKey: 'old-test-value' } } }); await pending;
  assert.equal(h.secretsData.value, null);
  assert.equal(h.secretsLoading.value, false);
});
