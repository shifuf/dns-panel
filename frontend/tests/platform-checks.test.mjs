import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import ts from 'typescript';
import * as vue from 'vue';
import { parse } from '@vue/compiler-sfc';

function harness(response) {
  const messages = [];
  const deps = {
    vue,
    '@tanstack/vue-query': {
      useQuery: () => ({ data: vue.ref(undefined) }),
      useMutation: options => options,
      useQueryClient: () => ({ invalidateQueries() {} }),
    },
    'naive-ui': { useMessage: () => Object.fromEntries(['success', 'warning', 'error'].map(level => [level, text => messages.push({ level, text })])) },
    'lucide-vue-next': {},
    '@/services/ssl': { checkPlatformDeployments: async () => ({ data: response }) },
    '@/utils/formatters': { formatDateTime: String },
  };
  const source = parse(readFileSync(new URL('../src/pages/PlatformDeploymentsPage.vue', import.meta.url), 'utf8')).descriptor.scriptSetup.content;
  const code = ts.transpileModule(source + '\nmodule.exports={checks,checkFor,runCheck};', { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
  const module = { exports: {} };
  new Function('require', 'module', 'exports', code)(name => deps[name] || {}, module, module.exports);
  return { ...module.exports, messages };
}

test('binding checks distinguish separate accounts deploying the same hostname', () => {
  const h = harness();
  h.checks.value = [
    { deploymentId: 10, provider: 'qiniu', domain: 'cdn.example.com', checked: true, live: { bound: true } },
    { deploymentId: 11, provider: 'qiniu', domain: 'cdn.example.com', checked: true, live: { bound: false } },
  ];
  assert.equal(h.checkFor({ id: 10, provider: 'qiniu', domain: 'cdn.example.com' }).live.bound, true);
  assert.equal(h.checkFor({ id: 12, provider: 'qiniu', domain: 'cdn.example.com' }), null);
});

test('partially failed checks warn instead of claiming success', async () => {
  const h = harness({ checks: [], checked: 1, total: 2, drift: 0 });
  await h.runCheck();
  assert.equal(h.messages[0].level, 'warning');
  assert.match(h.messages[0].text, /1.*未核实/);
});

test('EdgeOne checks use account and hostname when discovery order changes synthetic ids', () => {
  const h = harness();
  h.checks.value = [{ deploymentId: -3, credentialId: 8, provider: 'edgeone', domain: 'cdn.example.com', live: { bound: true } }];
  assert.equal(h.checkFor({ id: -1, credentialId: 8, provider: 'edgeone', domain: 'cdn.example.com' })?.live.bound, true);
  assert.equal(h.checkFor({ id: -3, credentialId: 9, provider: 'edgeone', domain: 'cdn.example.com' }), null);
});

test('EdgeOne checks keep same-account hostnames in separate zones distinct', () => {
  const h = harness();
  h.checks.value = [{ deploymentId: -3, credentialId: 8, siteId: 'zone-b', provider: 'edgeone', domain: 'cdn.example.com', live: { bound: true } }];
  assert.equal(h.checkFor({ id: -3, credentialId: 8, siteId: 'zone-a', provider: 'edgeone', domain: 'cdn.example.com' }), null);
});

test('certificate detail check cannot match an EdgeOne record with the same numeric id', () => {
  const source = parse(readFileSync(new URL('../src/pages/SSLCertificatesPage.vue', import.meta.url), 'utf8')).descriptor.scriptSetup.content;
  const ast = ts.createSourceFile('page.ts', source, ts.ScriptTarget.Latest, true);
  const statement = ast.statements.find(s => ts.isVariableStatement(s) && s.declarationList.declarations.some(d => d.name.getText(ast) === 'checksForCert'));
  const code = ts.transpileModule(statement.getText(ast) + '\nmodule.exports=checksForCert;', { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  const platformDeployments = vue.ref([
    { id: 10, provider: 'edgeone', domain: 'cdn.example.com', certRemoteId: 'other' },
    { id: 10, provider: 'qiniu', domain: 'cdn.example.com', certRemoteId: 'wildcard' },
  ]);
  const platformChecks = vue.ref([{ deploymentId: 10, provider: 'qiniu', domain: 'cdn.example.com' }]);
  const module = { exports: {} };
  new Function('module', 'platformDeployments', 'platformChecks', code)(module, platformDeployments, platformChecks);
  assert.equal(module.exports({ remoteCertId: 'wildcard' }).length, 1);
  assert.equal(module.exports({ remoteCertId: 'other' }).length, 0);
});
