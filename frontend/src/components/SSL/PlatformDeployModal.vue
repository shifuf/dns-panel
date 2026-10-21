<template>
  <NModal :show="props.show" preset="dialog" title="上传证书到平台" :mask-closable="false" style="max-width: 560px;" @update:show="(v: boolean) => emit('update:show', v)">
    <div class="space-y-4 pt-2">
      <NAlert type="info" :bordered="false">
        读取面板已签发的证书（Let's Encrypt / 腾讯云）上传到平台，并自动绑定到指定 CDN 域名。
        acme.sh 自动续期成功后会自动重新上传新证书并替换。
      </NAlert>
      <NFormItem label="选择证书" required>
        <NSelect v-model:value="pdCertId" :options="certOptions" filterable placeholder="选择面板中已签发的证书" />
      </NFormItem>
      <NFormItem label="目标平台" required>
        <NSelect
          v-model:value="pdProvider"
          :options="[
            { label: '七牛云（官方 API · AccessKey）', value: 'qiniu' },
            { label: '又拍云（模拟登录 · 账号密码）', value: 'upyun' },
            { label: '腾讯云（SSL 证书库 + CDN 域名绑定）', value: 'tencent' },
          ]"
        />
      </NFormItem>
      <NFormItem label="平台凭证" required>
        <div class="w-full space-y-2">
          <NSelect
            v-model:value="pdCredId"
            :options="credentialOptions"
            :placeholder="pdProvider === 'qiniu' ? '选择七牛云 AccessKey 凭证' : pdProvider === 'upyun' ? '选择又拍云账号凭证' : '选择腾讯云凭证（SSL 专属或 DNS 共用）'"
          />
          <div class="flex items-center gap-2">
            <NButton v-if="pdProvider !== 'tencent'" size="tiny" quaternary type="primary" @click="showQuickAdd = !showQuickAdd">
              <template #icon><Plus :size="12" /></template>
              {{ showQuickAdd ? '收起' : '快速添加凭证' }}
            </NButton>
            <NButton
              v-if="pdProvider !== 'tencent' && pdCredId"
              size="tiny"
              quaternary
              :loading="secretsLoading"
              @click="toggleSecrets"
            >
              <template #icon><component :is="showSecrets ? EyeOff : Eye" :size="12" /></template>
              {{ showSecrets ? '隐藏密钥' : '查看密钥' }}
            </NButton>
            <span v-if="pdProvider === 'tencent'" class="text-xs text-slate-400">
              腾讯云复用「腾讯云 SSL / DNSPod」凭证，无需单独创建
            </span>
            <span v-else-if="credentialOptions.length === 0" class="text-xs text-amber-600">
              还没有{{ PLATFORM_LABELS[pdProvider] }}凭证，请先添加
            </span>
          </div>
          <div v-if="showQuickAdd" class="space-y-2 rounded-xl border border-panel-border bg-panel-bg p-3">
            <NInput v-model:value="qName" size="small" placeholder="凭证名称，如：七牛云主账号" />
            <NInput v-model:value="qKey1" size="small" :placeholder="pdProvider === 'qiniu' ? 'AccessKey' : '登录账号'" />
            <NInput
              v-model:value="qKey2"
              size="small"
              type="password"
              show-password-on="click"
              :placeholder="pdProvider === 'qiniu' ? 'SecretKey' : '登录密码'"
            />
            <p v-if="pdProvider === 'upyun'" class="text-xs text-amber-600">
              又拍云没有官方证书 API，将使用账号密码模拟登录控制台；若账号开启验证码/两步验证会失败，需手动到控制台更新。
            </p>
            <div class="flex items-center gap-2">
              <NButton size="tiny" secondary :loading="testMutation.isPending.value" @click="testMutation.mutate()">
                测试连接
              </NButton>
              <NButton
                size="tiny" type="primary"
                :loading="quickAddMutation.isPending.value"
                :disabled="!testResult?.ok"
                :title="testResult?.ok ? '连接已验证，保存凭证' : '请先点击「测试连接」，成功后才能保存'"
                @click="quickAddMutation.mutate()"
              >
                保存
              </NButton>
              <NTag v-if="testResult" size="tiny" :bordered="false" :type="testResult.ok ? 'success' : 'error'">
                {{ testResult.ok ? '连接成功' : '连接失败' }}
              </NTag>
            </div>
            <p v-if="testResult && !testResult.ok" class="break-all text-xs text-red-500">{{ testResult.message }}</p>
          </div>
          <div v-if="showSecrets && secretsData" class="space-y-1.5 rounded-xl border border-panel-border bg-panel-bg p-3">
            <p class="text-xs font-semibold text-slate-600">
              已保存密钥 · {{ secretsData.name }}
              <NTag size="tiny" :bordered="false" type="info" class="ml-1">{{ PLATFORM_LABELS[secretsData.provider] }}</NTag>
            </p>
            <div
              v-for="(value, key) in secretsData.secrets"
              :key="key"
              class="flex items-center gap-2 text-xs"
            >
              <span class="w-20 shrink-0 text-slate-400">{{ SECRET_FIELD_LABELS[String(key)] || key }}</span>
              <span class="min-w-0 flex-1 break-all font-mono text-slate-600">
                {{ secretsVisible ? value : '••••••••••••' }}
              </span>
              <button
                class="shrink-0 text-slate-400 hover:text-slate-700"
                type="button"
                :title="secretsVisible ? '隐藏' : '显示'"
                @click="secretsVisible = !secretsVisible"
              >
                <component :is="secretsVisible ? EyeOff : Eye" :size="13" />
              </button>
              <button class="shrink-0 text-slate-400 hover:text-slate-700" type="button" title="复制" @click="copySecret(String(value))">
                <Copy :size="13" />
              </button>
            </div>
            <p class="text-[11px] text-slate-400">密钥保存在面板数据库中（加密存储），请勿泄露给他人</p>
          </div>
          <p v-if="showSecrets && !secretsLoading && !secretsData" class="text-xs text-red-500">密钥读取失败</p>
        </div>
      </NFormItem>
      <NFormItem label="绑定域名" required>
        <div class="w-full space-y-1">
          <NInput
            v-model:value="pdDomains"
            type="textarea"
            :rows="3"
            :placeholder="(certNames[0] || 'cdn.example.com') + '，多个域名用逗号分隔'"
          />
          <p class="text-xs text-slate-400">
            证书覆盖：{{ certNames.join('、') || '-' }}；只能绑定证书覆盖范围内的域名
          </p>
          <div v-if="pdProvider === 'upyun'" class="pt-1">
            <p class="mb-1 text-xs text-slate-500">
              你又拍云账号下已接入的域名（点击快选）：
              <span v-if="upyunError" class="text-red-500">加载失败：{{ upyunError }}</span>
              <span v-else-if="upyunDomains.length === 0" class="text-amber-600">暂无（保存凭证后会自动重新获取）</span>
            </p>
            <div class="flex flex-wrap gap-1">
              <NTag
                v-for="d in upyunDomains"
                :key="d.domain"
                size="tiny"
                :bordered="false"
                :type="d.covered ? 'success' : 'default'"
                :class="d.covered ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'"
                :title="d.covered ? `点击添加 ${d.domain}` : '该域名不在任何已签发证书的覆盖范围内'"
                @click="d.covered && addDomain(d.domain)"
              >{{ d.domain }}（{{ d.bucket }}）</NTag>
            </div>
          </div>
        </div>
      </NFormItem>
    </div>
    <template #action>
      <NButton @click="emit('update:show', false)">取消</NButton>
      <NButton
        type="primary"
        :loading="deployMutation.isPending.value"
        :disabled="!pdCertId || !pdCredId || !pdDomains.trim()"
        @click="deployMutation.mutate()"
      >
        上传并绑定
      </NButton>
    </template>
  </NModal>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NModal, NButton, NTag, NAlert, NFormItem, NInput, NSelect, useMessage } from 'naive-ui';
import { Plus, Eye, EyeOff, Copy } from 'lucide-vue-next';
import {
  getSslCertificates, getPlatformCredentials, createPlatformCredential,
  testPlatformCredential, deployCertToPlatform, getPlatformDeployments,
  getPlatformCredentialSecrets,
} from '@/services/ssl';
import type { PlatformCredential, PlatformDeploymentsResponse, UpyunAccountDomain, PlatformDeployment } from '@/services/ssl';
import type { SslCertificate } from '@/types/ssl';

const props = defineProps<{ show: boolean; initialCertId?: string | null }>();
const emit = defineEmits<{ (e: 'update:show', v: boolean): void; (e: 'deployed'): void }>();
const message = useMessage();
const queryClient = useQueryClient();

const PLATFORM_LABELS: Record<string, string> = { qiniu: '七牛云', upyun: '又拍云', tencent: '腾讯云' };

const pdCertId = ref<string | null>(null);
const pdProvider = ref<'qiniu' | 'upyun' | 'tencent'>('qiniu');
const pdCredId = ref<number | null>(null);
const pdDomains = ref('');
const showQuickAdd = ref(false);
const qName = ref('');
const qKey1 = ref('');
const qKey2 = ref('');
const testResult = ref<{ ok: boolean; message: string } | null>(null);

const { data: allIssuedCerts } = useQuery({
  queryKey: ['ssl-all-issued-certs'],
  queryFn: async (): Promise<SslCertificate[]> => {
    const res = await getSslCertificates('all', { page: 1, limit: 200 });
    return (res.data || []).filter(c => c.status === 'issued');
  },
  enabled: computed(() => props.show),
  staleTime: 30_000,
});

const { data: platformDeploymentsData, refetch: refetchDeployments } = useQuery({
  queryKey: ['ssl-platform-deployments'],
  queryFn: async (): Promise<PlatformDeploymentsResponse | undefined> => {
    const res = await getPlatformDeployments();
    return res.data;
  },
  // 弹窗打开时重新拉取：刚保存的又拍云凭证要立刻渲染出已接入域名
  enabled: computed(() => props.show),
  staleTime: 0,
  refetchOnMount: 'always',
});
const platformDeployments = computed<PlatformDeployment[]>(() => {
  const payload = platformDeploymentsData.value as unknown as { deployments?: PlatformDeployment[] } | PlatformDeployment[] | undefined;
  if (Array.isArray(payload)) return payload;
  return payload?.deployments || [];
});
const upyunDomains = computed<UpyunAccountDomain[]>(() => platformDeploymentsData.value?.upyunDomains || []);
const upyunError = computed(() => platformDeploymentsData.value?.upyunError || '');

const { data: platformCredentials } = useQuery({
  queryKey: ['ssl-platform-credentials'],
  queryFn: async (): Promise<PlatformCredential[]> => {
    const res = await getPlatformCredentials();
    const payload = res.data as unknown as { credentials?: PlatformCredential[] } | PlatformCredential[] | undefined;
    if (Array.isArray(payload)) return payload;
    return payload?.credentials || [];
  },
});

const platformsForCertId = (certId?: string | null): string => {
  if (!certId) return '';
  const names = new Set<string>();
  for (const d of platformDeployments.value) {
    if (d.certRemoteId === certId) names.add(PLATFORM_LABELS[d.provider] || d.provider);
  }
  return [...names].join('、');
};

const certOptions = computed(() =>
  (allIssuedCerts.value || [])
    .filter(c => c.status === 'issued' && c.remoteCertId)
    .map(c => {
      const deployed = platformsForCertId(c.remoteCertId);
      const label = `${c.domain}${c.notAfter ? '（到期 ' + formatDate(c.notAfter) + '）' : ''}${deployed ? ' · 已部署: ' + deployed : ''}`;
      return { label, value: c.remoteCertId };
    })
    .filter(o => o.value),
);

const credentialOptions = computed(() =>
  (platformCredentials.value || [])
    .filter(c => c.provider === pdProvider.value)
    .map(c => ({ label: c.name, value: c.id })),
);

const certNames = computed(() => {
  const cert = (allIssuedCerts.value || []).find(c => c.remoteCertId === pdCertId.value);
  if (!cert) return [] as string[];
  const names: string[] = [cert.domain];
  if (Array.isArray(cert.san)) names.push(...cert.san);
  else if (typeof cert.san === 'string' && cert.san) names.push(cert.san);
  return names.filter(Boolean);
});

watch(pdProvider, () => { pdCredId.value = null; testResult.value = null; });
watch(() => props.show, (visible) => {
  if (visible) {
    testResult.value = null;
    showQuickAdd.value = false;
    // 从证书列表页带着具体证书进来时，预选该证书并填入其主域名
    if (props.initialCertId) {
      pdCertId.value = props.initialCertId;
      const cert = (allIssuedCerts.value || []).find(c => c.remoteCertId === props.initialCertId);
      pdDomains.value = cert?.domain || '';
    }
  }
});

function addDomain(domain: string) {
  const current = pdDomains.value.split(/[,,\s]+/).map(s => s.trim()).filter(Boolean);
  if (!current.includes(domain)) current.push(domain);
  pdDomains.value = current.join(', ');
}

// ── 查看已保存的平台凭证密钥 ──
const SECRET_FIELD_LABELS: Record<string, string> = {
  accessKey: 'AccessKey',
  secretKey: 'SecretKey',
  username: '登录账号',
  password: '登录密码',
};
const showSecrets = ref(false);
const secretsVisible = ref(false);
const secretsLoading = ref(false);
const secretsData = ref<{ id: number; name: string; provider: 'qiniu' | 'upyun'; secrets: Record<string, string> } | null>(null);

async function toggleSecrets() {
  showSecrets.value = !showSecrets.value;
  if (!showSecrets.value) return;
  if (!pdCredId.value) return;
  secretsLoading.value = true;
  secretsData.value = null;
  secretsVisible.value = false;
  try {
    const res = await getPlatformCredentialSecrets(pdCredId.value);
    secretsData.value = res.data || null;
  } catch (err: any) {
    message.error(String(err));
  } finally {
    secretsLoading.value = false;
  }
}

async function copySecret(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    message.success('已复制');
  } catch {
    message.error('复制失败，请手动选择复制');
  }
}

watch(pdCredId, () => { showSecrets.value = false; secretsData.value = null; });

const testMutation = useMutation({
  mutationFn: () => {
    const provider = pdProvider.value;
    if (provider === 'tencent') {
      if (!pdCredId.value) throw new Error('请选择腾讯云凭证');
      return testPlatformCredential({ provider, credentialId: pdCredId.value });
    }
    const secrets: Record<string, string> = provider === 'qiniu'
      ? { accessKey: qKey1.value.trim(), secretKey: qKey2.value.trim() }
      : { username: qKey1.value.trim(), password: qKey2.value.trim() };
    return testPlatformCredential({ provider, secrets });
  },
  onSuccess: (res: any) => {
    testResult.value = { ok: true, message: res?.message || '连接成功' };
    message.success(res?.message || '连接成功');
  },
  onError: (err: any) => {
    testResult.value = { ok: false, message: String(err) };
    message.error(String(err));
  },
});

const quickAddMutation = useMutation({
  mutationFn: () => {
    if (!qName.value.trim()) throw new Error('请填写凭证名称');
    const provider = pdProvider.value as 'qiniu' | 'upyun';
    const secrets: Record<string, string> = provider === 'qiniu'
      ? { accessKey: qKey1.value.trim(), secretKey: qKey2.value.trim() }
      : { username: qKey1.value.trim(), password: qKey2.value.trim() };
    if (provider === 'qiniu' && !secrets.accessKey) throw new Error('请填写 AccessKey');
    if (provider === 'upyun' && !secrets.username) throw new Error('请填写登录账号');
    return createPlatformCredential({ name: qName.value.trim(), provider, secrets });
  },
  onSuccess: (res: any) => {
    message.success(res?.message || '平台凭证已添加');
    testResult.value = null;
    queryClient.invalidateQueries({ queryKey: ['ssl-platform-credentials'] });
    queryClient.invalidateQueries({ queryKey: ['ssl-platform-deployments'] });
    showQuickAdd.value = false;
    qName.value = ''; qKey1.value = ''; qKey2.value = '';
    setTimeout(() => {
      const list = (platformCredentials.value || []).filter(c => c.provider === pdProvider.value);
      if (list.length) pdCredId.value = list[list.length - 1].id;
    }, 300);
  },
  onError: (err: any) => message.error(String(err)),
});

const deployMutation = useMutation({
  mutationFn: () => {
    if (!pdCertId.value) throw new Error('请选择要上传的面板证书');
    if (!pdCredId.value) throw new Error('请选择平台凭证');
    const domains = pdDomains.value.split(/[,,\s]+/).map(s => s.trim()).filter(Boolean);
    if (!domains.length) throw new Error('请填写要绑定的 CDN 域名');
    return deployCertToPlatform({
      provider: pdProvider.value,
      credentialId: pdCredId.value,
      certId: pdCertId.value,
      domains,
    });
  },
  onSuccess: (res: any) => {
    message.success(res?.message || '上传成功');
    emit('update:show', false);
    emit('deployed');
    queryClient.invalidateQueries({ queryKey: ['ssl-platform-deployments'] });
  },
  onError: (err: any) => message.error(String(err)),
});

function formatDate(v?: string) {
  if (!v) return '-';
  try { return new Date(v).toLocaleDateString('zh-CN'); } catch { return v; }
}
</script>