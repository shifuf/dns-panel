<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { NButton, NInput, NModal, NAlert, NTag, NEmpty, NSpin, NDivider, useMessage, useDialog } from 'naive-ui';
import { Plus, Pencil, Trash2, CheckCircle, XCircle, ExternalLink, Database, Eye, EyeOff } from 'lucide-vue-next';
import {
  getDnsCredentials,
  createDnsCredential,
  updateDnsCredential,
  deleteDnsCredential,
  verifyDnsCredential,
  getDnsCredentialSecrets,
  getProviders,
} from '@/services/dnsCredentials';
import type { DnsCredential, ProviderCategory, ProviderConfig, ProviderType } from '@/types/dns';
import { useProviderStore } from '@/stores/provider';
import { normalizeProviderType } from '@/utils/provider';
import { formatDateSafe } from '@/utils/formatters';
import ProviderSelector from './ProviderSelector.vue';

const props = withDefaults(defineProps<{
  openAddSignal?: number;
  presetProvider?: ProviderType | null;
  embedded?: boolean;
  category?: ProviderCategory;
  title?: string;
  description?: string;
}>(), {
  openAddSignal: 0,
  presetProvider: null,
  embedded: false,
  category: 'dns',
  title: 'DNS 账户管理',
  description: '管理您的所有 DNS 服务商账户凭证',
});

const emit = defineEmits<{
  changed: [];
}>();

const message = useMessage();
const dlg = useDialog();
const providerStore = useProviderStore();
const route = useRoute();
const router = useRouter();

const credentials = ref<DnsCredential[]>([]);
const providers = ref<ProviderConfig[]>([]);
const isLoading = ref(true);

// Dialog state
const dialogOpen = ref(false);
const editing = ref<DnsCredential | null>(null);
const formName = ref('');
const formProvider = ref<ProviderType>('cloudflare');
const formSecrets = ref<Record<string, string>>({});
const submitError = ref('');
const submitting = ref(false);
const secretsLoading = ref(false);
const showSecretFields = ref<Record<string, boolean>>({});

// Verify state
const verifying = ref<number | null>(null);
const verifyResults = ref<Record<number, boolean>>({});

const EDGEONE_FALLBACK_PROVIDER: ProviderConfig = {
  type: 'edgeone',
  name: '腾讯云 EdgeOne',
  category: 'acceleration',
  authFields: [
    { key: 'secretId', label: 'SecretId', type: 'text', required: true, placeholder: '输入腾讯云 SecretId' },
    { key: 'secretKey', label: 'SecretKey', type: 'password', required: true, placeholder: '输入腾讯云 SecretKey' },
    { key: 'planId', label: '默认套餐 ID', type: 'text', required: false, placeholder: '可选，创建站点时默认使用' },
    { key: 'endpoint', label: 'API Endpoint', type: 'text', required: false, placeholder: '可选，默认 teo.tencentcloudapi.com' },
  ],
};

function mergeProviders(list: ProviderConfig[]): ProviderConfig[] {
  const map = new Map<ProviderType, ProviderConfig>();

  for (const item of list) {
    const type = normalizeProviderType(item.type);
    const normalized: ProviderConfig = { ...item, type };
    const existing = map.get(type);
    if (!existing) {
      map.set(type, normalized);
      continue;
    }

    const fieldByKey = new Map<string, ProviderConfig['authFields'][number]>();
    [...(existing.authFields || []), ...(normalized.authFields || [])].forEach((field) => {
      if (!fieldByKey.has(field.key)) fieldByKey.set(field.key, field);
    });

    const preferNewName = /token/i.test(existing.name || '') && !/token/i.test(normalized.name || '');
    map.set(type, {
      ...existing,
      name: preferNewName ? normalized.name : existing.name,
      authFields: Array.from(fieldByKey.values()),
      capabilities: existing.capabilities || normalized.capabilities,
    });
  }

  return Array.from(map.values());
}

const selectedProviderConfig = computed(() =>
  providers.value.find(p => p.type === formProvider.value)
);

// Provider credential guides
const PROVIDER_CREDENTIAL_GUIDE: Record<string, { title: string; steps: string[]; link?: string }> = {
  cloudflare: {
    title: 'Cloudflare API Token 获取方式',
    steps: [
      '登录 Cloudflare 控制台',
      '进入「API 令牌」页面：管理账户 → 账户 API 令牌',
      '创建令牌 → 创建自定义令牌',
      '权限添加：区域.DNS（编辑）',
      '如需「自定义主机名」，额外添加：区域.SSL 和证书（编辑）',
      '如需「Tunnels」，额外添加：账户.Cloudflare Tunnel（编辑）',
      '资源选择：包含 → 所有区域',
      '建议额外添加：区域（Zone）读取',
      '创建并复制 Token',
    ],
    link: 'https://dash.cloudflare.com/profile/api-tokens',
  },
  aliyun: {
    title: '阿里云 AccessKey 获取方式',
    steps: [
      '登录阿里云控制台',
      '点击右上角头像 → AccessKey 管理',
      '创建 AccessKey 或使用已有的 AccessKey',
      '建议创建 RAM 子账号并授予 DNS 相关权限',
    ],
    link: 'https://ram.console.aliyun.com/manage/ak',
  },
  dnspod: {
    title: '腾讯云（两种方式）',
    steps: [
      '方式一：使用腾讯云 API3.0（SecretId/SecretKey）',
      '登录 DNSPod 控制台 → 账号中心 → 密钥管理 → 创建 API 密钥',
      '复制 SecretId 和 SecretKey 并填写到前两个输入框',
      '方式二：使用 DNSPod Token（传统）',
      '登录 DNSPod 控制台 → 账号中心 → 密钥管理 → 创建 DNSPod Token',
      '将 ID 与 Token 分别填写到下方的 ID 与 Token 输入框',
    ],
    link: 'https://console.dnspod.cn/account/token/apikey',
  },
  dnspod_token: {
    title: 'DNSPod Token 获取方式',
    steps: [
      '登录 DNSPod 控制台',
      '进入 账号中心 → 密钥管理',
      '创建 DNSPod Token（传统 API Token）',
      '分别复制 Token ID 与 Token',
    ],
    link: 'https://console.dnspod.cn/account/token',
  },
  huawei: {
    title: '华为云 AccessKey 获取方式',
    steps: [
      '登录华为云控制台',
      '点击右上角用户名 → 我的凭证',
      '选择 访问密钥 → 新增访问密钥',
      '下载并保存 AccessKey ID 和 Secret Access Key',
    ],
    link: 'https://console.huaweicloud.com/iam/#/myCredential',
  },
  baidu: {
    title: '百度云 AccessKey 获取方式',
    steps: [
      '登录百度智能云控制台',
      '点击右上角用户名 → 安全认证',
      '在 Access Key 页面创建或查看密钥',
      '复制 AccessKey 和 SecretKey',
    ],
    link: 'https://console.bce.baidu.com/iam/#/iam/accesslist',
  },
  west: {
    title: '西部数码 API 密码获取方式',
    steps: [
      '登录西部数码会员中心',
      '进入 账户安全 → API 密码设置',
      '设置或查看 API 密码',
      '使用会员账号和 API 密码进行认证',
    ],
    link: 'https://www.west.cn/manager/api/',
  },
  huoshan: {
    title: '火山引擎 AccessKey 获取方式',
    steps: [
      '登录火山引擎控制台',
      '点击右上角用户名 → 密钥管理',
      '创建新的 Access Key',
      '保存 AccessKey ID 和 Secret Access Key',
    ],
    link: 'https://console.volcengine.com/iam/keymanage/',
  },
  jdcloud: {
    title: '京东云 AccessKey 获取方式',
    steps: [
      '登录京东云控制台',
      '点击右上角账户 → Access Key 管理',
      '创建新的 Access Key',
      '复制 AccessKey ID 和 AccessKey Secret',
    ],
    link: 'https://uc.jdcloud.com/account/accesskey',
  },
  dnsla: {
    title: 'DNSLA API 密钥获取方式',
    steps: [
      '登录 DNSLA 控制台',
      '进入 用户中心 → API 接口',
      '创建或查看 API ID 和 API Secret',
      '复制 API ID 和 API Secret',
    ],
    link: 'https://www.dns.la/',
  },
  namesilo: {
    title: 'NameSilo API Key 获取方式',
    steps: [
      '登录 NameSilo 账户',
      '进入 Account → API Manager',
      '生成新的 API Key',
      '复制 API Key（注意保存，只显示一次）',
    ],
    link: 'https://www.namesilo.com/account/api-manager',
  },
  powerdns: {
    title: 'PowerDNS API Key 获取方式',
    steps: [
      '登录 PowerDNS 服务器',
      '查看配置文件中的 api-key 设置',
      '或在 PowerDNS Admin 界面获取 API Key',
      '填写服务器地址格式：IP:端口（如 192.168.1.1:8081）',
    ],
  },
  spaceship: {
    title: 'Spaceship API 密钥获取方式',
    steps: [
      '登录 Spaceship 账户',
      '进入 Account Settings → API',
      '生成 API Key 和 API Secret',
      '复制 API Key 和 API Secret',
    ],
    link: 'https://www.spaceship.com/',
  },
  edgeone: {
    title: '腾讯云 EdgeOne API 密钥获取方式',
    steps: [
      '登录腾讯云控制台',
      '进入「访问管理 → 访问密钥 → API 密钥管理」',
      '创建或查看 SecretId / SecretKey',
      '建议创建子账号并授予 EdgeOne 相关权限',
      '如有固定套餐，可把 PlanId 一并保存，后续创建站点会自动带上',
    ],
    link: 'https://console.cloud.tencent.com/cam/capi',
  },
  tencent_ssl: {
    title: '腾讯云 SSL 证书 API 密钥获取方式',
    steps: [
      '登录腾讯云控制台',
      '进入「访问管理 → 访问密钥 → API 密钥管理」',
      '创建或查看已有的 SecretId 和 SecretKey',
      '建议创建子账号并仅授予 SSL 证书相关权限（QcloudSSLFullAccess）',
      '复制 SecretId 和 SecretKey',
    ],
    link: 'https://console.cloud.tencent.com/cam/capi',
  },
};

async function loadData() {
  isLoading.value = true;
  try {
    const [credsRes, provsRes] = await Promise.all([
      getDnsCredentials(props.category),
      getProviders(),
    ]);
    credentials.value = credsRes.data?.credentials || [];
    providers.value = mergeProviders(provsRes.data?.providers || []).filter(
      (provider) => (provider.category || 'dns') === props.category,
    );
    if (props.category === 'acceleration' && !providers.value.some((provider) => provider.type === 'edgeone')) {
      providers.value = [EDGEONE_FALLBACK_PROVIDER, ...providers.value];
    }
    if (providers.value.length > 0 && !providers.value.some((provider) => provider.type === formProvider.value)) {
      formProvider.value = providers.value[0].type;
    }
  } catch {
    message.error('加载数据失败');
  } finally {
    isLoading.value = false;
  }
}

function getRouteProvider(): ProviderType | null {
  const raw = route.query.provider;
  if (!raw) return null;
  const provider = normalizeProviderType(String(raw));
  const exists = providers.value.some((p) => normalizeProviderType(p.type) === provider);
  return exists ? provider : null;
}

function clearRouteCreateIntent() {
  if (!route.query.action && !route.query.provider) return;
  const nextQuery = { ...route.query };
  delete nextQuery.action;
  delete nextQuery.provider;
  router.replace({ path: route.path, query: nextQuery });
}

function consumeRouteCreateIntent() {
  if (route.query.action !== 'add') return;
  openAdd();
  const provider = getRouteProvider();
  if (provider) {
    formProvider.value = provider;
  }
  clearRouteCreateIntent();
}

onMounted(async () => {
  await loadData();
  consumeRouteCreateIntent();
});

watch(
  () => [route.query.action, route.query.provider, providers.value.length],
  () => {
    if (!providers.value.length) return;
    consumeRouteCreateIntent();
  }
);

watch(
  () => props.category,
  async () => {
    await loadData();
  }
);

// Reset secrets when provider changes in add mode
watch(() => formProvider.value, () => {
  if (!dialogOpen.value || editing.value) return;
  formSecrets.value = {};
  showSecretFields.value = {};
});

watch(
  () => props.openAddSignal,
  (signal, prevSignal) => {
    if (!signal || signal === prevSignal) return;
    openAddWithProvider(props.presetProvider);
  }
);

function openAdd() {
  editing.value = null;
  formName.value = '';
  formProvider.value = props.presetProvider
    ? normalizeProviderType(props.presetProvider)
    : (providers.value[0]?.type || (props.category === 'acceleration' ? 'edgeone' : 'cloudflare'));
  formSecrets.value = {};
  submitError.value = '';
  showSecretFields.value = {};
  dialogOpen.value = true;
}

function openAddWithProvider(provider?: ProviderType | null) {
  openAdd();
  if (provider) {
    formProvider.value = normalizeProviderType(provider);
  }
}

async function openEdit(cred: DnsCredential) {
  editing.value = cred;
  formName.value = cred.name;
  formProvider.value = cred.provider;
  formSecrets.value = {};
  submitError.value = '';
  showSecretFields.value = {};
  dialogOpen.value = true;

  secretsLoading.value = true;
  try {
    const res = await getDnsCredentialSecrets(cred.id);
    formSecrets.value = res.data?.secrets || {};
  } catch (err: any) {
    submitError.value = `加载密钥失败: ${String(err)}`;
  } finally {
    secretsLoading.value = false;
  }
}

function closeDialog() {
  dialogOpen.value = false;
  editing.value = null;
  submitError.value = '';
  showSecretFields.value = {};
}

function setSecretField(key: string, value: string) {
  formSecrets.value = {
    ...formSecrets.value,
    [key]: value,
  };
}

async function handleSubmit() {
  if (!formName.value.trim()) { submitError.value = '请输入账户别名'; return; }

  const secrets = { ...formSecrets.value };
  Object.keys(secrets).forEach(k => { if (!secrets[k]) delete secrets[k]; });

  // DNSPod dual-auth validation
  if (formProvider.value === 'dnspod') {
    const hasTC3 = Boolean(secrets.secretId && secrets.secretKey);
    const hasTC3Partial = Boolean(secrets.secretId || secrets.secretKey);
    const hasLegacy = Boolean(
      (secrets.tokenId && secrets.token) ||
      (!secrets.tokenId && secrets.token && String(secrets.token).includes(','))
    );
    const hasLegacyPartial = Boolean(secrets.tokenId || secrets.token);

    if (!editing.value && !hasTC3 && !hasLegacy) {
      submitError.value = '请填写 SecretId/SecretKey 或 DNSPod Token，两种方式二选一';
      return;
    }
    if (hasTC3Partial && !hasTC3) {
      submitError.value = 'SecretId/SecretKey 需要同时填写';
      return;
    }
    if (hasLegacyPartial && !hasLegacy) {
      submitError.value = 'DNSPod Token 请填写 ID + Token，或在 Token 中填入组合格式：ID,Token';
      return;
    }
  }

  const requiredFields = (selectedProviderConfig.value?.authFields || [])
    .filter((field) => field.required)
    .map((field) => field.key);
  if (formProvider.value !== 'dnspod') {
    const missing = requiredFields.filter((key) => !String(secrets[key] || '').trim());
    if (missing.length > 0) {
      submitError.value = `缺少必填字段: ${missing.join(', ')}`;
      return;
    }
  }

  try {
    submitting.value = true;
    submitError.value = '';

    if (editing.value) {
      await updateDnsCredential(editing.value.id, {
        name: formName.value,
        secrets: Object.keys(secrets).length > 0 ? secrets : undefined,
      });
    } else {
      await createDnsCredential({
        name: formName.value,
        provider: formProvider.value,
        secrets,
      });
    }

    await loadData();
    await providerStore.loadData();
    closeDialog();
    emit('changed');
    message.success(editing.value ? '已更新' : '已创建');
  } catch (err: any) {
    submitError.value = typeof err === 'string' ? err : (err?.message || '操作失败');
  } finally {
    submitting.value = false;
  }
}

async function handleVerify(id: number) {
  verifying.value = id;
  try {
    const res = await verifyDnsCredential(id);
    verifyResults.value[id] = !!res.data?.valid;
  } catch {
    verifyResults.value[id] = false;
  } finally {
    verifying.value = null;
  }
}

function confirmDelete(cred: DnsCredential) {
  dlg.warning({
    title: '确认删除',
    content: `确定要删除账户 ${cred.name} 吗？此操作不可恢复。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteDnsCredential(cred.id);
        await loadData();
        await providerStore.loadData();
        emit('changed');
        message.success('已删除');
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}

function toggleSecretVisibility(key: string) {
  showSecretFields.value = { ...showSecretFields.value, [key]: !showSecretFields.value[key] };
}

const currentGuide = computed(() => PROVIDER_CREDENTIAL_GUIDE[formProvider.value]);
</script>

<template>
  <section :class="props.embedded ? 'h-full' : 'bento-card h-full'">
    <div class="mb-4 flex items-center justify-between">
      <div class="flex items-center gap-4">
        <Database :size="18" class="text-accent" />
        <div>
          <h3 class="text-base font-semibold text-slate-700">{{ props.title }}</h3>
          <p class="text-xs text-slate-500">{{ props.description }}</p>
        </div>
      </div>
      <NButton size="small" type="primary" @click="openAdd">
        <template #icon><Plus :size="14" /></template>
        新增账户
      </NButton>
    </div>

    <div v-if="isLoading" class="flex justify-center py-8"><NSpin size="medium" /></div>

    <NEmpty v-else-if="credentials.length === 0" description="暂无账户，点击上方按钮添加" class="py-6" />

    <div v-else class="space-y-4">
      <div
        v-for="cred in credentials"
        :key="cred.id"
        class="flex items-center gap-4 rounded-xl border border-panel-border bg-panel-bg p-3"
      >
        <div class="min-w-0 flex-1">
          <div class="mb-0.5 flex items-center gap-4">
            <span class="truncate text-sm font-semibold text-slate-700">{{ cred.name }}</span>
            <NTag size="tiny" :bordered="false">{{ cred.providerName || cred.provider }}</NTag>
          </div>
          <p class="text-xs text-slate-500">
            ID: {{ cred.id }} &middot; 创建于 {{ formatDateSafe(cred.createdAt) }}
          </p>
        </div>

        <div class="flex items-center gap-4">
          <!-- Verify button -->
          <NButton
            text
            size="tiny"
            :loading="verifying === cred.id"
            @click="handleVerify(cred.id)"
          >
            <template #icon>
              <CheckCircle
                v-if="verifyResults[cred.id] === true"
                :size="14"
                class="text-green-500"
              />
              <XCircle
                v-else-if="verifyResults[cred.id] === false"
                :size="14"
                class="text-red-500"
              />
              <CheckCircle v-else :size="14" />
            </template>
          </NButton>
          <NButton text size="tiny" @click="openEdit(cred)">
            <template #icon><Pencil :size="12" /></template>
          </NButton>
          <NButton text size="tiny" type="error" @click="confirmDelete(cred)">
            <template #icon><Trash2 :size="12" /></template>
          </NButton>
        </div>
      </div>
    </div>

    <!-- Add/Edit dialog -->
    <NModal
      :show="dialogOpen"
      preset="card"
      :title="editing ? '编辑账户' : '新增账户'"
      :style="{ width: '600px' }"
      @update:show="(v: boolean) => { if (!v) closeDialog(); }"
    >
      <div class="space-y-4">
        <NAlert v-if="submitError" type="error" :bordered="false">{{ submitError }}</NAlert>

        <div>
          <label class="mb-1 block text-sm text-slate-400">账户别名</label>
          <NInput
            v-model:value="formName"
            placeholder="例如：个人域名、公司 DNS"
            size="small"
          />
        </div>

        <!-- Provider selector (only for add) -->
        <div v-if="!editing">
          <label class="mb-2 block text-sm text-slate-400">选择服务商</label>
          <ProviderSelector
            :providers="providers"
            :selected-provider="formProvider"
            @select="formProvider = $event"
          />
        </div>

        <!-- Auth fields -->
        <div v-if="selectedProviderConfig" class="rounded-xl bg-panel-bg p-4">
          <p class="mb-2 text-sm font-medium text-accent">
            {{ selectedProviderConfig.name }} 认证信息
            <span v-if="editing" class="ml-1 text-xs text-slate-500">
              {{ secretsLoading ? '(加载密钥中...)' : '(可查看/修改)' }}
            </span>
          </p>

          <div class="space-y-4">
            <template v-for="(field, idx) in selectedProviderConfig.authFields" :key="field.key">
              <NDivider
                v-if="formProvider === 'dnspod' && field.key === 'tokenId'"
                title-placement="left"
                class="!my-3"
              >
                <span class="text-xs text-slate-500">DNSPod Token 认证</span>
              </NDivider>

              <div>
                <label class="mb-0.5 block text-xs text-slate-400">{{ field.label }}</label>
                <NInput
                  :value="formSecrets[field.key] || ''"
                  :type="field.type === 'password' && !showSecretFields[field.key] ? 'password' : 'text'"
                  :placeholder="field.placeholder"
                  size="small"
                  @update:value="(val: string) => setSecretField(field.key, val)"
                >
                  <template v-if="field.type === 'password'" #suffix>
                    <button
                      class="p-0.5 text-slate-500 transition-colors hover:text-slate-300"
                      type="button"
                      @click="toggleSecretVisibility(field.key)"
                    >
                      <EyeOff v-if="showSecretFields[field.key]" :size="14" />
                      <Eye v-else :size="14" />
                    </button>
                  </template>
                </NInput>
                <p v-if="field.helpText" class="mt-0.5 text-xs text-slate-500">{{ field.helpText }}</p>
              </div>
            </template>
          </div>
        </div>

        <!-- Credential guide -->
        <NAlert v-if="currentGuide" type="info" :bordered="false">
          <p class="mb-1 text-sm font-medium">{{ currentGuide.title }}</p>
          <ol class="list-decimal space-y-0.5 pl-4 text-sm">
            <li v-for="(step, i) in currentGuide.steps" :key="i">{{ step }}</li>
          </ol>
          <a
            v-if="currentGuide.link"
            :href="currentGuide.link"
            target="_blank"
            rel="noopener noreferrer"
            class="mt-2 inline-flex items-center gap-4 text-xs text-accent hover:underline"
          >
            <ExternalLink :size="12" />
            前往获取
          </a>
        </NAlert>

        <div class="flex justify-end gap-4">
          <NButton size="small" @click="closeDialog">取消</NButton>
          <NButton size="small" type="primary" :loading="submitting" @click="handleSubmit">保存</NButton>
        </div>
      </div>
    </NModal>
  </section>
</template>
