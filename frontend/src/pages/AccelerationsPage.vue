<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NButton, NEmpty, NInput, NSelect, NSpin, NTag, useMessage } from 'naive-ui';
import { RefreshCw, Plus, Globe } from 'lucide-vue-next';
import {
  listAccelerationConfigs,
  enableAcceleration,
  createAccelerationVerifyRecord,
  syncAcceleration,
  verifyAcceleration,
  updateAccelerationConfig,
  setAccelerationSiteStatus,
  deleteRemoteAcceleration,
  type AccelerationConfigInput,
  type DomainAccelerationConfig,
} from '@/services/accelerations';
import { getDnsCredentials, getProviders } from '@/services/dnsCredentials';
import { getDomains } from '@/services/domains';
import { getProviderDisplayName } from '@/utils/provider';
import type { DnsCredential } from '@/types/dns';
import type { Domain } from '@/types';
import AddAccelerationCredentialDialog from '@/components/Dashboard/AddAccelerationCredentialDialog.vue';
import AccelerationSiteDialog from '@/components/Acceleration/AccelerationSiteDialog.vue';

type RowStatus = 'verified' | 'pending' | 'paused' | 'error';
type LocalStatusFilter = 'all' | RowStatus;

type LocalAccelerationRow = DomainAccelerationConfig & {
  key: string;
  dnsCredentialName: string;
  pluginCredentialName: string;
  status: RowStatus;
  hasError: boolean;
  searchText: string;
};

type AccelerationSiteDialogPayload = AccelerationConfigInput & {
  zoneName: string;
  dnsCredentialId: number;
  pluginCredentialId: number;
};

const router = useRouter();
const route = useRoute();
const queryClient = useQueryClient();
const message = useMessage();

const showAddAccelerationCredential = ref(false);
const showAccelerationSiteDialog = ref(false);
const accelerationDialogMode = ref<'create' | 'edit'>('create');
const accelerationDialogValue = ref<(Partial<DomainAccelerationConfig> & {
  zoneName?: string;
  dnsCredentialId?: number | null;
  pluginCredentialId?: number | null;
}) | null>(null);
const accelerationDialogLockDomain = ref(false);
const accelerationDialogLockPluginCredential = ref(false);
const localKeyword = ref('');
const localStatusFilter = ref<LocalStatusFilter>('all');
const localDnsCredentialFilter = ref<number | null>(null);
const localPluginCredentialFilter = ref<number | null>(null);
const isBatchRunning = ref(false);
const batchFeedback = ref<{ tone: 'warning' | 'error'; title: string; items: string[] } | null>(null);

const { data: accelerationConfigsData, isLoading: loadingConfigs, refetch: refetchAccelerationConfigs } = useQuery({
  queryKey: ['acceleration-configs-page'],
  queryFn: async () => {
    const res = await listAccelerationConfigs();
    return res.data?.items || [];
  },
});

const {
  data: dnsContextData,
  isLoading: loadingDnsContext,
  refetch: refetchDnsContext,
} = useQuery({
  queryKey: ['acceleration-page-dns-context'],
  queryFn: async () => {
    const [providersRes, credentialsRes] = await Promise.all([
      getProviders(),
      getDnsCredentials(),
    ]);
    const allCredentials = (credentialsRes.data?.credentials || []) as DnsCredential[];
    const dnsProviderSet = new Set(
      (providersRes.data?.providers || [])
        .filter((item) => (item.category || 'dns') === 'dns')
        .map((item) => String(item.type || '').trim().toLowerCase()),
    );
    const accelerationProviderSet = new Set(
      (providersRes.data?.providers || [])
        .filter((item) => (item.category || 'dns') === 'acceleration')
        .map((item) => String(item.type || '').trim().toLowerCase()),
    );
    const dnsCredentials = allCredentials.filter((item) =>
      dnsProviderSet.has(String(item.provider || '').trim().toLowerCase()),
    ) as DnsCredential[];
    const accelerationCredentials = allCredentials.filter((item) =>
      accelerationProviderSet.has(String(item.provider || '').trim().toLowerCase()),
    ) as DnsCredential[];

    const domainsByCredential = await Promise.all(dnsCredentials.map(async (credential) => {
      try {
        const res = await getDomains(credential.id);
        return (res.data?.domains || []).map((domain) => ({
          ...domain,
          credentialId: credential.id,
          credentialName: credential.name,
          provider: credential.provider,
        })) as Domain[];
      } catch {
        return [] as Domain[];
      }
    }));

    return {
      allCredentials,
      dnsCredentials,
      accelerationCredentials,
      domains: domainsByCredential.flat(),
    };
  },
});

const accelerationConfigs = computed<DomainAccelerationConfig[]>(() => accelerationConfigsData.value || []);
const allCredentials = computed<DnsCredential[]>(() => dnsContextData.value?.allCredentials || []);
const dnsDomains = computed<Domain[]>(() => dnsContextData.value?.domains || []);
const dnsCredentials = computed<DnsCredential[]>(() => dnsContextData.value?.dnsCredentials || []);
const accelerationCredentials = computed<DnsCredential[]>(() => dnsContextData.value?.accelerationCredentials || []);

const credentialNameMap = computed(() => {
  const map = new Map<number, string>();
  for (const credential of allCredentials.value) {
    map.set(credential.id, credential.name);
  }
  return map;
});

const dnsCredentialOptions = computed(() =>
  dnsCredentials.value.map((credential) => ({
    label: `${credential.name} · ${getProviderDisplayName(credential.provider || '') || credential.provider || 'DNS'}`,
    value: credential.id,
  })),
);

const accelerationCredentialOptions = computed(() =>
  accelerationCredentials.value.map((credential) => ({
    label: `${credential.name} · ${getProviderDisplayName(credential.provider || '') || credential.provider || '加速'}`,
    value: credential.id,
  })),
);

const availableCreateDomains = computed(() =>
  dnsDomains.value.filter((domain) => Number(domain.credentialId || 0) > 0),
);

function refreshAccelerationViews() {
  queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  queryClient.invalidateQueries({ queryKey: ['acceleration-configs-page'] });
  queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-page'] });
}

function normalizeText(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

function getPrimaryAccelerationDomain(item: {
  accelerationDomain?: string;
  zoneName?: string;
}) {
  return String(item.accelerationDomain || item.zoneName || '').trim();
}

function getErrorMessage(err: any): string {
  return String(err?.response?.data?.message || err?.message || err || '操作失败');
}

function copyText(text: string | undefined) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(
    () => message.success('已复制'),
    () => message.error('复制失败'),
  );
}

async function refreshCurrentPageData() {
  await Promise.all([
    refetchAccelerationConfigs(),
    refetchDnsContext(),
  ]);
  refreshAccelerationViews();
}

function getLocalKey(config: DomainAccelerationConfig): string {
  return [
    config.dnsCredentialId,
    config.pluginCredentialId,
    normalizeText(config.accelerationDomain || config.zoneName),
  ].join('::');
}

const scopedZoneName = computed(() => normalizeText(route.query.zoneName));
const scopedDnsCredentialId = computed(() => {
  const value = Number(route.query.dnsCredentialId || 0);
  return value > 0 ? value : null;
});

function getRowStatus(item: {
  verified?: boolean;
  paused?: boolean;
  lastError?: string;
  domainStatus?: string;
  cnameStatus?: string;
  identificationStatus?: string;
  verifyStatus?: string;
}): RowStatus {
  if (item.paused) return 'paused';
  const domainStatus = normalizeText(item.domainStatus);
  const cnameStatus = normalizeText(item.cnameStatus || item.identificationStatus || item.verifyStatus);
  if (
    item.verified
    || ['online', 'active', 'enabled'].includes(domainStatus)
    || ['finished', 'active', 'verified', 'success', 'completed'].includes(cnameStatus)
  ) return 'verified';
  if (String(item.lastError || '').trim()) return 'error';
  return 'pending';
}

const localRows = computed<LocalAccelerationRow[]>(() =>
  accelerationConfigs.value.map((config) => {
    const dnsCredentialName = credentialNameMap.value.get(config.dnsCredentialId) || `DNS 凭证 #${config.dnsCredentialId}`;
    const pluginCredentialName = credentialNameMap.value.get(config.pluginCredentialId) || `加速账户 #${config.pluginCredentialId}`;
    return {
      ...config,
      key: getLocalKey(config),
      dnsCredentialName,
      pluginCredentialName,
      status: getRowStatus(config),
      hasError: Boolean(String(config.lastError || '').trim()),
      searchText: [
        config.zoneName,
        config.accelerationDomain,
        config.remoteSiteId,
        config.siteStatus,
        config.domainStatus,
        config.verifyStatus,
        config.identificationStatus,
        config.cnameStatus,
        config.cnameTarget,
        config.originValue,
        config.hostHeader,
        config.ipv6Status,
        config.accessType,
        config.area,
        config.lastError,
        dnsCredentialName,
        pluginCredentialName,
      ].join(' ').toLowerCase(),
    };
  }),
);

const filteredLocalRows = computed(() =>
  localRows.value.filter((row) => {
    if (scopedZoneName.value && normalizeText(row.zoneName) !== scopedZoneName.value) return false;
    if (scopedDnsCredentialId.value && row.dnsCredentialId !== scopedDnsCredentialId.value) return false;
    const keyword = normalizeText(localKeyword.value);
    if (keyword && !row.searchText.includes(keyword)) return false;
    if (localStatusFilter.value !== 'all' && row.status !== localStatusFilter.value) return false;
    if (localDnsCredentialFilter.value && row.dnsCredentialId !== localDnsCredentialFilter.value) return false;
    if (localPluginCredentialFilter.value && row.pluginCredentialId !== localPluginCredentialFilter.value) return false;
    return true;
  }),
);

const saveAccelerationMutation = useMutation({
  mutationFn: async (payload: AccelerationSiteDialogPayload) => {
    if (accelerationDialogMode.value === 'edit') {
      return updateAccelerationConfig(payload);
    }
    return enableAcceleration({
      ...payload,
      autoDnsRecord: true,
    });
  },
  onSuccess: async (res) => {
    if (accelerationDialogMode.value === 'edit') {
      message.success('加速配置已更新');
    } else {
      const added = res.data?.dnsRecordsAdded?.length || 0;
      const skipped = res.data?.dnsRecordsSkipped?.length || 0;
      const failed = res.data?.dnsErrors?.length || 0;
      let text = '加速域名已创建';
      if (added) text += `，新增 ${added} 条验证记录`;
      if (skipped) text += `，${skipped} 条验证记录已存在`;
      if (failed) text += `，${failed} 条验证记录写入失败`;
      message.success(text);
    }
    showAccelerationSiteDialog.value = false;
    accelerationDialogValue.value = null;
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

async function runBatch<T>(options: {
  items: T[];
  emptyMessage: string;
  actionLabel: string;
  describe: (item: T) => string;
  execute: (item: T) => Promise<unknown>;
}) {
  if (!options.items.length) {
    message.warning(options.emptyMessage);
    return;
  }

  isBatchRunning.value = true;
  batchFeedback.value = null;
  let success = 0;
  const failures: string[] = [];

  for (const item of options.items) {
    try {
      await options.execute(item);
      success += 1;
    } catch (err) {
      failures.push(`${options.describe(item)}: ${getErrorMessage(err)}`);
    }
  }

  isBatchRunning.value = false;
  if (failures.length) {
    batchFeedback.value = {
      tone: success > 0 ? 'warning' : 'error',
      title: `${options.actionLabel}完成：成功 ${success}，失败 ${failures.length}`,
      items: failures.slice(0, 8),
    };
    message.warning(`${options.actionLabel}完成：成功 ${success}，失败 ${failures.length}`);
  } else {
    message.success(`${options.actionLabel}完成，共 ${success} 项`);
  }

  await refreshCurrentPageData();
}

const syncConfigMutation = useMutation({
  mutationFn: async (config: DomainAccelerationConfig) => syncAcceleration({
    zoneName: config.zoneName,
    dnsCredentialId: config.dnsCredentialId,
    accelerationDomain: config.accelerationDomain,
  }),
  onSuccess: async () => {
    message.success('加速状态已同步');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const verifyConfigMutation = useMutation({
  mutationFn: async (config: DomainAccelerationConfig) => verifyAcceleration({
    zoneName: config.zoneName,
    dnsCredentialId: config.dnsCredentialId,
    accelerationDomain: config.accelerationDomain,
  }),
  onSuccess: async () => {
    message.success('已提交验证');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const setSiteStatusMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId?: number; pluginCredentialId?: number; remoteSiteId?: string; accelerationDomain?: string; enabled: boolean }) =>
    setAccelerationSiteStatus(payload),
  onSuccess: async () => {
    message.success('加速站点状态已更新');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const deleteRemoteMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId?: number; pluginCredentialId?: number; remoteSiteId?: string; accelerationDomain?: string; deleteLocalConfig?: boolean }) =>
    deleteRemoteAcceleration(payload),
  onSuccess: async () => {
    message.success('远端加速站点已删除');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const createVerifyRecordMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId: number; pluginCredentialId?: number; remoteSiteId?: string; accelerationDomain?: string }) =>
    createAccelerationVerifyRecord(payload),
  onSuccess: async (res) => {
    const added = res.data?.dnsRecordsAdded?.length || 0;
    const skipped = res.data?.dnsRecordsSkipped?.length || 0;
    const failed = res.data?.dnsErrors?.length || 0;
    let text = '验证记录处理完成';
    if (added) text += `，新增 ${added} 条`;
    if (skipped) text += `，${skipped} 条已存在`;
    if (failed) text += `，${failed} 条失败`;
    message.success(text);
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

function setLocalStatusFilter(value: string | null) {
  localStatusFilter.value = (value || 'all') as LocalStatusFilter;
}

function setLocalDnsCredentialFilter(value: string | number | null) {
  localDnsCredentialFilter.value = value == null ? null : Number(value);
}

function setLocalPluginCredentialFilter(value: string | number | null) {
  localPluginCredentialFilter.value = value == null ? null : Number(value);
}

function openCreateAccelerationDialog() {
  accelerationDialogMode.value = 'create';
  accelerationDialogLockDomain.value = false;
  accelerationDialogLockPluginCredential.value = false;
  const firstDomain = availableCreateDomains.value.find((domain) =>
    (!scopedZoneName.value || normalizeText(domain.name) === scopedZoneName.value)
    && (!scopedDnsCredentialId.value || Number(domain.credentialId || 0) === scopedDnsCredentialId.value),
  ) || availableCreateDomains.value[0] || dnsDomains.value[0] || null;
  accelerationDialogValue.value = {
    zoneName: firstDomain?.name || '',
    dnsCredentialId: Number(firstDomain?.credentialId || 0) || null,
    pluginCredentialId: accelerationCredentials.value[0]?.id || null,
    subDomain: '@',
    originType: 'IP_DOMAIN',
    originProtocol: 'FOLLOW',
    httpOriginPort: 80,
    httpsOriginPort: 443,
    ipv6Status: 'follow',
  };
  showAccelerationSiteDialog.value = true;
}

function openEditAccelerationDialog(config: LocalAccelerationRow) {
  accelerationDialogMode.value = 'edit';
  accelerationDialogLockDomain.value = true;
  accelerationDialogLockPluginCredential.value = true;
  accelerationDialogValue.value = { ...config };
  showAccelerationSiteDialog.value = true;
}

function goToDomain(config: { zoneName: string; dnsCredentialId?: number | null }) {
  const match = dnsDomains.value.find((domain) =>
    domain.credentialId === config.dnsCredentialId
    && normalizeText(domain.name) === normalizeText(config.zoneName),
  );
  if (!match) {
    message.warning('未找到对应的本地域名详情');
    return;
  }
  router.push({
    name: 'DomainDetail',
    params: { zoneId: match.id },
    query: match.credentialId ? { credentialId: String(match.credentialId) } : {},
  });
}

async function batchSyncFilteredLocal() {
  await runBatch({
    items: filteredLocalRows.value,
    emptyMessage: '当前筛选结果中没有本地加速配置',
    actionLabel: '本地配置同步',
    describe: (row) => row.zoneName,
    execute: (row) => syncAcceleration({
      zoneName: row.zoneName,
      dnsCredentialId: row.dnsCredentialId,
      accelerationDomain: row.accelerationDomain,
    }),
  });
}

async function batchVerifyFilteredLocal() {
  await runBatch({
    items: filteredLocalRows.value.filter((row) => row.status === 'pending' || row.status === 'error'),
    emptyMessage: '当前筛选结果中没有需要验证的本地配置',
    actionLabel: '批量验证',
    describe: (row) => row.zoneName,
    execute: (row) => verifyAcceleration({
      zoneName: row.zoneName,
      dnsCredentialId: row.dnsCredentialId,
      accelerationDomain: row.accelerationDomain,
    }),
  });
}

async function batchCreateVerifyRecordsForLocal() {
  await runBatch({
    items: filteredLocalRows.value.filter((row) => !row.verified && row.verifyRecordName),
    emptyMessage: '当前筛选结果中没有需要补验证记录的本地配置',
    actionLabel: '批量补验证记录',
    describe: (row) => row.zoneName,
    execute: (row) => createAccelerationVerifyRecord({
      zoneName: row.zoneName,
      dnsCredentialId: row.dnsCredentialId,
      pluginCredentialId: row.pluginCredentialId,
      remoteSiteId: row.remoteSiteId,
      accelerationDomain: row.accelerationDomain,
    }),
  });
}

async function batchSetFilteredLocalStatus(enabled: boolean) {
  await runBatch({
    items: filteredLocalRows.value.filter((row) => enabled ? row.paused : !row.paused),
    emptyMessage: enabled ? '当前筛选结果中没有可恢复的本地站点' : '当前筛选结果中没有可暂停的本地站点',
    actionLabel: enabled ? '批量恢复站点' : '批量暂停站点',
    describe: (row) => row.zoneName,
    execute: (row) => setAccelerationSiteStatus({
      zoneName: row.zoneName,
      dnsCredentialId: row.dnsCredentialId,
      remoteSiteId: row.remoteSiteId,
      accelerationDomain: row.accelerationDomain,
      enabled,
    }),
  });
}

const localManagedCount = computed(() => localRows.value.length);
const localVerifiedCount = computed(() => localRows.value.filter((item) => item.verified).length);
const localErrorCount = computed(() => localRows.value.filter((item) => item.hasError).length);
const localPendingCount = computed(() => localRows.value.filter((item) => !item.verified && !item.paused).length);
const pageLoading = computed(() => loadingConfigs.value || loadingDnsContext.value);

function getEffectiveLabel(item: { verified?: boolean; paused?: boolean; lastError?: string }): string {
  const status = getRowStatus(item);
  if (status === 'paused') return '已暂停';
  if (status === 'verified') return '已生效';
  if (status === 'error') return '异常';
  return '未生效';
}

function getEffectiveType(item: { verified?: boolean; paused?: boolean; lastError?: string }): 'success' | 'warning' | 'error' | 'default' {
  const status = getRowStatus(item);
  if (status === 'paused') return 'warning';
  if (status === 'verified') return 'success';
  if (status === 'error') return 'error';
  return 'default';
}
</script>

<template>
  <div class="bento-grid">
    <section class="bento-hero col-span-12">
      <div class="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
        <div>
          <div class="section-badge">
            <span class="dot" />
            <span class="label">Acceleration Workspace</span>
          </div>
          <h1 class="page-title">
            加速
            <span class="gradient-text"> 管理</span>
          </h1>
          <p class="page-subtitle">集中管理 EdgeOne 加速域名，直接完成新增、编辑、验证、同步、停启用和删除。</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <NButton
            size="small"
            type="primary"
            :disabled="!accelerationCredentials.length || !availableCreateDomains.length"
            @click="openCreateAccelerationDialog"
          >
            <template #icon><Plus :size="14" /></template>
            新增加速域名
          </NButton>
          <NButton size="small" secondary @click="refreshCurrentPageData">
            <template #icon><RefreshCw :size="14" /></template>
            刷新列表
          </NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchSyncFilteredLocal">
            <template #icon><Globe :size="14" /></template>
            同步列表
          </NButton>
          <NButton size="small" type="primary" @click="showAddAccelerationCredential = true">
            <template #icon><Plus :size="14" /></template>
            添加加速账户
          </NButton>
        </div>
      </div>

      <div class="mt-6 grid gap-4 md:grid-cols-4">
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">已接管</p>
          <p class="mt-3 text-4xl text-slate-800">{{ localManagedCount }}</p>
          <p class="mt-2 text-xs text-slate-500">已纳管的加速域名记录</p>
        </article>
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">已生效</p>
          <p class="mt-3 text-4xl text-emerald-600">{{ localVerifiedCount }}</p>
          <p class="mt-2 text-xs text-slate-500">本地配置中已完成验证的站点</p>
        </article>
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">异常</p>
          <p class="mt-3 text-4xl text-rose-600">{{ localErrorCount }}</p>
          <p class="mt-2 text-xs text-slate-500">最近同步或验证返回异常的站点</p>
        </article>
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">待验证</p>
          <p class="mt-3 text-4xl text-amber-600">{{ localPendingCount }}</p>
          <p class="mt-2 text-xs text-slate-500">等待验证或补录验证记录的站点</p>
        </article>
      </div>

      <div v-if="scopedZoneName" class="mt-5 rounded-2xl border border-sky-200 bg-sky-50/90 p-4 text-sm text-sky-800">
        当前仅显示域名 `{{ scopedZoneName }}` 的加速记录。
      </div>

      <div
        v-if="batchFeedback"
        class="mt-5 rounded-2xl border p-4"
        :class="batchFeedback.tone === 'error' ? 'border-rose-200 bg-rose-50/90' : 'border-amber-200 bg-amber-50/90'"
      >
        <p class="text-sm font-semibold" :class="batchFeedback.tone === 'error' ? 'text-rose-700' : 'text-amber-800'">
          {{ batchFeedback.title }}
        </p>
        <div class="mt-2 space-y-1 text-xs" :class="batchFeedback.tone === 'error' ? 'text-rose-700' : 'text-amber-800'">
          <p v-for="item in batchFeedback.items" :key="item">{{ item }}</p>
        </div>
      </div>
    </section>

    <section class="bento-card col-span-12">
      <div class="flex flex-col gap-4">
        <div class="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="bento-section-title">加速域名列表</p>
            <p class="bento-section-meta">EdgeOne 加速域名列表，支持新增、编辑、验证、同步、停启用和删除。</p>
          </div>
          <p class="text-xs text-slate-500">显示 {{ filteredLocalRows.length }} / {{ localRows.length }} 项</p>
        </div>

        <div class="grid gap-3 xl:grid-cols-4">
          <NInput v-model:value="localKeyword" clearable placeholder="搜索域名 / Site ID / 错误信息 / 账户名" />
          <NSelect
            :value="localStatusFilter"
            :options="[
              { label: '全部状态', value: 'all' },
              { label: '已生效', value: 'verified' },
              { label: '待验证', value: 'pending' },
              { label: '已暂停', value: 'paused' },
              { label: '异常', value: 'error' },
            ]"
            @update:value="setLocalStatusFilter"
          />
          <NSelect
            clearable
            :value="localDnsCredentialFilter"
            :options="dnsCredentialOptions"
            placeholder="筛选 DNS 账户"
            @update:value="setLocalDnsCredentialFilter"
          />
          <NSelect
            clearable
            :value="localPluginCredentialFilter"
            :options="accelerationCredentialOptions"
            placeholder="筛选加速账户"
            @update:value="setLocalPluginCredentialFilter"
          />
        </div>

        <div class="flex flex-wrap gap-2">
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchSyncFilteredLocal">批量同步</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchVerifyFilteredLocal">批量验证</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchCreateVerifyRecordsForLocal">批量补验证记录</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchSetFilteredLocalStatus(false)">批量暂停</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchSetFilteredLocalStatus(true)">批量恢复</NButton>
        </div>
      </div>

      <div v-if="pageLoading" class="flex justify-center py-16">
        <NSpin size="large" />
      </div>
      <NEmpty v-else-if="localRows.length === 0" description="暂无已纳管的加速域名" class="py-12" />
      <NEmpty v-else-if="filteredLocalRows.length === 0" description="没有匹配当前筛选条件的加速域名" class="py-12" />
      <div v-else class="mt-4 space-y-3">
        <div v-for="config in filteredLocalRows" :key="config.key" class="panel-muted p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-slate-700">{{ getPrimaryAccelerationDomain(config) }}</p>
              <p class="mt-1 text-xs text-slate-500">
                根域名 {{ config.zoneName }} · Site {{ config.remoteSiteId || '-' }} · DNS {{ config.dnsCredentialName }} · 加速 {{ config.pluginCredentialName }}
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <NTag size="small" :bordered="false" :type="getEffectiveType(config)">
                {{ getEffectiveLabel(config) }}
              </NTag>
              <NTag size="small" :bordered="false" :type="config.verified ? 'success' : (config.paused ? 'warning' : 'default')">
                {{ config.paused ? '已暂停' : (config.verified ? '已验证' : '待验证') }}
              </NTag>
              <NTag v-if="config.hasError" size="small" :bordered="false" type="error">最近异常</NTag>
              <NTag size="small" :bordered="false">{{ config.domainStatus || config.siteStatus || 'unknown' }}</NTag>
            </div>
          </div>

          <div class="mt-3 grid gap-3 md:grid-cols-4">
            <div>
              <p class="text-xs text-slate-500">状态链路</p>
              <p class="mt-1 text-sm text-slate-700">{{ config.domainStatus || config.siteStatus || '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">CNAME / 验证：{{ config.cnameStatus || config.identificationStatus || config.verifyStatus || '-' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">回源配置</p>
              <p class="mt-1 break-all text-sm text-slate-700">{{ config.originValue || '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">{{ config.originProtocol || 'FOLLOW' }} · HTTP {{ config.httpOriginPort || 80 }} / HTTPS {{ config.httpsOriginPort || 443 }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">CNAME / Host</p>
              <p class="mt-1 break-all text-sm text-slate-700">{{ config.cnameTarget || '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">Host Header：{{ config.hostHeader || '未设置' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">最近同步 / 套餐</p>
              <p class="mt-1 text-sm text-slate-700">{{ config.lastSyncedAt ? new Date(config.lastSyncedAt).toLocaleString('zh-CN') : '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">{{ config.area || 'global' }} / {{ config.planId || '默认' }} · IPv6 {{ config.ipv6Status || 'follow' }}</p>
            </div>
          </div>

          <div v-if="config.lastError" class="mt-3 rounded-xl border border-rose-200 bg-rose-50/90 p-3">
            <p class="text-sm font-semibold text-rose-700">最近错误</p>
            <p class="mt-1 break-all text-xs text-rose-700">{{ config.lastError }}</p>
          </div>

          <div v-if="!config.verified && config.verifyRecordName" class="mt-3 rounded-xl border border-amber-200 bg-amber-50/80 p-3">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-amber-800">当前未生效</p>
                <p class="mt-1 text-xs text-amber-700">需要完成域名归属验证。可以自动补写验证记录，也可以手动复制下面的记录信息。</p>
              </div>
              <div class="flex flex-wrap gap-2">
                <NButton
                  size="small"
                  secondary
                  :loading="createVerifyRecordMutation.isPending.value"
                  @click="createVerifyRecordMutation.mutate({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId, pluginCredentialId: config.pluginCredentialId, remoteSiteId: config.remoteSiteId, accelerationDomain: config.accelerationDomain })"
                >
                  自动添加记录
                </NButton>
                <NButton
                  size="small"
                  secondary
                  :loading="verifyConfigMutation.isPending.value"
                  @click="verifyConfigMutation.mutate(config)"
                >
                  手动验证
                </NButton>
              </div>
            </div>

            <div class="mt-3 grid gap-3 md:grid-cols-3">
              <button class="rounded-lg bg-white/80 p-3 text-left" @click="copyText(config.verifyRecordType || 'TXT')">
                <p class="text-xs text-slate-500">记录类型</p>
                <p class="mt-1 text-sm font-medium text-slate-700">{{ config.verifyRecordType || 'TXT' }}</p>
              </button>
              <button class="rounded-lg bg-white/80 p-3 text-left" @click="copyText(config.verifyRecordName)">
                <p class="text-xs text-slate-500">主机记录</p>
                <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ config.verifyRecordName }}</p>
              </button>
              <button class="rounded-lg bg-white/80 p-3 text-left" @click="copyText(config.verifyRecordValue)">
                <p class="text-xs text-slate-500">记录值</p>
                <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ config.verifyRecordValue || '-' }}</p>
              </button>
            </div>
          </div>

          <div class="mt-3 flex flex-wrap gap-2">
            <NButton size="small" secondary @click="goToDomain({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId })">
              <template #icon><Globe :size="14" /></template>
              打开域名
            </NButton>
            <NButton size="small" secondary @click="openEditAccelerationDialog(config)">
              编辑配置
            </NButton>
            <NButton size="small" secondary :loading="syncConfigMutation.isPending.value" @click="syncConfigMutation.mutate(config)">
              同步
            </NButton>
            <NButton v-if="!config.verified" size="small" secondary :loading="verifyConfigMutation.isPending.value" @click="verifyConfigMutation.mutate(config)">
              手动验证
            </NButton>
            <NButton
              size="small"
              secondary
              :loading="setSiteStatusMutation.isPending.value"
              @click="setSiteStatusMutation.mutate({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId, remoteSiteId: config.remoteSiteId, accelerationDomain: config.accelerationDomain, enabled: Boolean(config.paused) })"
            >
              {{ config.paused ? '恢复站点' : '暂停站点' }}
            </NButton>
            <NButton
              size="small"
              tertiary
              type="error"
              :loading="deleteRemoteMutation.isPending.value"
              @click="deleteRemoteMutation.mutate({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId, remoteSiteId: config.remoteSiteId, accelerationDomain: config.accelerationDomain, deleteLocalConfig: true })"
            >
              删除
            </NButton>
          </div>
        </div>
      </div>
    </section>

    <AddAccelerationCredentialDialog
      v-model:show="showAddAccelerationCredential"
      @created="refreshCurrentPageData"
    />
    <AccelerationSiteDialog
      :show="showAccelerationSiteDialog"
      :loading="saveAccelerationMutation.isPending.value"
      :mode="accelerationDialogMode"
      :domains="accelerationDialogMode === 'edit' ? dnsDomains.filter((domain) => Number(domain.credentialId || 0) === Number(accelerationDialogValue?.dnsCredentialId || 0) && normalizeText(domain.name) === normalizeText(accelerationDialogValue?.zoneName)) : availableCreateDomains"
      :acceleration-credentials="accelerationCredentials"
      :value="accelerationDialogValue"
      :lock-domain="accelerationDialogLockDomain"
      :lock-plugin-credential="accelerationDialogLockPluginCredential"
      @update:show="showAccelerationSiteDialog = $event"
      @submit="saveAccelerationMutation.mutate"
    />
  </div>
</template>
