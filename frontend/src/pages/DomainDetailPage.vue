<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NAlert, NButton, NSelect, NSpin, NTag, useMessage } from 'naive-ui';
import { Plus, RefreshCw, Globe, ListTree, Activity, Check, Settings, Zap } from 'lucide-vue-next';
import {
  getDNSRecords,
  getDNSLines,
  getDNSMinTTL,
  createDNSRecord,
  updateDNSRecord,
  deleteDNSRecord,
  setDNSRecordStatus,
  refreshDNSRecords,
  batchDeleteDNSRecords,
  batchSetDNSRecordStatus,
} from '@/services/dns';
import { getDomainById } from '@/services/domains';
import { getDnsCredentials, getProviders } from '@/services/dnsCredentials';
import {
  listAccelerationConfigs,
  discoverAccelerationSites,
  enableAcceleration,
  verifyAcceleration,
  syncAcceleration,
  disableAcceleration,
  setAccelerationSiteStatus,
  deleteRemoteAcceleration,
  type DomainAccelerationConfig,
  type DiscoveredAccelerationSite,
} from '@/services/accelerations';
import type { RecordsResponseCapabilities } from '@/services/dns';
import { useProviderStore } from '@/stores/provider';
import { useBreadcrumbStore } from '@/stores/breadcrumb';
import { useCredentialResolver } from '@/composables/useCredentialResolver';
import { useResponsive } from '@/composables/useResponsive';
import type { DNSRecord } from '@/types';
import type { DnsCredential, DnsLine } from '@/types/dns';
import { normalizeProviderType } from '@/utils/provider';
import DNSRecordTable from '@/components/DNSRecordTable/DNSRecordTable.vue';
import QuickAddForm from '@/components/QuickAddForm/QuickAddForm.vue';
import AddAccelerationCredentialDialog from '@/components/Dashboard/AddAccelerationCredentialDialog.vue';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const queryClient = useQueryClient();
const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const { credentialId } = useCredentialResolver();
const { isMobile } = useResponsive();

const zoneId = computed(() => route.params.zoneId as string);
const showAddDialog = ref(false);
const showAddAccelerationCredential = ref(false);
const selectedAccelerationCredentialId = ref<number | null>(null);

const capabilities = computed<RecordsResponseCapabilities>(() => {
  const apiCaps = recordsData.value?.capabilities;
  if (apiCaps) return apiCaps;
  const storeCaps = providerStore.currentCapabilities;
  return {
    supportsWeight: !!storeCaps?.supportsWeight,
    supportsLine: !!storeCaps?.supportsLine,
    supportsStatus: !!storeCaps?.supportsStatus,
    supportsRemark: !!storeCaps?.supportsRemark,
  };
});
const isCloudflare = computed(() => providerStore.selectedProvider === 'cloudflare');

const { data: domainData } = useQuery({
  queryKey: computed(() => ['domain-detail', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getDomainById(zoneId.value, credentialId.value);
    return res.data?.domain || null;
  },
  enabled: computed(() => !!zoneId.value),
});

// DNS records
const { data: recordsData, isLoading: recordsLoading, refetch: refetchRecords } = useQuery({
  queryKey: computed(() => ['dns-records', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getDNSRecords(zoneId.value, credentialId.value);
    return res.data as { records: DNSRecord[]; capabilities?: RecordsResponseCapabilities };
  },
  enabled: computed(() => !!zoneId.value),
});

const records = computed(() => recordsData.value?.records || []);
const zoneName = computed(() =>
  domainData.value?.name || records.value[0]?.zoneName || ''
);
const visibleRecords = computed(() =>
  records.value.filter((r) => !(r.type === 'NS' && r.name === r.zoneName))
);
const hiddenRootNsCount = computed(() => records.value.length - visibleRecords.value.length);
const enabledCount = computed(() => visibleRecords.value.filter(r => r.enabled !== false).length);
const recordTypeCount = computed(() => new Set(visibleRecords.value.map(r => r.type)).size);

// DNS lines
const { data: linesData } = useQuery({
  queryKey: computed(() => ['dns-lines', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getDNSLines(zoneId.value, credentialId.value);
    return res.data?.lines || [];
  },
  enabled: computed(() => !!zoneId.value && !!capabilities.value?.supportsLine),
});
const lines = computed<DnsLine[]>(() => linesData.value || []);

// Min TTL
const { data: minTTLData } = useQuery({
  queryKey: computed(() => ['dns-min-ttl', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getDNSMinTTL(zoneId.value, credentialId.value);
    return res.data?.minTTL ?? 1;
  },
  enabled: computed(() => !!zoneId.value),
});
const minTTL = computed(() => minTTLData.value ?? 1);

const { data: accelerationCredentialData, refetch: refetchAccelerationCredentials } = useQuery({
  queryKey: ['acceleration-credentials'],
  queryFn: async () => {
    const [providersRes, credentialsRes] = await Promise.all([
      getProviders(),
      getDnsCredentials(),
    ]);
    const accelerationProviderSet = new Set(
      (providersRes.data?.providers || [])
        .filter((item) => (item.category || 'dns') === 'acceleration')
        .map((item) => normalizeProviderType(item.type)),
    );
    return (credentialsRes.data?.credentials || []).filter((item) =>
      accelerationProviderSet.has(normalizeProviderType(item.provider)),
    ) as DnsCredential[];
  },
});

const accelerationCredentials = computed(() => accelerationCredentialData.value || []);

watch(accelerationCredentials, (list) => {
  if (!list.length) {
    selectedAccelerationCredentialId.value = null;
    return;
  }
  if (selectedAccelerationCredentialId.value && list.some((item) => item.id === selectedAccelerationCredentialId.value)) {
    return;
  }
  selectedAccelerationCredentialId.value = list[0].id;
}, { immediate: true });

const { data: accelerationConfigData, isLoading: accelerationLoading, refetch: refetchAccelerationConfig } = useQuery({
  queryKey: computed(() => ['acceleration-config', zoneName.value, credentialId.value]),
  queryFn: async () => {
    if (!zoneName.value || typeof credentialId.value !== 'number') return null;
    const res = await listAccelerationConfigs({
      zoneName: zoneName.value,
      dnsCredentialId: credentialId.value,
    });
    return res.data?.items?.[0] || null;
  },
  enabled: computed(() => !!zoneName.value && typeof credentialId.value === 'number'),
});

const accelerationConfig = computed<DomainAccelerationConfig | null>(() => accelerationConfigData.value || null);

const { data: discoveredAccelerationData, isLoading: discoveringAcceleration, refetch: refetchDiscoveredAcceleration } = useQuery({
  queryKey: computed(() => ['acceleration-discover', zoneName.value]),
  queryFn: async () => {
    if (!zoneName.value) return [];
    const res = await discoverAccelerationSites({ zoneName: zoneName.value });
    return res.data?.items || [];
  },
  enabled: computed(() => !!zoneName.value),
});

const discoveredAccelerationSites = computed<DiscoveredAccelerationSite[]>(() => discoveredAccelerationData.value || []);

watch(accelerationConfig, (config) => {
  if (config?.pluginCredentialId) {
    selectedAccelerationCredentialId.value = config.pluginCredentialId;
  }
}, { immediate: true });

watch(discoveredAccelerationSites, (list) => {
  if (accelerationConfig.value?.pluginCredentialId) return;
  if (selectedAccelerationCredentialId.value && list.some((item) => item.pluginCredentialId === selectedAccelerationCredentialId.value)) return;
  if (list[0]?.pluginCredentialId) {
    selectedAccelerationCredentialId.value = list[0].pluginCredentialId;
  }
}, { immediate: true });

// Keep provider context in sync when navigating from dashboard with credentialId.
watch(
  [credentialId, () => providerStore.credentials.length],
  ([credId]) => {
    if (typeof credId !== 'number' || !Number.isFinite(credId)) return;
    const cred = providerStore.credentials.find(c => c.id === credId);
    if (!cred) return;

    if (providerStore.selectedProvider !== normalizeProviderType(cred.provider)) {
      providerStore.selectProvider(cred.provider);
    }
    if (providerStore.selectedCredentialId !== credId) {
      providerStore.selectCredential(credId);
    }
  },
  { immediate: true }
);

// Set breadcrumb label
watch(zoneName, () => {
  if (zoneName.value) {
    breadcrumbStore.setLabel(`zone:${zoneId.value}`, zoneName.value);
  }
}, { immediate: true });

const accelerationStatusMeta = computed(() => {
  const config = accelerationConfig.value;
  if (!config) return { type: 'default' as const, label: '未接入', detail: '尚未接入加速' };
  if (config.paused) return { type: 'warning' as const, label: '已暂停', detail: config.siteStatus || '加速站点当前已暂停' };
  if (config.verified) return { type: 'success' as const, label: '已验证', detail: config.siteStatus || '加速已生效' };
  if (config.lastError) return { type: 'error' as const, label: '异常', detail: config.lastError };
  return { type: 'warning' as const, label: '待验证', detail: config.verifyStatus || config.siteStatus || '等待验证' };
});

const selectedDiscoveredSite = computed<DiscoveredAccelerationSite | null>(() => {
  if (!selectedAccelerationCredentialId.value) return discoveredAccelerationSites.value[0] || null;
  return discoveredAccelerationSites.value.find((item) => item.pluginCredentialId === selectedAccelerationCredentialId.value) || discoveredAccelerationSites.value[0] || null;
});

const effectiveAccelerationView = computed(() => {
  if (accelerationConfig.value) {
    return {
      source: 'local' as const,
      site: accelerationConfig.value,
      credentialName: accelerationCredentials.value.find((item) => item.id === accelerationConfig.value?.pluginCredentialId)?.name || '',
    };
  }
  if (selectedDiscoveredSite.value) {
    return {
      source: 'remote' as const,
      site: selectedDiscoveredSite.value.site,
      credentialName: selectedDiscoveredSite.value.pluginCredentialName,
    };
  }
  return null;
});

const accelerationStatusDisplay = computed(() => {
  const current = effectiveAccelerationView.value;
  if (!current) return { type: 'default' as const, label: '未接入', detail: '尚未接入加速' };
  const site = current.site;
  if (current.source === 'remote') {
    if (site.paused) return { type: 'warning' as const, label: '远端已暂停', detail: site.siteStatus || 'EdgeOne 远端站点当前已暂停' };
    if (site.verified) return { type: 'success' as const, label: '远端已接入', detail: site.siteStatus || 'EdgeOne 已存在站点' };
    return { type: 'warning' as const, label: '远端待接管', detail: site.verifyStatus || site.siteStatus || 'EdgeOne 已存在站点，尚未纳入本地管理' };
  }
  return accelerationStatusMeta.value;
});

function copyText(text: string | undefined) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(
    () => message.success('已复制'),
    () => message.error('复制失败'),
  );
}

const enableAccelerationMutation = useMutation({
  mutationFn: async () => {
    const pluginCredentialId = selectedAccelerationCredentialId.value;
    if (!zoneName.value || typeof credentialId.value !== 'number' || !pluginCredentialId) {
      throw new Error('缺少域名、DNS 凭证或 EdgeOne 凭证');
    }
    return enableAcceleration({
      zoneName: zoneName.value,
      zoneId: zoneId.value,
      dnsCredentialId: credentialId.value,
      pluginCredentialId,
      autoDnsRecord: true,
    });
  },
  onSuccess: async (res) => {
    const added = res.data?.dnsRecordsAdded || [];
    const skipped = res.data?.dnsRecordsSkipped || [];
    const errors = res.data?.dnsErrors || [];
    let text = '已提交加速接入';
    if (added.length) text += `，已自动创建 ${added.length} 条验证记录`;
    if (skipped.length) text += `，${skipped.length} 条验证记录已存在`;
    if (errors.length) text += `，${errors.length} 条记录创建失败`;
    if (res.data?.config?.verified) text += '，验证已完成';
    message.success(text);
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const accelerationSiteStatusMutation = useMutation({
  mutationFn: async (enabled: boolean) => {
    const current = effectiveAccelerationView.value;
    if (!zoneName.value || !current) {
      throw new Error('缺少可操作的加速站点');
    }
    return setAccelerationSiteStatus({
      zoneName: zoneName.value,
      dnsCredentialId: typeof credentialId.value === 'number' ? credentialId.value : undefined,
      pluginCredentialId: current.source === 'remote' ? selectedDiscoveredSite.value?.pluginCredentialId : undefined,
      remoteSiteId: current.site.remoteSiteId,
      enabled,
    });
  },
  onSuccess: async () => {
    message.success('加速站点状态已更新');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const deleteRemoteAccelerationMutation = useMutation({
  mutationFn: async () => {
    const current = effectiveAccelerationView.value;
    if (!zoneName.value || !current) {
      throw new Error('缺少可删除的加速站点');
    }
    return deleteRemoteAcceleration({
      zoneName: zoneName.value,
      dnsCredentialId: typeof credentialId.value === 'number' ? credentialId.value : undefined,
      pluginCredentialId: current.source === 'remote' ? selectedDiscoveredSite.value?.pluginCredentialId : undefined,
      remoteSiteId: current.site.remoteSiteId,
      deleteLocalConfig: true,
    });
  },
  onSuccess: async () => {
    message.success('远端加速站点已删除');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const verifyAccelerationMutation = useMutation({
  mutationFn: async () => {
    if (!zoneName.value || typeof credentialId.value !== 'number') {
      throw new Error('缺少域名或 DNS 凭证');
    }
    return verifyAcceleration({
      zoneName: zoneName.value,
      dnsCredentialId: credentialId.value,
    });
  },
  onSuccess: async (res) => {
    message.success(res.data?.config?.verified ? '加速验证成功' : '已提交加速验证');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const syncAccelerationMutation = useMutation({
  mutationFn: async () => {
    if (!zoneName.value || typeof credentialId.value !== 'number') {
      throw new Error('缺少域名或 DNS 凭证');
    }
    return syncAcceleration({
      zoneName: zoneName.value,
      dnsCredentialId: credentialId.value,
    });
  },
  onSuccess: async () => {
    message.success('加速状态已同步');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const disableAccelerationMutation = useMutation({
  mutationFn: async () => {
    if (!zoneName.value || typeof credentialId.value !== 'number') {
      throw new Error('缺少域名或 DNS 凭证');
    }
    return disableAcceleration({
      zoneName: zoneName.value,
      dnsCredentialId: credentialId.value,
    });
  },
  onSuccess: async () => {
    message.success('已移除本地加速配置');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// Mutations
const createMutation = useMutation({
  mutationFn: (params: Parameters<typeof createDNSRecord>[1]) => createDNSRecord(zoneId.value, params, credentialId.value),
  onSuccess: () => { message.success('记录已添加'); showAddDialog.value = false; refetchRecords(); },
  onError: (err: any) => message.error(String(err)),
});

const updateMutation = useMutation({
  mutationFn: (vars: { recordId: string; params: Parameters<typeof updateDNSRecord>[2] }) =>
    updateDNSRecord(zoneId.value, vars.recordId, vars.params, credentialId.value),
  onSuccess: () => { message.success('记录已更新'); refetchRecords(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteRecordMutation = useMutation({
  mutationFn: (recordId: string) => deleteDNSRecord(zoneId.value, recordId, credentialId.value),
  onSuccess: () => { message.success('记录已删除'); refetchRecords(); },
  onError: (err: any) => message.error(String(err)),
});

const statusMutation = useMutation({
  mutationFn: (vars: { recordId: string; enabled: boolean }) =>
    setDNSRecordStatus(zoneId.value, vars.recordId, vars.enabled, credentialId.value),
  onSuccess: () => { message.success('状态已更新'); refetchRecords(); },
  onError: (err: any) => message.error(String(err)),
});

async function handleRefresh() {
  try {
    await refreshDNSRecords(zoneId.value, credentialId.value);
    await refetchRecords();
    message.success('已刷新');
  } catch (err: any) {
    message.error(String(err));
  }
}

function handleAddSubmit(params: any) {
  createMutation.mutate(params);
}

function handleUpdate(recordId: string, params: any) {
  updateMutation.mutate({ recordId, params });
}

function handleDelete(recordId: string) {
  deleteRecordMutation.mutate(recordId);
}

function handleStatusChange(recordId: string, enabled: boolean) {
  statusMutation.mutate({ recordId, enabled });
}

async function handleBatchDelete(recordIds: string[]) {
  if (!recordIds.length) return;
  try {
    const res = await batchDeleteDNSRecords(zoneId.value, recordIds, credentialId.value);
    const success = Number(res.data?.successCount || 0);
    const failed = Number(res.data?.failedCount || 0);
    if (failed > 0) {
      message.warning(`批量删除完成：成功 ${success}，失败 ${failed}`);
    } else {
      message.success(`已删除 ${success} 条记录`);
    }
    await refetchRecords();
  } catch (err: any) {
    message.error(String(err));
  }
}

async function handleBatchStatusChange(recordIds: string[], enabled: boolean) {
  if (!recordIds.length) return;
  try {
    const res = await batchSetDNSRecordStatus(zoneId.value, recordIds, enabled, credentialId.value);
    const success = Number(res.data?.successCount || 0);
    const failed = Number(res.data?.failedCount || 0);
    if (failed > 0) {
      message.warning(`批量${enabled ? '启用' : '禁用'}完成：成功 ${success}，失败 ${failed}`);
    } else {
      message.success(`已${enabled ? '启用' : '禁用'} ${success} 条记录`);
    }
    await refetchRecords();
  } catch (err: any) {
    message.error(String(err));
  }
}
</script>

<template>
  <div class="bento-grid">
    <section class="bento-hero col-span-12">
      <div class="flex flex-col md:flex-row gap-6">
        <div class="flex-1">
          <div class="section-badge">
            <span class="dot" />
            <span class="label">Zone Workspace</span>
          </div>
          <h1 class="page-title">
            DNS 记录
            <span class="gradient-text"> 详情</span>
          </h1>
          <p class="page-subtitle">
            Zone: {{ zoneId }} · 最小 TTL {{ minTTL }}
            <template v-if="hiddenRootNsCount > 0"> · 已隐藏根NS {{ hiddenRootNsCount }} 条</template>
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          <NTag size="small" :bordered="false" type="success">
            启用记录 {{ enabledCount }}
          </NTag>
          <NTag size="small" :bordered="false">
            类型 {{ recordTypeCount }}
          </NTag>
          <NButton
            v-if="isCloudflare"
            size="small"
            secondary
            @click="router.push({ path: `/hostnames/${zoneId}`, query: credentialId ? { credentialId: String(credentialId) } : {} })"
          >
            <template #icon><Globe :size="14" /></template>
            Hostnames
          </NButton>
          <NButton size="small" type="primary" @click="showAddDialog = true">
            <template #icon><Plus :size="14" /></template>
            添加记录
          </NButton>
          <NButton size="small" secondary @click="handleRefresh">
            <template #icon><RefreshCw :size="14" /></template>
          </NButton>
        </div>
      </div>

      <div class="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        <article class="bento-card p-5 relative overflow-hidden">
          <div class="absolute -right-12 -top-12 w-44 h-44 rounded-full bg-gradient-to-br from-indigo-500/20 to-violet-500/20 blur-2xl" />
          <div class="absolute right-4 top-4 w-14 h-14 rounded-full bg-gradient-to-br from-indigo-400/30 to-violet-400/30 blur-xl" />
          <div class="relative z-10">
            <p class="text-xs uppercase tracking-widest text-slate-500">记录总数</p>
            <div class="mt-2">
              <p class="text-5xl bg-gradient-to-r from-indigo-600 to-violet-600 bg-clip-text text-transparent">{{ visibleRecords.length }}</p>
            </div>
            <div class="mt-3 h-2.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-indigo-500 to-violet-500 rounded-full" :style="{ width: Math.min(100, (enabledCount / Math.max(1, visibleRecords.length)) * 100) + '%' }"></div>
            </div>
            <p class="mt-3 text-xs text-slate-500">
              启用 {{ enabledCount }} 条 · 占比 {{ visibleRecords.length > 0 ? Math.round((enabledCount / visibleRecords.length) * 100) : 0 }}%
            </p>
          </div>
        </article>
        <article class="bento-card p-5 relative overflow-hidden">
          <div class="absolute -left-12 -bottom-12 w-36 h-36 rounded-full bg-gradient-to-br from-emerald-500/18 to-green-500/18 blur-xl" />
          <div class="absolute left-4 bottom-4 w-12 h-12 rounded-full bg-gradient-to-br from-emerald-400/25 to-green-400/25 blur-lg" />
          <div class="relative z-10">
            <p class="text-xs uppercase tracking-widest text-slate-500">线路策略</p>
            <div class="mt-2 flex items-center gap-1.5">
              <span class="w-3.5 h-3.5 rounded-full bg-emerald-500 shadow-lg shadow-emerald-500/35"></span>
              <p class="text-5xl text-emerald-600">{{ lines.length || 1 }}</p>
            </div>
            <div class="mt-3 flex items-center gap-2">
              <span class="text-xs text-slate-500">解析线路</span>
              <div class="flex gap-0.5">
                <span v-for="i in Math.min(lines.length || 1, 5)" :key="i" class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              </div>
            </div>
          </div>
        </article>
        <article class="bento-card p-5 relative overflow-hidden">
          <div class="absolute -right-14 -top-14 w-44 h-44 rounded-full bg-gradient-to-br from-amber-500/18 to-yellow-500/18 blur-xl" />
          <div class="absolute right-4 top-4 w-12 h-12 rounded-full bg-gradient-to-br from-amber-400/25 to-yellow-400/25 blur-lg" />
          <div class="relative z-10">
            <p class="text-xs uppercase tracking-widest text-slate-500">变更能力</p>
            <div class="mt-3">
              <p class="text-lg bg-gradient-to-r from-amber-600 to-yellow-600 bg-clip-text text-transparent">
                {{ capabilities?.supportsStatus || capabilities?.supportsRemark ? '含状态/备注' : '标准模式' }}
              </p>
            </div>
            <div class="mt-3 flex gap-2">
              <span v-if="capabilities?.supportsStatus" class="inline-flex items-center gap-1 text-xs font-semibold bg-emerald-100 text-emerald-700 px-2 py-0.5 rounded-lg">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                状态
              </span>
              <span v-if="capabilities?.supportsRemark" class="inline-flex items-center gap-1 text-xs font-semibold bg-blue-100 text-blue-700 px-2 py-0.5 rounded-lg">
                <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                备注
              </span>
              <span v-if="capabilities?.supportsWeight" class="inline-flex items-center gap-1 text-xs font-semibold bg-purple-100 text-purple-700 px-2 py-0.5 rounded-lg">
                <span class="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
                权重
              </span>
            </div>
          </div>
        </article>
      </div>
    </section>

    <section class="bento-card col-span-12">
      <div class="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <p class="bento-section-title">加速管理</p>
          <p class="bento-section-meta">接入 EdgeOne 后可自动生成域名归属验证记录，并支持手动验证与状态同步</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <NTag size="small" :bordered="false" :type="accelerationStatusDisplay.type">
            {{ accelerationStatusDisplay.label }}
          </NTag>
          <NTag v-if="effectiveAccelerationView?.site?.remoteSiteId" size="small" :bordered="false">
            Site {{ effectiveAccelerationView.site.remoteSiteId }}
          </NTag>
        </div>
      </div>

      <div v-if="accelerationLoading || discoveringAcceleration" class="flex justify-center py-10">
        <NSpin size="large" />
      </div>

      <div v-else class="space-y-4">
        <NAlert v-if="accelerationConfig?.lastError" type="warning" :bordered="false">
          {{ accelerationConfig.lastError }}
        </NAlert>

        <NAlert
          v-if="!accelerationConfig && selectedDiscoveredSite"
          type="info"
          :bordered="false"
        >
          检测到 EdgeOne 中已存在当前域名站点，来源账户：{{ selectedDiscoveredSite.pluginCredentialName }}。可以直接接管到面板中继续管理。
        </NAlert>

        <div v-if="!accelerationCredentials.length" class="rounded-2xl border border-dashed border-panel-border bg-panel-surface p-5">
          <p class="text-sm font-semibold text-slate-700">暂无可用的加速账户</p>
          <p class="mt-1 text-sm text-slate-500">先添加一个 EdgeOne 账户，再为当前域名接入加速。</p>
          <div class="mt-4">
            <NButton size="small" type="primary" @click="showAddAccelerationCredential = true">
              添加加速账户
            </NButton>
          </div>
        </div>

        <template v-else>
          <div class="grid gap-4 md:grid-cols-[280px_1fr]">
            <div>
              <label class="mb-2 block text-sm text-slate-500">加速厂商账户</label>
              <NSelect
                v-model:value="selectedAccelerationCredentialId"
                size="small"
                :options="accelerationCredentials.map((item) => ({ label: item.name, value: item.id }))"
                placeholder="选择 EdgeOne 账户"
              />
            </div>
            <div class="rounded-2xl border border-panel-border bg-panel-surface p-4">
              <div class="flex flex-wrap items-center gap-2">
                <NButton
                  v-if="!accelerationConfig"
                  size="small"
                  type="primary"
                  :loading="enableAccelerationMutation.isPending.value"
                  @click="enableAccelerationMutation.mutate()"
                >
                  {{ selectedDiscoveredSite ? '接管已有站点' : '接入 EdgeOne' }}
                </NButton>
                <template v-if="accelerationConfig">
                  <NButton
                    size="small"
                    secondary
                    :loading="syncAccelerationMutation.isPending.value"
                    @click="syncAccelerationMutation.mutate()"
                  >
                    刷新状态
                  </NButton>
                  <NButton
                    v-if="!accelerationConfig.verified"
                    size="small"
                    type="primary"
                    :loading="verifyAccelerationMutation.isPending.value"
                    @click="verifyAccelerationMutation.mutate()"
                  >
                    手动验证
                  </NButton>
                  <NButton
                    size="small"
                    secondary
                    :loading="accelerationSiteStatusMutation.isPending.value"
                    @click="accelerationSiteStatusMutation.mutate(Boolean(accelerationConfig?.paused))"
                  >
                    {{ accelerationConfig?.paused ? '恢复站点' : '暂停站点' }}
                  </NButton>
                  <NButton
                    size="small"
                    tertiary
                    type="error"
                    :loading="deleteRemoteAccelerationMutation.isPending.value"
                    @click="deleteRemoteAccelerationMutation.mutate()"
                  >
                    删除远端
                  </NButton>
                  <NButton
                    size="small"
                    tertiary
                    :loading="disableAccelerationMutation.isPending.value"
                    @click="disableAccelerationMutation.mutate()"
                  >
                    移除配置
                  </NButton>
                </template>
                <template v-else-if="selectedDiscoveredSite">
                  <NButton
                    size="small"
                    secondary
                    :loading="syncAccelerationMutation.isPending.value"
                    @click="refetchDiscoveredAcceleration()"
                  >
                    刷新远端
                  </NButton>
                  <NButton
                    size="small"
                    secondary
                    :loading="accelerationSiteStatusMutation.isPending.value"
                    @click="accelerationSiteStatusMutation.mutate(Boolean(selectedDiscoveredSite.site.paused))"
                  >
                    {{ selectedDiscoveredSite.site.paused ? '恢复远端' : '暂停远端' }}
                  </NButton>
                  <NButton
                    size="small"
                    tertiary
                    type="error"
                    :loading="deleteRemoteAccelerationMutation.isPending.value"
                    @click="deleteRemoteAccelerationMutation.mutate()"
                  >
                    删除远端
                  </NButton>
                </template>
                <NButton size="small" secondary @click="showAddAccelerationCredential = true">
                  新增加速账户
                </NButton>
              </div>
              <p class="mt-3 text-sm text-slate-500">
                {{ accelerationStatusDisplay.detail || '当前还没有加速接入状态' }}
              </p>
            </div>
          </div>

          <div v-if="effectiveAccelerationView" class="grid gap-4 md:grid-cols-3">
            <article class="rounded-2xl border border-panel-border bg-panel-surface p-4">
              <p class="text-xs uppercase tracking-widest text-slate-500">站点状态</p>
              <p class="mt-2 text-lg font-semibold text-slate-800">{{ effectiveAccelerationView.site.siteStatus || '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">验证状态：{{ effectiveAccelerationView.site.verifyStatus || '-' }}</p>
            </article>
            <article class="rounded-2xl border border-panel-border bg-panel-surface p-4">
              <p class="text-xs uppercase tracking-widest text-slate-500">接入模式</p>
              <p class="mt-2 text-lg font-semibold text-slate-800">{{ effectiveAccelerationView.site.accessType || 'partial' }}</p>
              <p class="mt-1 text-xs text-slate-500">区域：{{ effectiveAccelerationView.site.area || 'global' }}</p>
            </article>
            <article class="rounded-2xl border border-panel-border bg-panel-surface p-4">
              <p class="text-xs uppercase tracking-widest text-slate-500">{{ effectiveAccelerationView.source === 'local' ? '最近同步' : '远端账户' }}</p>
              <p class="mt-2 text-lg font-semibold text-slate-800">
                {{
                  effectiveAccelerationView.source === 'local'
                    ? (accelerationConfig?.lastSyncedAt ? new Date(accelerationConfig.lastSyncedAt).toLocaleString('zh-CN') : '-')
                    : (effectiveAccelerationView.credentialName || '-')
                }}
              </p>
              <p class="mt-1 text-xs text-slate-500">套餐：{{ effectiveAccelerationView.site.planId || '默认' }}</p>
            </article>
          </div>

          <div v-if="effectiveAccelerationView?.site?.verifyRecordName" class="rounded-2xl border border-panel-border bg-panel-surface p-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p class="text-sm font-semibold text-slate-700">验证记录</p>
                <p class="text-xs text-slate-500">接入时会自动写入当前 DNS 服务商，也可以复制后手动补录</p>
              </div>
            </div>
            <div class="mt-4 grid gap-3 md:grid-cols-3">
              <div class="rounded-xl bg-white/60 p-3">
                <p class="text-xs text-slate-500">类型</p>
                <button class="mt-1 text-left text-sm font-medium text-slate-800" @click="copyText(effectiveAccelerationView.site.verifyRecordType)">
                  {{ effectiveAccelerationView.site.verifyRecordType || 'TXT' }}
                </button>
              </div>
              <div class="rounded-xl bg-white/60 p-3">
                <p class="text-xs text-slate-500">主机记录</p>
                <button class="mt-1 break-all text-left text-sm font-medium text-slate-800" @click="copyText(effectiveAccelerationView.site.verifyRecordName)">
                  {{ effectiveAccelerationView.site.verifyRecordName }}
                </button>
              </div>
              <div class="rounded-xl bg-white/60 p-3">
                <p class="text-xs text-slate-500">记录值</p>
                <button class="mt-1 break-all text-left text-sm font-medium text-slate-800" @click="copyText(effectiveAccelerationView.site.verifyRecordValue)">
                  {{ effectiveAccelerationView.site.verifyRecordValue }}
                </button>
              </div>
            </div>
          </div>

          <div v-if="discoveredAccelerationSites.length > 1 && !accelerationConfig" class="rounded-2xl border border-panel-border bg-panel-surface p-4">
            <p class="text-sm font-semibold text-slate-700">发现的远端站点</p>
            <p class="mt-1 text-xs text-slate-500">如果同一域名在多个 EdgeOne 账户下已存在，这里会展示所有候选站点。</p>
            <div class="mt-4 grid gap-3">
              <div
                v-for="item in discoveredAccelerationSites"
                :key="`${item.pluginCredentialId}-${item.site.remoteSiteId}`"
                class="rounded-xl border border-panel-border bg-white/60 p-3"
              >
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p class="text-sm font-medium text-slate-800">{{ item.pluginCredentialName }}</p>
                    <p class="text-xs text-slate-500">Site {{ item.site.remoteSiteId || '-' }} · {{ item.site.siteStatus || 'unknown' }}</p>
                  </div>
                  <NButton size="small" secondary @click="selectedAccelerationCredentialId = item.pluginCredentialId">
                    选择此账户
                  </NButton>
                </div>
              </div>
            </div>
          </div>
        </template>
      </div>
    </section>

    <section class="bento-card col-span-12">
      <div class="mb-4">
        <p class="bento-section-title">记录列表</p>
        <p class="bento-section-meta">支持批量启用/禁用、批量删除、字段自定义显示</p>
      </div>

      <div v-if="recordsLoading" class="flex justify-center py-20">
        <NSpin size="large" />
      </div>

      <DNSRecordTable
        v-else
        :records="records"
        :lines="lines"
        :min-ttl="minTTL"
        :capabilities="capabilities"
        @update="handleUpdate"
        @delete="handleDelete"
        @status-change="handleStatusChange"
        @batch-delete="handleBatchDelete"
        @batch-status-change="handleBatchStatusChange"
      />
    </section>

    <QuickAddForm
      v-model:show="showAddDialog"
      :lines="lines"
      :min-ttl="minTTL"
      :loading="createMutation.isPending.value"
      @submit="handleAddSubmit"
    />
    <AddAccelerationCredentialDialog
      v-model:show="showAddAccelerationCredential"
      @created="() => { refetchAccelerationCredentials(); refetchDiscoveredAcceleration(); }"
    />
  </div>
</template>
