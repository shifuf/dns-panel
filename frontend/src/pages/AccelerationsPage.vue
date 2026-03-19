<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NButton, NEmpty, NSelect, NSpin, NTag, useMessage } from 'naive-ui';
import { RefreshCw, Plus, Globe, ShieldCheck } from 'lucide-vue-next';
import {
  listAccelerationConfigs,
  listRemoteAccelerationSites,
  importRemoteAcceleration,
  syncAcceleration,
  verifyAcceleration,
  disableAcceleration,
  setAccelerationSiteStatus,
  deleteRemoteAcceleration,
  syncAllAccelerations,
  type DomainAccelerationConfig,
  type DiscoveredAccelerationSite,
} from '@/services/accelerations';
import { getDnsCredentials, getProviders } from '@/services/dnsCredentials';
import { getDomains } from '@/services/domains';
import { getProviderDisplayName } from '@/utils/provider';
import type { DnsCredential } from '@/types/dns';
import type { Domain } from '@/types';
import AddAccelerationCredentialDialog from '@/components/Dashboard/AddAccelerationCredentialDialog.vue';

const router = useRouter();
const queryClient = useQueryClient();
const message = useMessage();

const showAddAccelerationCredential = ref(false);
const remoteImportTargets = ref<Record<string, number | null>>({});

const { data: accelerationConfigsData, isLoading: loadingConfigs, refetch: refetchAccelerationConfigs } = useQuery({
  queryKey: ['acceleration-configs-page'],
  queryFn: async () => {
    const res = await listAccelerationConfigs();
    return res.data?.items || [];
  },
});

const { data: remoteAccelerationSitesData, isLoading: loadingRemote, refetch: refetchRemoteAccelerationSites } = useQuery({
  queryKey: ['remote-acceleration-sites-page'],
  queryFn: async () => {
    const res = await listRemoteAccelerationSites();
    return res.data?.items || [];
  },
});

const {
  data: dnsContextData,
  isLoading: loadingDnsContext,
} = useQuery({
  queryKey: ['acceleration-page-dns-context'],
  queryFn: async () => {
    const [providersRes, credentialsRes] = await Promise.all([
      getProviders(),
      getDnsCredentials(),
    ]);
    const dnsProviderSet = new Set(
      (providersRes.data?.providers || [])
        .filter((item) => (item.category || 'dns') === 'dns')
        .map((item) => String(item.type || '').trim().toLowerCase()),
    );
    const dnsCredentials = (credentialsRes.data?.credentials || []).filter((item) =>
      dnsProviderSet.has(String(item.provider || '').trim().toLowerCase()),
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
      dnsCredentials,
      domains: domainsByCredential.flat(),
    };
  },
});

const accelerationConfigs = computed<DomainAccelerationConfig[]>(() => accelerationConfigsData.value || []);
const remoteAccelerationSites = computed<DiscoveredAccelerationSite[]>(() => remoteAccelerationSitesData.value || []);
const dnsDomains = computed<Domain[]>(() => dnsContextData.value?.domains || []);
const dnsCredentials = computed<DnsCredential[]>(() => dnsContextData.value?.dnsCredentials || []);

function refreshAccelerationViews() {
  queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  queryClient.invalidateQueries({ queryKey: ['acceleration-configs-page'] });
  queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-page'] });
}

async function refreshCurrentPageData() {
  await Promise.all([
    refetchAccelerationConfigs(),
    refetchRemoteAccelerationSites(),
  ]);
  refreshAccelerationViews();
}

function getRemoteKey(item: DiscoveredAccelerationSite): string {
  return `${item.pluginCredentialId}::${String(item.site.remoteSiteId || item.site.zoneName || '').toLowerCase()}`;
}

const remoteRows = computed(() =>
  remoteAccelerationSites.value.map((item) => {
    const zoneName = String(item.site.zoneName || '').trim();
    const key = getRemoteKey(item);
    const localConfig = accelerationConfigs.value.find((config) =>
      String(config.zoneName || '').trim().toLowerCase() === zoneName.toLowerCase(),
    ) || null;
    const matchingDomains = dnsDomains.value.filter((domain) =>
      String(domain.name || '').trim().toLowerCase() === zoneName.toLowerCase(),
    );
    const selectedDnsCredentialId = remoteImportTargets.value[key]
      ?? localConfig?.dnsCredentialId
      ?? matchingDomains[0]?.credentialId
      ?? null;
    return {
      key,
      zoneName,
      item,
      localConfig,
      matchingDomains,
      selectedDnsCredentialId,
      dnsOptions: matchingDomains
        .filter((domain) => typeof domain.credentialId === 'number')
        .map((domain) => ({
          label: `${domain.name} / ${domain.credentialName || getProviderDisplayName(domain.provider || '') || 'DNS 账户'}`,
          value: domain.credentialId as number,
        })),
    };
  }),
);

watch(remoteRows, (rows) => {
  if (!rows.length) return;
  const next = { ...remoteImportTargets.value };
  let changed = false;
  for (const row of rows) {
    if (next[row.key] !== undefined) continue;
    next[row.key] = row.selectedDnsCredentialId;
    changed = true;
  }
  if (changed) {
    remoteImportTargets.value = next;
  }
}, { immediate: true });

const importRemoteMutation = useMutation({
  mutationFn: async (rowKey: string) => {
    const row = remoteRows.value.find((item) => item.key === rowKey);
    if (!row) throw new Error('远端站点不存在');
    if (!row.selectedDnsCredentialId) throw new Error('请选择要绑定的 DNS 账户');
    return importRemoteAcceleration({
      zoneName: row.zoneName,
      dnsCredentialId: row.selectedDnsCredentialId,
      pluginCredentialId: row.item.pluginCredentialId,
      remoteSiteId: row.item.site.remoteSiteId,
      autoDnsRecord: true,
    });
  },
  onSuccess: async (res) => {
    const added = res.data?.dnsRecordsAdded?.length || 0;
    const skipped = res.data?.dnsRecordsSkipped?.length || 0;
    const failed = res.data?.dnsErrors?.length || 0;
    let text = '远端站点已接管';
    if (added) text += `，新增 ${added} 条验证记录`;
    if (skipped) text += `，${skipped} 条验证记录已存在`;
    if (failed) text += `，${failed} 条验证记录写入失败`;
    message.success(text);
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

const syncConfigMutation = useMutation({
  mutationFn: async (config: DomainAccelerationConfig) => syncAcceleration({
    zoneName: config.zoneName,
    dnsCredentialId: config.dnsCredentialId,
  }),
  onSuccess: async () => {
    message.success('加速状态已同步');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

const verifyConfigMutation = useMutation({
  mutationFn: async (config: DomainAccelerationConfig) => verifyAcceleration({
    zoneName: config.zoneName,
    dnsCredentialId: config.dnsCredentialId,
  }),
  onSuccess: async () => {
    message.success('已提交验证');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

const disableConfigMutation = useMutation({
  mutationFn: async (config: DomainAccelerationConfig) => disableAcceleration({
    zoneName: config.zoneName,
    dnsCredentialId: config.dnsCredentialId,
  }),
  onSuccess: async () => {
    message.success('已移除本地配置');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

const setSiteStatusMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId?: number; pluginCredentialId?: number; remoteSiteId?: string; enabled: boolean }) =>
    setAccelerationSiteStatus(payload),
  onSuccess: async () => {
    message.success('加速站点状态已更新');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

const deleteRemoteMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId?: number; pluginCredentialId?: number; remoteSiteId?: string; deleteLocalConfig?: boolean }) =>
    deleteRemoteAcceleration(payload),
  onSuccess: async () => {
    message.success('远端加速站点已删除');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

const syncAllMutation = useMutation({
  mutationFn: () => syncAllAccelerations(),
  onSuccess: async (res) => {
    const synced = Number(res.data?.synced || 0);
    const failed = Number(res.data?.failed || 0);
    if (failed > 0) {
      message.warning(`同步完成：成功 ${synced}，失败 ${failed}`);
    } else {
      message.success(`已同步 ${synced} 个加速配置`);
    }
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(String(err)),
});

function setRemoteImportTarget(rowKey: string, credentialId: number | null) {
  remoteImportTargets.value = {
    ...remoteImportTargets.value,
    [rowKey]: credentialId,
  };
}

function goToDomain(config: { zoneName: string; dnsCredentialId?: number | null }) {
  const match = dnsDomains.value.find((domain) =>
    domain.credentialId === config.dnsCredentialId
    && String(domain.name || '').trim().toLowerCase() === String(config.zoneName || '').trim().toLowerCase(),
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

const localManagedCount = computed(() => accelerationConfigs.value.length);
const localVerifiedCount = computed(() => accelerationConfigs.value.filter((item) => item.verified).length);
const remoteOnlyCount = computed(() => remoteRows.value.filter((item) => !item.localConfig).length);
const pageLoading = computed(() => loadingConfigs.value || loadingRemote.value || loadingDnsContext.value);
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
          <p class="page-subtitle">集中查看 EdgeOne 已接管列表、远端已有站点以及验证接入状态</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <NButton size="small" secondary @click="refreshCurrentPageData">
            <template #icon><RefreshCw :size="14" /></template>
            刷新列表
          </NButton>
          <NButton size="small" secondary :loading="syncAllMutation.isPending.value" @click="syncAllMutation.mutate()">
            <template #icon><ShieldCheck :size="14" /></template>
            同步全部
          </NButton>
          <NButton size="small" type="primary" @click="showAddAccelerationCredential = true">
            <template #icon><Plus :size="14" /></template>
            添加加速账户
          </NButton>
        </div>
      </div>

      <div class="mt-6 grid gap-4 md:grid-cols-3">
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">已接管</p>
          <p class="mt-3 text-4xl text-slate-800">{{ localManagedCount }}</p>
          <p class="mt-2 text-xs text-slate-500">已纳入本地管理的加速站点</p>
        </article>
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">已验证</p>
          <p class="mt-3 text-4xl text-emerald-600">{{ localVerifiedCount }}</p>
          <p class="mt-2 text-xs text-slate-500">本地配置中已完成验证的站点</p>
        </article>
        <article class="bento-card p-5">
          <p class="text-xs uppercase tracking-widest text-slate-500">待接管</p>
          <p class="mt-3 text-4xl text-amber-600">{{ remoteOnlyCount }}</p>
          <p class="mt-2 text-xs text-slate-500">仅存在于 EdgeOne 远端、尚未接管的站点</p>
        </article>
      </div>
    </section>

    <section class="bento-card col-span-12">
      <div class="mb-4 flex items-center justify-between gap-3">
        <div>
          <p class="bento-section-title">本地加速配置</p>
          <p class="bento-section-meta">已接管并持久化到面板中的 EdgeOne 站点</p>
        </div>
      </div>

      <div v-if="pageLoading" class="flex justify-center py-16">
        <NSpin size="large" />
      </div>
      <NEmpty v-else-if="accelerationConfigs.length === 0" description="暂无本地加速配置" class="py-12" />
      <div v-else class="space-y-3">
        <div v-for="config in accelerationConfigs" :key="config.id" class="panel-muted p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-slate-700">{{ config.zoneName }}</p>
              <p class="mt-1 text-xs text-slate-500">
                Site {{ config.remoteSiteId || '-' }} · DNS 凭证 #{{ config.dnsCredentialId }} · 加速账户 #{{ config.pluginCredentialId }}
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <NTag size="small" :bordered="false" :type="config.verified ? 'success' : (config.paused ? 'warning' : 'default')">
                {{ config.paused ? '已暂停' : (config.verified ? '已验证' : '待验证') }}
              </NTag>
              <NTag size="small" :bordered="false">{{ config.siteStatus || 'unknown' }}</NTag>
            </div>
          </div>

          <div class="mt-3 grid gap-3 md:grid-cols-4">
            <div>
              <p class="text-xs text-slate-500">验证状态</p>
              <p class="mt-1 text-sm text-slate-700">{{ config.verifyStatus || '-' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">接入模式</p>
              <p class="mt-1 text-sm text-slate-700">{{ config.accessType || 'partial' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">区域</p>
              <p class="mt-1 text-sm text-slate-700">{{ config.area || 'global' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">最近同步</p>
              <p class="mt-1 text-sm text-slate-700">{{ config.lastSyncedAt ? new Date(config.lastSyncedAt).toLocaleString('zh-CN') : '-' }}</p>
            </div>
          </div>

          <div class="mt-3 flex flex-wrap gap-2">
            <NButton size="small" secondary @click="goToDomain({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId })">
              <template #icon><Globe :size="14" /></template>
              打开域名
            </NButton>
            <NButton size="small" secondary :loading="syncConfigMutation.isPending.value" @click="syncConfigMutation.mutate(config)">
              刷新状态
            </NButton>
            <NButton v-if="!config.verified" size="small" secondary :loading="verifyConfigMutation.isPending.value" @click="verifyConfigMutation.mutate(config)">
              手动验证
            </NButton>
            <NButton
              size="small"
              secondary
              :loading="setSiteStatusMutation.isPending.value"
              @click="setSiteStatusMutation.mutate({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId, remoteSiteId: config.remoteSiteId, enabled: Boolean(config.paused) })"
            >
              {{ config.paused ? '恢复站点' : '暂停站点' }}
            </NButton>
            <NButton
              size="small"
              tertiary
              type="error"
              :loading="deleteRemoteMutation.isPending.value"
              @click="deleteRemoteMutation.mutate({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId, remoteSiteId: config.remoteSiteId, deleteLocalConfig: true })"
            >
              删除远端
            </NButton>
            <NButton size="small" tertiary :loading="disableConfigMutation.isPending.value" @click="disableConfigMutation.mutate(config)">
              仅移除本地
            </NButton>
          </div>
        </div>
      </div>
    </section>

    <section class="bento-card col-span-12">
      <div class="mb-4">
        <p class="bento-section-title">远端已有站点</p>
        <p class="bento-section-meta">EdgeOne 中已经存在但可能尚未接管到面板的站点</p>
      </div>

      <div v-if="pageLoading" class="flex justify-center py-16">
        <NSpin size="large" />
      </div>
      <NEmpty v-else-if="remoteRows.length === 0" description="暂无远端站点" class="py-12" />
      <div v-else class="space-y-3">
        <div v-for="row in remoteRows" :key="row.key" class="panel-muted p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-slate-700">{{ row.zoneName }}</p>
              <p class="mt-1 text-xs text-slate-500">
                {{ row.item.pluginCredentialName }} · Site {{ row.item.site.remoteSiteId || '-' }}
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <NTag size="small" :bordered="false" :type="row.item.site.verified ? 'success' : (row.item.site.paused ? 'warning' : 'default')">
                {{ row.item.site.paused ? '已暂停' : (row.item.site.verified ? '已验证' : '待验证') }}
              </NTag>
              <NTag v-if="row.localConfig" size="small" :bordered="false" type="success">已接管</NTag>
              <NTag size="small" :bordered="false">{{ row.item.site.siteStatus || 'unknown' }}</NTag>
            </div>
          </div>

          <div class="mt-3 grid gap-3 md:grid-cols-4">
            <div>
              <p class="text-xs text-slate-500">本地状态</p>
              <p class="mt-1 text-sm text-slate-700">{{ row.localConfig ? `DNS #${row.localConfig.dnsCredentialId}` : '未接管' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">匹配域名</p>
              <p class="mt-1 text-sm text-slate-700">{{ row.matchingDomains.length ? `${row.matchingDomains.length} 个候选` : '未匹配' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">接入模式</p>
              <p class="mt-1 text-sm text-slate-700">{{ row.item.site.accessType || 'partial' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">区域 / 套餐</p>
              <p class="mt-1 text-sm text-slate-700">{{ row.item.site.area || 'global' }} / {{ row.item.site.planId || '默认' }}</p>
            </div>
          </div>

          <div v-if="!row.localConfig" class="mt-3">
            <NSelect
              :value="row.selectedDnsCredentialId"
              size="small"
              :options="row.dnsOptions"
              placeholder="选择要绑定的 DNS 账户"
              @update:value="(value) => setRemoteImportTarget(row.key, value == null ? null : Number(value))"
            />
          </div>

          <div class="mt-3 flex flex-wrap gap-2">
            <NButton
              v-if="row.localConfig"
              size="small"
              secondary
              @click="goToDomain({ zoneName: row.zoneName, dnsCredentialId: row.localConfig.dnsCredentialId })"
            >
              打开域名
            </NButton>
            <NButton
              v-if="!row.localConfig"
              size="small"
              type="primary"
              :disabled="!row.selectedDnsCredentialId"
              :loading="importRemoteMutation.isPending.value"
              @click="importRemoteMutation.mutate(row.key)"
            >
              接管站点
            </NButton>
            <NButton
              size="small"
              secondary
              :loading="setSiteStatusMutation.isPending.value"
              @click="setSiteStatusMutation.mutate({ zoneName: row.zoneName, dnsCredentialId: row.localConfig?.dnsCredentialId, pluginCredentialId: row.item.pluginCredentialId, remoteSiteId: row.item.site.remoteSiteId, enabled: Boolean(row.item.site.paused) })"
            >
              {{ row.item.site.paused ? '恢复站点' : '暂停站点' }}
            </NButton>
            <NButton
              size="small"
              tertiary
              type="error"
              :loading="deleteRemoteMutation.isPending.value"
              @click="deleteRemoteMutation.mutate({ zoneName: row.zoneName, dnsCredentialId: row.localConfig?.dnsCredentialId, pluginCredentialId: row.item.pluginCredentialId, remoteSiteId: row.item.site.remoteSiteId, deleteLocalConfig: true })"
            >
              删除远端
            </NButton>
          </div>
        </div>
      </div>
    </section>

    <AddAccelerationCredentialDialog
      v-model:show="showAddAccelerationCredential"
      @created="refreshCurrentPageData"
    />
  </div>
</template>
