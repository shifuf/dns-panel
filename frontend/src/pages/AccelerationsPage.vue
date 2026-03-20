<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NButton, NEmpty, NInput, NSelect, NSpin, NTag, useMessage } from 'naive-ui';
import { RefreshCw, Plus, Globe, ShieldCheck } from 'lucide-vue-next';
import {
  listAccelerationConfigs,
  listRemoteAccelerationSites,
  importRemoteAcceleration,
  createAccelerationVerifyRecord,
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

type RowStatus = 'verified' | 'pending' | 'paused' | 'error';
type LocalStatusFilter = 'all' | RowStatus;
type RemoteStatusFilter = 'all' | 'verified' | 'pending' | 'paused';
type RemoteOwnershipFilter = 'all' | 'managed' | 'unmanaged';

type LocalAccelerationRow = DomainAccelerationConfig & {
  key: string;
  dnsCredentialName: string;
  pluginCredentialName: string;
  status: RowStatus;
  hasError: boolean;
  searchText: string;
};

type RemoteAccelerationRow = {
  key: string;
  zoneName: string;
  item: DiscoveredAccelerationSite;
  localConfig: LocalAccelerationRow | null;
  matchingDomains: Domain[];
  selectedDnsCredentialId: number | null;
  dnsOptions: Array<{ label: string; value: number }>;
  dnsCredentialName: string;
  ownershipStatus: 'managed' | 'unmanaged';
  searchText: string;
};

const router = useRouter();
const queryClient = useQueryClient();
const message = useMessage();

const showAddAccelerationCredential = ref(false);
const remoteImportTargets = ref<Record<string, number | null>>({});
const localKeyword = ref('');
const localStatusFilter = ref<LocalStatusFilter>('all');
const localDnsCredentialFilter = ref<number | null>(null);
const localPluginCredentialFilter = ref<number | null>(null);
const remoteKeyword = ref('');
const remoteStatusFilter = ref<RemoteStatusFilter>('all');
const remoteOwnershipFilter = ref<RemoteOwnershipFilter>('all');
const remotePluginCredentialFilter = ref<number | null>(null);
const isBatchRunning = ref(false);
const batchFeedback = ref<{ tone: 'warning' | 'error'; title: string; items: string[] } | null>(null);

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
const remoteAccelerationSites = computed<DiscoveredAccelerationSite[]>(() => remoteAccelerationSitesData.value || []);
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
    refetchRemoteAccelerationSites(),
  ]);
  refreshAccelerationViews();
}

function getRemoteKey(item: DiscoveredAccelerationSite): string {
  return `${item.pluginCredentialId}::${normalizeText(item.site.remoteSiteId || item.site.zoneName)}`;
}

function getLocalKey(config: DomainAccelerationConfig): string {
  return `${config.dnsCredentialId}::${normalizeText(config.zoneName)}`;
}

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
    const keyword = normalizeText(localKeyword.value);
    if (keyword && !row.searchText.includes(keyword)) return false;
    if (localStatusFilter.value !== 'all' && row.status !== localStatusFilter.value) return false;
    if (localDnsCredentialFilter.value && row.dnsCredentialId !== localDnsCredentialFilter.value) return false;
    if (localPluginCredentialFilter.value && row.pluginCredentialId !== localPluginCredentialFilter.value) return false;
    return true;
  }),
);

const remoteRows = computed<RemoteAccelerationRow[]>(() =>
  remoteAccelerationSites.value.map((item) => {
    const zoneName = String(item.site.zoneName || '').trim();
    const key = getRemoteKey(item);
    const localConfig = localRows.value.find((config) =>
      normalizeText(config.zoneName) === normalizeText(zoneName),
    ) || null;
    const matchingDomains = dnsDomains.value.filter((domain) =>
      normalizeText(domain.name) === normalizeText(zoneName),
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
      dnsCredentialName: selectedDnsCredentialId
        ? (credentialNameMap.value.get(selectedDnsCredentialId) || `DNS 凭证 #${selectedDnsCredentialId}`)
        : '未选择 DNS 账户',
      ownershipStatus: localConfig ? 'managed' : 'unmanaged',
      searchText: [
        zoneName,
        item.site.accelerationDomain,
        item.site.remoteSiteId,
        item.site.siteStatus,
        item.site.domainStatus,
        item.site.verifyStatus,
        item.site.identificationStatus,
        item.site.cnameStatus,
        item.site.cnameTarget,
        item.site.originValue,
        item.site.hostHeader,
        item.site.accessType,
        item.site.area,
        item.site.planId,
        item.pluginCredentialName,
        localConfig?.dnsCredentialName,
      ].join(' ').toLowerCase(),
    };
  }),
);

const filteredRemoteRows = computed(() =>
  remoteRows.value.filter((row) => {
    const keyword = normalizeText(remoteKeyword.value);
    if (keyword && !row.searchText.includes(keyword)) return false;
    if (remoteStatusFilter.value !== 'all') {
      const status = row.item.site.paused ? 'paused' : (row.item.site.verified ? 'verified' : 'pending');
      if (status !== remoteStatusFilter.value) return false;
    }
    if (remoteOwnershipFilter.value !== 'all' && row.ownershipStatus !== remoteOwnershipFilter.value) return false;
    if (remotePluginCredentialFilter.value && row.item.pluginCredentialId !== remotePluginCredentialFilter.value) return false;
    return true;
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

async function syncExistingRemoteSites() {
  await runBatch({
    items: remoteRows.value.filter((row) => !row.localConfig && row.selectedDnsCredentialId),
    emptyMessage: '没有可同步的远端站点，或尚未匹配到可用的 DNS 账户',
    actionLabel: '远端站点同步',
    describe: (row) => row.zoneName,
    execute: (row) => importRemoteAcceleration({
      zoneName: row.zoneName,
      dnsCredentialId: Number(row.selectedDnsCredentialId),
      pluginCredentialId: row.item.pluginCredentialId,
      remoteSiteId: row.item.site.remoteSiteId,
      autoDnsRecord: true,
    }),
  });
}

const syncConfigMutation = useMutation({
  mutationFn: async (config: DomainAccelerationConfig) => syncAcceleration({
    zoneName: config.zoneName,
    dnsCredentialId: config.dnsCredentialId,
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
  }),
  onSuccess: async () => {
    message.success('已提交验证');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
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
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const setSiteStatusMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId?: number; pluginCredentialId?: number; remoteSiteId?: string; enabled: boolean }) =>
    setAccelerationSiteStatus(payload),
  onSuccess: async () => {
    message.success('加速站点状态已更新');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const deleteRemoteMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId?: number; pluginCredentialId?: number; remoteSiteId?: string; deleteLocalConfig?: boolean }) =>
    deleteRemoteAcceleration(payload),
  onSuccess: async () => {
    message.success('远端加速站点已删除');
    await refreshCurrentPageData();
  },
  onError: (err: any) => message.error(getErrorMessage(err)),
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
  onError: (err: any) => message.error(getErrorMessage(err)),
});

const createVerifyRecordMutation = useMutation({
  mutationFn: async (payload: { zoneName: string; dnsCredentialId: number; pluginCredentialId?: number; remoteSiteId?: string }) =>
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

function setRemoteImportTarget(rowKey: string, credentialId: number | null) {
  remoteImportTargets.value = {
    ...remoteImportTargets.value,
    [rowKey]: credentialId,
  };
}

function setLocalStatusFilter(value: string | null) {
  localStatusFilter.value = (value || 'all') as LocalStatusFilter;
}

function setLocalDnsCredentialFilter(value: string | number | null) {
  localDnsCredentialFilter.value = value == null ? null : Number(value);
}

function setLocalPluginCredentialFilter(value: string | number | null) {
  localPluginCredentialFilter.value = value == null ? null : Number(value);
}

function setRemoteStatusFilter(value: string | null) {
  remoteStatusFilter.value = (value || 'all') as RemoteStatusFilter;
}

function setRemoteOwnershipFilter(value: string | null) {
  remoteOwnershipFilter.value = (value || 'all') as RemoteOwnershipFilter;
}

function setRemotePluginCredentialFilter(value: string | number | null) {
  remotePluginCredentialFilter.value = value == null ? null : Number(value);
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
      enabled,
    }),
  });
}

async function batchImportFilteredRemote() {
  await runBatch({
    items: filteredRemoteRows.value.filter((row) => !row.localConfig && row.selectedDnsCredentialId),
    emptyMessage: '当前筛选结果中没有可接管的远端站点',
    actionLabel: '批量接管站点',
    describe: (row) => row.zoneName,
    execute: (row) => importRemoteAcceleration({
      zoneName: row.zoneName,
      dnsCredentialId: Number(row.selectedDnsCredentialId),
      pluginCredentialId: row.item.pluginCredentialId,
      remoteSiteId: row.item.site.remoteSiteId,
      autoDnsRecord: true,
    }),
  });
}

async function batchCreateVerifyRecordsForRemote() {
  await runBatch({
    items: filteredRemoteRows.value.filter((row) =>
      !row.item.site.verified
      && row.item.site.verifyRecordName
      && Boolean(row.localConfig?.dnsCredentialId || row.selectedDnsCredentialId),
    ),
    emptyMessage: '当前筛选结果中没有需要补验证记录的远端站点',
    actionLabel: '远端批量补验证记录',
    describe: (row) => row.zoneName,
    execute: (row) => createAccelerationVerifyRecord({
      zoneName: row.zoneName,
      dnsCredentialId: Number(row.localConfig?.dnsCredentialId || row.selectedDnsCredentialId),
      pluginCredentialId: row.item.pluginCredentialId,
      remoteSiteId: row.item.site.remoteSiteId,
    }),
  });
}

async function batchSetFilteredRemoteStatus(enabled: boolean) {
  await runBatch({
    items: filteredRemoteRows.value.filter((row) => enabled ? row.item.site.paused : !row.item.site.paused),
    emptyMessage: enabled ? '当前筛选结果中没有可恢复的远端站点' : '当前筛选结果中没有可暂停的远端站点',
    actionLabel: enabled ? '远端批量恢复站点' : '远端批量暂停站点',
    describe: (row) => row.zoneName,
    execute: (row) => setAccelerationSiteStatus({
      zoneName: row.zoneName,
      dnsCredentialId: row.localConfig?.dnsCredentialId,
      pluginCredentialId: row.item.pluginCredentialId,
      remoteSiteId: row.item.site.remoteSiteId,
      enabled,
    }),
  });
}

async function batchDeleteFilteredRemote() {
  const targets = filteredRemoteRows.value;
  if (!targets.length) {
    message.warning('当前筛选结果中没有可删除的远端站点');
    return;
  }
  if (!window.confirm(`确认删除当前筛选结果中的 ${targets.length} 个远端加速站点吗？`)) {
    return;
  }
  await runBatch({
    items: targets,
    emptyMessage: '当前筛选结果中没有可删除的远端站点',
    actionLabel: '远端批量删除',
    describe: (row) => row.zoneName,
    execute: (row) => deleteRemoteAcceleration({
      zoneName: row.zoneName,
      dnsCredentialId: row.localConfig?.dnsCredentialId,
      pluginCredentialId: row.item.pluginCredentialId,
      remoteSiteId: row.item.site.remoteSiteId,
      deleteLocalConfig: true,
    }),
  });
}

const localManagedCount = computed(() => localRows.value.length);
const localVerifiedCount = computed(() => localRows.value.filter((item) => item.verified).length);
const localErrorCount = computed(() => localRows.value.filter((item) => item.hasError).length);
const remoteOnlyCount = computed(() => remoteRows.value.filter((item) => !item.localConfig).length);
const pageLoading = computed(() => loadingConfigs.value || loadingRemote.value || loadingDnsContext.value);

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
          <p class="page-subtitle">集中查看 EdgeOne 已接管列表、远端已有站点、验证接入状态、异常信息以及批量运维动作</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <NButton size="small" secondary @click="refreshCurrentPageData">
            <template #icon><RefreshCw :size="14" /></template>
            刷新列表
          </NButton>
          <NButton size="small" secondary :loading="importRemoteMutation.isPending.value || isBatchRunning" @click="syncExistingRemoteSites">
            <template #icon><Globe :size="14" /></template>
            同步远端已有
          </NButton>
          <NButton size="small" secondary :loading="syncAllMutation.isPending.value || isBatchRunning" @click="syncAllMutation.mutate()">
            <template #icon><ShieldCheck :size="14" /></template>
            同步全部
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
          <p class="mt-2 text-xs text-slate-500">已纳入本地管理的加速站点</p>
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
          <p class="text-xs uppercase tracking-widest text-slate-500">待接管</p>
          <p class="mt-3 text-4xl text-amber-600">{{ remoteOnlyCount }}</p>
          <p class="mt-2 text-xs text-slate-500">仅存在于 EdgeOne 远端、尚未接管的站点</p>
        </article>
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
            <p class="bento-section-title">本地加速配置</p>
            <p class="bento-section-meta">已接管并持久化到面板中的 EdgeOne 站点，支持批量同步、验证、补验证记录和停启用</p>
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
      <NEmpty v-else-if="localRows.length === 0" description="暂无本地加速配置" class="py-12" />
      <NEmpty v-else-if="filteredLocalRows.length === 0" description="没有匹配当前筛选条件的本地加速配置" class="py-12" />
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
                  @click="createVerifyRecordMutation.mutate({ zoneName: config.zoneName, dnsCredentialId: config.dnsCredentialId, pluginCredentialId: config.pluginCredentialId, remoteSiteId: config.remoteSiteId })"
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
      <div class="flex flex-col gap-4">
        <div class="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="bento-section-title">远端已有站点</p>
            <p class="bento-section-meta">EdgeOne 中已经存在但可能尚未接管到面板的站点，支持批量接管、补验证记录、停启用和删除</p>
          </div>
          <p class="text-xs text-slate-500">显示 {{ filteredRemoteRows.length }} / {{ remoteRows.length }} 项</p>
        </div>

        <div class="grid gap-3 xl:grid-cols-4">
          <NInput v-model:value="remoteKeyword" clearable placeholder="搜索域名 / Site ID / 账户名 / DNS 账户" />
          <NSelect
            :value="remoteStatusFilter"
            :options="[
              { label: '全部状态', value: 'all' },
              { label: '已生效', value: 'verified' },
              { label: '待验证', value: 'pending' },
              { label: '已暂停', value: 'paused' },
            ]"
            @update:value="setRemoteStatusFilter"
          />
          <NSelect
            :value="remoteOwnershipFilter"
            :options="[
              { label: '全部接管状态', value: 'all' },
              { label: '已接管', value: 'managed' },
              { label: '待接管', value: 'unmanaged' },
            ]"
            @update:value="setRemoteOwnershipFilter"
          />
          <NSelect
            clearable
            :value="remotePluginCredentialFilter"
            :options="accelerationCredentialOptions"
            placeholder="筛选加速账户"
            @update:value="setRemotePluginCredentialFilter"
          />
        </div>

        <div class="flex flex-wrap gap-2">
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchImportFilteredRemote">批量接管</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchCreateVerifyRecordsForRemote">批量补验证记录</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchSetFilteredRemoteStatus(false)">批量暂停</NButton>
          <NButton size="small" secondary :loading="isBatchRunning" @click="batchSetFilteredRemoteStatus(true)">批量恢复</NButton>
          <NButton size="small" tertiary type="error" :loading="isBatchRunning" @click="batchDeleteFilteredRemote">批量删除远端</NButton>
        </div>
      </div>

      <div v-if="pageLoading" class="flex justify-center py-16">
        <NSpin size="large" />
      </div>
      <NEmpty v-else-if="remoteRows.length === 0" description="暂无远端站点" class="py-12" />
      <NEmpty v-else-if="filteredRemoteRows.length === 0" description="没有匹配当前筛选条件的远端站点" class="py-12" />
      <div v-else class="mt-4 space-y-3">
        <div v-for="row in filteredRemoteRows" :key="row.key" class="panel-muted p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-slate-700">{{ getPrimaryAccelerationDomain(row.item.site) }}</p>
              <p class="mt-1 text-xs text-slate-500">
                根域名 {{ row.zoneName }} · {{ row.item.pluginCredentialName }} · Site {{ row.item.site.remoteSiteId || '-' }}
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <NTag size="small" :bordered="false" :type="getEffectiveType(row.item.site)">
                {{ getEffectiveLabel(row.item.site) }}
              </NTag>
              <NTag size="small" :bordered="false" :type="row.item.site.verified ? 'success' : (row.item.site.paused ? 'warning' : 'default')">
                {{ row.item.site.paused ? '已暂停' : (row.item.site.verified ? '已验证' : '待验证') }}
              </NTag>
              <NTag v-if="row.localConfig" size="small" :bordered="false" type="success">已接管</NTag>
              <NTag v-else size="small" :bordered="false" type="warning">待接管</NTag>
              <NTag size="small" :bordered="false">{{ row.item.site.domainStatus || row.item.site.siteStatus || 'unknown' }}</NTag>
            </div>
          </div>

          <div class="mt-3 grid gap-3 md:grid-cols-4">
            <div>
              <p class="text-xs text-slate-500">本地状态</p>
              <p class="mt-1 text-sm text-slate-700">{{ row.localConfig ? row.localConfig.dnsCredentialName : '未接管' }}</p>
              <p class="mt-1 text-xs text-slate-500">CNAME / 验证：{{ row.item.site.cnameStatus || row.item.site.identificationStatus || row.item.site.verifyStatus || '-' }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">候选 DNS 账户</p>
              <p class="mt-1 text-sm text-slate-700">{{ row.dnsCredentialName }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">回源配置</p>
              <p class="mt-1 break-all text-sm text-slate-700">{{ row.item.site.originValue || '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">{{ row.item.site.originProtocol || 'FOLLOW' }} · HTTP {{ row.item.site.httpOriginPort || 80 }} / HTTPS {{ row.item.site.httpsOriginPort || 443 }}</p>
            </div>
            <div>
              <p class="text-xs text-slate-500">CNAME / 套餐</p>
              <p class="mt-1 break-all text-sm text-slate-700">{{ row.item.site.cnameTarget || '-' }}</p>
              <p class="mt-1 text-xs text-slate-500">{{ row.item.site.area || 'global' }} / {{ row.item.site.planId || '默认' }} · IPv6 {{ row.item.site.ipv6Status || 'follow' }}</p>
            </div>
          </div>

          <div v-if="row.localConfig?.lastError" class="mt-3 rounded-xl border border-rose-200 bg-rose-50/90 p-3">
            <p class="text-sm font-semibold text-rose-700">本地最近错误</p>
            <p class="mt-1 break-all text-xs text-rose-700">{{ row.localConfig.lastError }}</p>
          </div>

          <div v-if="!row.item.site.verified && row.item.site.verifyRecordName" class="mt-3 rounded-xl border border-amber-200 bg-amber-50/80 p-3">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-amber-800">当前未生效</p>
                <p class="mt-1 text-xs text-amber-700">需要补全验证记录后再验证。你可以自动写入，也可以复制记录手动添加。</p>
              </div>
              <div class="flex flex-wrap gap-2">
                <NButton
                  size="small"
                  secondary
                  :disabled="!(row.localConfig?.dnsCredentialId || row.selectedDnsCredentialId)"
                  :loading="createVerifyRecordMutation.isPending.value"
                  @click="createVerifyRecordMutation.mutate({ zoneName: row.zoneName, dnsCredentialId: Number(row.localConfig?.dnsCredentialId || row.selectedDnsCredentialId), pluginCredentialId: row.item.pluginCredentialId, remoteSiteId: row.item.site.remoteSiteId })"
                >
                  自动添加记录
                </NButton>
                <NButton
                  v-if="row.localConfig"
                  size="small"
                  secondary
                  :loading="verifyConfigMutation.isPending.value"
                  @click="verifyConfigMutation.mutate(row.localConfig)"
                >
                  手动验证
                </NButton>
              </div>
            </div>

            <div class="mt-3 grid gap-3 md:grid-cols-3">
              <button class="rounded-lg bg-white/80 p-3 text-left" @click="copyText(row.item.site.verifyRecordType || 'TXT')">
                <p class="text-xs text-slate-500">记录类型</p>
                <p class="mt-1 text-sm font-medium text-slate-700">{{ row.item.site.verifyRecordType || 'TXT' }}</p>
              </button>
              <button class="rounded-lg bg-white/80 p-3 text-left" @click="copyText(row.item.site.verifyRecordName)">
                <p class="text-xs text-slate-500">主机记录</p>
                <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ row.item.site.verifyRecordName }}</p>
              </button>
              <button class="rounded-lg bg-white/80 p-3 text-left" @click="copyText(row.item.site.verifyRecordValue)">
                <p class="text-xs text-slate-500">记录值</p>
                <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ row.item.site.verifyRecordValue || '-' }}</p>
              </button>
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
