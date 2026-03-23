<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NAlert, NButton, NSpin, NTag, useMessage } from 'naive-ui';
import { Plus, RefreshCw, Globe } from 'lucide-vue-next';
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
  createAccelerationVerifyRecord,
  updateAccelerationConfig,
  type AccelerationConfigInput,
  type DomainAccelerationConfig,
  type DiscoveredAccelerationSite,
} from '@/services/accelerations';
import type { RecordsResponseCapabilities } from '@/services/dns';
import { useProviderStore } from '@/stores/provider';
import { useBreadcrumbStore } from '@/stores/breadcrumb';
import { useCredentialResolver } from '@/composables/useCredentialResolver';
import type { DNSRecord, Domain } from '@/types';
import type { DnsCredential, DnsLine } from '@/types/dns';
import { normalizeProviderType } from '@/utils/provider';
import DNSRecordTable from '@/components/DNSRecordTable/DNSRecordTable.vue';
import QuickAddForm from '@/components/QuickAddForm/QuickAddForm.vue';
import AddAccelerationCredentialDialog from '@/components/Dashboard/AddAccelerationCredentialDialog.vue';
import AccelerationSiteDialog from '@/components/Acceleration/AccelerationSiteDialog.vue';
import AccelerationResultDialog from '@/components/Acceleration/AccelerationResultDialog.vue';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const queryClient = useQueryClient();
const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const { credentialId } = useCredentialResolver();

const zoneId = computed(() => route.params.zoneId as string);
const showAddDialog = ref(false);
const showAddAccelerationCredential = ref(false);
const showAccelerationSiteDialog = ref(false);
const showAccelerationResultDialog = ref(false);
const accelerationDialogMode = ref<'create' | 'edit'>('create');
const accelerationDialogLockDomain = ref(true);
const accelerationDialogLockPluginCredential = ref(false);
const accelerationDialogValue = ref<(Partial<DomainAccelerationConfig> & {
  zoneName?: string;
  dnsCredentialId?: number | null;
  pluginCredentialId?: number | null;
}) | null>(null);
const accelerationResultState = ref<{
  title?: string;
  dnsCredentialId?: number | null;
  pluginCredentialId?: number | null;
  remoteSiteId?: string;
  accelerationDomain?: string;
  config?: DomainAccelerationConfig | null;
  site?: DiscoveredAccelerationSite['site'] | null;
  dnsRecordsAdded?: Array<{ zoneName: string; type: string; name: string; value: string }>;
  dnsRecordsSkipped?: Array<{ zoneName: string; type: string; name: string; value: string }>;
  dnsErrors?: Array<{ error: string; name?: string }>;
} | null>(null);
const pendingAccelerationRecordAction = ref<null | {
  kind: 'create' | 'update';
  recordId?: string;
  params: any;
}>(null);
const selectedAccelerationCredentialId = ref<number | null>(null);

type AccelerationSiteDialogPayload = AccelerationConfigInput & {
  zoneName: string;
  dnsCredentialId: number;
  pluginCredentialId: number;
  autoDnsRecord?: boolean;
};

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
const currentAccelerationDomains = computed<Domain[]>(() => {
  if (!zoneName.value || typeof credentialId.value !== 'number') return [];
  return [{
    id: String(domainData.value?.id || zoneId.value),
    name: zoneName.value,
    status: String(domainData.value?.status || ''),
    credentialId: credentialId.value,
    credentialName: providerStore.credentials.find((item) => item.id === credentialId.value)?.name,
    provider: providerStore.credentials.find((item) => item.id === credentialId.value)?.provider,
  }];
});

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

function normalizeAccelerationState(value: unknown) {
  return String(value || '').trim().toLowerCase();
}

function isAccelerationEffective(site: Partial<DomainAccelerationConfig | DiscoveredAccelerationSite['site']> | null | undefined) {
  if (!site) return false;
  const domainStatus = normalizeAccelerationState(site.domainStatus);
  const cnameStatus = normalizeAccelerationState(site.cnameStatus || site.identificationStatus || site.verifyStatus);
  return Boolean(site.verified)
    || ['online', 'active', 'enabled'].includes(domainStatus)
    || ['finished', 'active', 'verified', 'success', 'completed'].includes(cnameStatus);
}

function getAccelerationStatusMeta(
  site: Partial<DomainAccelerationConfig | DiscoveredAccelerationSite['site']> | null | undefined,
  options?: { remote?: boolean; lastError?: string },
) {
  if (!site) return { type: 'default' as const, label: '未接入', detail: '尚未接入加速' };
  const detail = String(
    site.cnameStatus
      || site.identificationStatus
      || site.verifyStatus
      || site.domainStatus
      || site.siteStatus
      || '',
  ).trim();
  if (site.paused) {
    return {
      type: 'warning' as const,
      label: '已暂停',
      detail: detail || '加速站点当前已暂停',
    };
  }
  if (String(options?.lastError || '').trim()) {
    return {
      type: 'error' as const,
      label: '异常',
      detail: String(options?.lastError || '').trim(),
    };
  }
  if (isAccelerationEffective(site)) {
    return {
      type: 'success' as const,
      label: '已生效',
      detail: detail || '加速已生效',
    };
  }
  return {
    type: 'warning' as const,
    label: options?.remote ? '待完成' : '待验证',
    detail: detail || '等待配置或验证完成',
  };
}

function getAccelerationComparableDomain(
  site: Partial<DomainAccelerationConfig | DiscoveredAccelerationSite['site']> | null | undefined,
) {
  return normalizeAccelerationState(site?.accelerationDomain || site?.zoneName);
}

const accelerationStatusDisplay = computed(() =>
  getAccelerationStatusMeta(accelerationConfig.value, { lastError: accelerationConfig.value?.lastError }),
);

const selectedDiscoveredSite = computed<DiscoveredAccelerationSite | null>(() => {
  const currentConfig = accelerationConfig.value;
  const currentCredentialId = selectedAccelerationCredentialId.value;
  const expectedDomain = currentConfig
    ? getAccelerationComparableDomain(currentConfig)
    : normalizeAccelerationState(zoneName.value);

  if (currentConfig?.remoteSiteId) {
    const matchedByRemoteId = discoveredAccelerationSites.value.find((item) =>
      String(item.site.remoteSiteId || '') === String(currentConfig.remoteSiteId || ''),
    );
    if (matchedByRemoteId) return matchedByRemoteId;
  }

  if (currentCredentialId) {
    const matchedByCredentialAndDomain = discoveredAccelerationSites.value.find((item) =>
      item.pluginCredentialId === currentCredentialId
      && getAccelerationComparableDomain(item.site) === expectedDomain,
    );
    if (matchedByCredentialAndDomain) return matchedByCredentialAndDomain;

    const matchedByCredential = discoveredAccelerationSites.value.find((item) => item.pluginCredentialId === currentCredentialId);
    if (matchedByCredential) return matchedByCredential;
  }

  const matchedByDomain = discoveredAccelerationSites.value.find((item) =>
    getAccelerationComparableDomain(item.site) === expectedDomain,
  );
  if (matchedByDomain) return matchedByDomain;

  return discoveredAccelerationSites.value[0] || null;
});


const effectiveAccelerationView = computed(() => {
  if (selectedDiscoveredSite.value) {
    return {
      source: 'remote' as const,
      site: selectedDiscoveredSite.value.site,
      credentialName: selectedDiscoveredSite.value.pluginCredentialName,
    };
  }
  if (accelerationConfig.value) {
    return {
      source: 'cache' as const,
      site: accelerationConfig.value,
      credentialName: accelerationCredentials.value.find((item) => item.id === accelerationConfig.value?.pluginCredentialId)?.name || '',
    };
  }
  return null;
});

const accelerationDomainLabel = computed(() =>
  effectiveAccelerationView.value?.site.accelerationDomain
  || effectiveAccelerationView.value?.site.zoneName
  || zoneName.value
  || '-',
);

const accelerationOriginSummary = computed(() => {
  const site = effectiveAccelerationView.value?.site;
  if (!site) return '-';
  const protocol = site.originProtocol || 'FOLLOW';
  const httpPort = site.httpOriginPort || 80;
  const httpsPort = site.httpsOriginPort || 443;
  return `${protocol} · HTTP ${httpPort} / HTTPS ${httpsPort}`;
});

const accelerationSourceDetail = computed(() => {
  const current = effectiveAccelerationView.value;
  if (!current) return '-';
  if (current.credentialName) return current.credentialName;
  return accelerationConfig.value?.lastSyncedAt
    ? new Date(accelerationConfig.value.lastSyncedAt).toLocaleString('zh-CN')
    : '等待首次同步';
});

const accelerationCnameHint = computed(() => {
  const site = effectiveAccelerationView.value?.site;
  if (!site) return '当前还没有可用的接入信息';
  if (!site.cnameTarget) return '等待 EdgeOne 下发 CNAME 记录值';
  return isAccelerationEffective(site)
    ? '当前 CNAME 已可用于解析接入，可继续观察实际生效情况'
    : '请前往 DNS 服务商添加以下 CNAME 记录，等待解析生效';
});

const saveAccelerationMutation = useMutation({
  mutationFn: async (payload: AccelerationSiteDialogPayload) => {
    if (accelerationDialogMode.value === 'edit') {
      return updateAccelerationConfig(payload);
    }
    return enableAcceleration({
      ...payload,
      zoneId: zoneId.value,
      autoDnsRecord: payload.autoDnsRecord !== false,
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
    pendingAccelerationRecordAction.value = null;
    accelerationResultState.value = {
      title: accelerationDialogMode.value === 'edit' ? '加速配置已更新' : '加速域名已创建',
      dnsCredentialId: typeof credentialId.value === 'number' ? credentialId.value : null,
      pluginCredentialId: selectedAccelerationCredentialId.value,
      remoteSiteId: String(res.data?.config?.remoteSiteId || res.data?.site?.remoteSiteId || ''),
      accelerationDomain: String(res.data?.config?.accelerationDomain || res.data?.site?.accelerationDomain || ''),
      config: res.data?.config || null,
      site: (res.data?.site as DiscoveredAccelerationSite['site'] | null) || null,
      dnsRecordsAdded: res.data?.dnsRecordsAdded || [],
      dnsRecordsSkipped: res.data?.dnsRecordsSkipped || [],
      dnsErrors: res.data?.dnsErrors || [],
    };
    showAccelerationResultDialog.value = true;
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
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
    accelerationResultState.value = {
      ...(accelerationResultState.value || {}),
      config: res.data?.config || accelerationResultState.value?.config || null,
      site: (res.data?.site as DiscoveredAccelerationSite['site'] | null) || accelerationResultState.value?.site || null,
      dnsRecordsAdded: res.data?.dnsRecordsAdded || [],
      dnsRecordsSkipped: res.data?.dnsRecordsSkipped || [],
      dnsErrors: res.data?.dnsErrors || [],
    };
    showAccelerationResultDialog.value = true;
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
  },
  onError: (err: any) => message.error(String(err)),
});

function openCreateAccelerationDialog() {
  if (typeof credentialId.value !== 'number' || !zoneName.value) {
    message.warning('当前域名信息尚未加载完成');
    return;
  }
  accelerationDialogMode.value = 'create';
  accelerationDialogLockDomain.value = true;
  accelerationDialogLockPluginCredential.value = false;
  const remoteSite = selectedDiscoveredSite.value?.site;
  accelerationDialogValue.value = {
    zoneName: zoneName.value,
    dnsCredentialId: credentialId.value,
    pluginCredentialId: selectedAccelerationCredentialId.value || accelerationCredentials.value[0]?.id || null,
    accelerationDomain: remoteSite?.accelerationDomain,
    subDomain: remoteSite?.subDomain || '@',
    originType: remoteSite?.originType || 'IP_DOMAIN',
    originValue: remoteSite?.originValue || '',
    backupOriginValue: remoteSite?.backupOriginValue || '',
    hostHeader: remoteSite?.hostHeader || '',
    originProtocol: remoteSite?.originProtocol || 'FOLLOW',
    httpOriginPort: remoteSite?.httpOriginPort || 80,
    httpsOriginPort: remoteSite?.httpsOriginPort || 443,
    ipv6Status: remoteSite?.ipv6Status || 'follow',
  };
  showAccelerationSiteDialog.value = true;
}

function openEditAccelerationDialog() {
  if (!accelerationConfig.value) {
    openCreateAccelerationDialog();
    return;
  }
  accelerationDialogMode.value = 'edit';
  accelerationDialogLockDomain.value = true;
  accelerationDialogLockPluginCredential.value = true;
  accelerationDialogValue.value = { ...accelerationConfig.value };
  showAccelerationSiteDialog.value = true;
}

function openAccelerationDialog() {
  if (accelerationConfig.value) {
    openEditAccelerationDialog();
    return;
  }
  openCreateAccelerationDialog();
}

const canEnableAccelerationWhenAddingRecord = computed(() =>
  accelerationCredentials.value.length > 0 && typeof credentialId.value === 'number' && !!zoneName.value,
);

const addRecordAccelerationLabel = computed(() => {
  if (effectiveAccelerationView.value) {
    return '保存后填写并更新当前记录的加速配置';
  }
  const selected = accelerationCredentials.value.find((item) => item.id === selectedAccelerationCredentialId.value);
  return selected ? `保存后填写加速配置（${selected.name}）` : '保存后填写加速配置';
});

const recordAccelerationStateResolver = computed(() => {
  const localConfig = accelerationConfig.value;
  const remoteSite = selectedDiscoveredSite.value?.site;
  const remoteMeta = remoteSite ? getAccelerationStatusMeta(remoteSite, { remote: true }) : null;
  const localMeta = localConfig ? getAccelerationStatusMeta(localConfig, { lastError: localConfig.lastError }) : null;

  return (record: DNSRecord) => {
    const recordDomain = buildDomainNameFromRecord(record.name);
    if (!recordDomain) {
      return null;
    }

    const localDomain = normalizeAccelerationState(localConfig?.accelerationDomain || localConfig?.zoneName);
    if (localConfig && recordDomain === localDomain) {
      return {
        matched: true,
        label: localMeta?.label || '已接入',
        type: localMeta?.type || 'success',
        detail: localMeta?.detail || `当前记录 ${recordDomain} 已纳入加速配置`,
      };
    }

    const remoteDomain = normalizeAccelerationState(remoteSite?.accelerationDomain || remoteSite?.zoneName);
    if (!localConfig && remoteSite && recordDomain === remoteDomain) {
      return {
        matched: true,
        label: remoteMeta?.label || '已接入',
        type: remoteMeta?.type || 'warning',
        detail: remoteMeta?.detail || `远端已存在 ${recordDomain} 的加速站点`,
      };
    }

    const rootZone = normalizeAccelerationState(zoneName.value);
    if (localConfig && localDomain === rootZone && recordDomain.endsWith(`.${rootZone}`)) {
      return {
        matched: false,
        label: '站点已接入',
        type: 'warning' as const,
        detail: '当前根域名已接入加速，若要让该子域单独加速，保存后会同步为对应子域配置',
      };
    }

    if (!localConfig && remoteSite && remoteDomain === rootZone && recordDomain.endsWith(`.${rootZone}`)) {
      return {
        matched: false,
        label: '远端根站点',
        type: 'warning' as const,
        detail: '远端已存在根域站点，保存后可继续补全当前子域的加速配置',
      };
    }

    return {
      matched: false,
      label: '未接入',
      type: 'default' as const,
      detail: `保存后可将 ${recordDomain} 接入加速`,
    };
  };
});

function buildDomainNameFromRecord(name: string) {
  const recordName = String(name || '').trim();
  const zone = String(zoneName.value || '').trim().toLowerCase();
  if (!zone) return '';
  if (!recordName || recordName === '@') return zone;
  const normalized = recordName.toLowerCase();
  return normalized.endsWith(`.${zone}`) ? normalized : `${normalized}.${zone}`;
}

function buildAccelerationConfigFromRecord(params: any): AccelerationConfigInput {
  return {
    accelerationDomain: buildDomainNameFromRecord(params?.name),
    subDomain: String(params?.name || '@').trim() || '@',
    originType: 'IP_DOMAIN',
    originValue: String(params?.content || '').trim(),
    originProtocol: 'FOLLOW',
    httpOriginPort: 80,
    httpsOriginPort: 443,
    ipv6Status: 'follow',
  };
}

function openAccelerationDialogForRecordAction(action: { kind: 'create' | 'update'; recordId?: string; params: any }) {
  if (typeof credentialId.value !== 'number' || !zoneName.value) {
    message.warning('当前域名信息尚未加载完成');
    return;
  }
  pendingAccelerationRecordAction.value = action;
  accelerationDialogMode.value = accelerationConfig.value ? 'edit' : 'create';
  accelerationDialogLockDomain.value = true;
  accelerationDialogLockPluginCredential.value = Boolean(accelerationConfig.value?.pluginCredentialId);
  const recordConfig = buildAccelerationConfigFromRecord(action.params);
  accelerationDialogValue.value = {
    ...accelerationConfig.value,
    ...recordConfig,
    zoneName: zoneName.value,
    dnsCredentialId: credentialId.value,
    pluginCredentialId: accelerationConfig.value?.pluginCredentialId || selectedAccelerationCredentialId.value || accelerationCredentials.value[0]?.id || null,
    originType: accelerationConfig.value?.originType || recordConfig.originType || 'IP_DOMAIN',
    originValue: accelerationConfig.value?.originValue || recordConfig.originValue || '',
    backupOriginValue: accelerationConfig.value?.backupOriginValue || '',
    hostHeader: accelerationConfig.value?.hostHeader || '',
    originProtocol: accelerationConfig.value?.originProtocol || recordConfig.originProtocol || 'FOLLOW',
    httpOriginPort: accelerationConfig.value?.httpOriginPort || recordConfig.httpOriginPort || 80,
    httpsOriginPort: accelerationConfig.value?.httpsOriginPort || recordConfig.httpsOriginPort || 443,
    ipv6Status: accelerationConfig.value?.ipv6Status || recordConfig.ipv6Status || 'follow',
  };
  showAccelerationSiteDialog.value = true;
}

// Mutations
const createMutation = useMutation({
  mutationFn: async (params: Parameters<typeof createDNSRecord>[1] & { enableAcceleration?: boolean; accelerationConfig?: AccelerationConfigInput; autoDnsRecord?: boolean }) => {
    const { enableAcceleration: enableAfterCreate, accelerationConfig: accelerationConfigInput, autoDnsRecord, ...recordParams } = params;
    const recordResult = await createDNSRecord(zoneId.value, recordParams, credentialId.value);
    let accelerationResult: Awaited<ReturnType<typeof enableAcceleration | typeof updateAccelerationConfig>> | null = null;
    if (
      enableAfterCreate
      && typeof credentialId.value === 'number'
      && zoneName.value
    ) {
      const payload = {
        zoneName: zoneName.value,
        dnsCredentialId: credentialId.value,
        pluginCredentialId: accelerationConfig.value?.pluginCredentialId || selectedAccelerationCredentialId.value || undefined,
        ...(accelerationConfigInput || buildAccelerationConfigFromRecord(recordParams)),
      };
      if (accelerationConfig.value?.pluginCredentialId) {
        accelerationResult = await updateAccelerationConfig(payload);
      } else if (selectedAccelerationCredentialId.value) {
        accelerationResult = await enableAcceleration({
          ...payload,
          zoneId: zoneId.value,
          pluginCredentialId: selectedAccelerationCredentialId.value,
          autoDnsRecord: autoDnsRecord !== false,
        });
      }
    }
    return { recordResult, accelerationResult };
  },
  onSuccess: async (result) => {
    let text = '记录已添加';
    if (result.accelerationResult) {
      const added = result.accelerationResult.data?.dnsRecordsAdded?.length || 0;
      const skipped = result.accelerationResult.data?.dnsRecordsSkipped?.length || 0;
      const failed = result.accelerationResult.data?.dnsErrors?.length || 0;
      text += '，并已提交加速接入';
      if (added) text += `（新增 ${added} 条验证记录）`;
      if (skipped) text += `（${skipped} 条验证记录已存在）`;
      if (failed) text += `（${failed} 条验证记录写入失败）`;
    }
    message.success(text);
    showAddDialog.value = false;
    pendingAccelerationRecordAction.value = null;
    showAccelerationSiteDialog.value = false;
    accelerationDialogValue.value = null;
    if (result.accelerationResult) {
      accelerationResultState.value = {
        title: 'DNS 记录和加速配置已提交',
        dnsCredentialId: typeof credentialId.value === 'number' ? credentialId.value : null,
        pluginCredentialId: selectedAccelerationCredentialId.value,
        remoteSiteId: String(result.accelerationResult.data?.config?.remoteSiteId || result.accelerationResult.data?.site?.remoteSiteId || ''),
        accelerationDomain: String(result.accelerationResult.data?.config?.accelerationDomain || result.accelerationResult.data?.site?.accelerationDomain || ''),
        config: result.accelerationResult.data?.config || null,
        site: (result.accelerationResult.data?.site as DiscoveredAccelerationSite['site'] | null) || null,
        dnsRecordsAdded: result.accelerationResult.data?.dnsRecordsAdded || [],
        dnsRecordsSkipped: result.accelerationResult.data?.dnsRecordsSkipped || [],
        dnsErrors: result.accelerationResult.data?.dnsErrors || [],
      };
      showAccelerationResultDialog.value = true;
    }
    await refetchRecords();
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const updateMutation = useMutation({
  mutationFn: async (vars: { recordId: string; params: Parameters<typeof updateDNSRecord>[2] & { enableAcceleration?: boolean; accelerationConfig?: AccelerationConfigInput; autoDnsRecord?: boolean } }) => {
    const { enableAcceleration: enableAfterUpdate, accelerationConfig: accelerationConfigInput, autoDnsRecord, ...recordParams } = vars.params;
    const recordResult = await updateDNSRecord(zoneId.value, vars.recordId, recordParams, credentialId.value);
    let accelerationResult: Awaited<ReturnType<typeof enableAcceleration | typeof updateAccelerationConfig>> | null = null;
    if (
      enableAfterUpdate
      && typeof credentialId.value === 'number'
      && zoneName.value
    ) {
      const payload = {
        zoneName: zoneName.value,
        dnsCredentialId: credentialId.value,
        pluginCredentialId: accelerationConfig.value?.pluginCredentialId || selectedAccelerationCredentialId.value || undefined,
        ...(accelerationConfigInput || buildAccelerationConfigFromRecord(recordParams)),
      };
      if (accelerationConfig.value?.pluginCredentialId) {
        accelerationResult = await updateAccelerationConfig(payload);
      } else if (selectedAccelerationCredentialId.value) {
        accelerationResult = await enableAcceleration({
          ...payload,
          zoneId: zoneId.value,
          pluginCredentialId: selectedAccelerationCredentialId.value,
          autoDnsRecord: autoDnsRecord !== false,
        });
      }
    }
    return { recordResult, accelerationResult };
  },
  onSuccess: async (result) => {
    let text = '记录已更新';
    if (result.accelerationResult) {
      const added = result.accelerationResult.data?.dnsRecordsAdded?.length || 0;
      const skipped = result.accelerationResult.data?.dnsRecordsSkipped?.length || 0;
      const failed = result.accelerationResult.data?.dnsErrors?.length || 0;
      text += '，并已提交加速接入';
      if (added) text += `（新增 ${added} 条验证记录）`;
      if (skipped) text += `（${skipped} 条验证记录已存在）`;
      if (failed) text += `（${failed} 条验证记录写入失败）`;
    }
    message.success(text);
    pendingAccelerationRecordAction.value = null;
    showAccelerationSiteDialog.value = false;
    accelerationDialogValue.value = null;
    if (result.accelerationResult) {
      accelerationResultState.value = {
        title: 'DNS 记录和加速配置已更新',
        dnsCredentialId: typeof credentialId.value === 'number' ? credentialId.value : null,
        pluginCredentialId: selectedAccelerationCredentialId.value,
        remoteSiteId: String(result.accelerationResult.data?.config?.remoteSiteId || result.accelerationResult.data?.site?.remoteSiteId || ''),
        accelerationDomain: String(result.accelerationResult.data?.config?.accelerationDomain || result.accelerationResult.data?.site?.accelerationDomain || ''),
        config: result.accelerationResult.data?.config || null,
        site: (result.accelerationResult.data?.site as DiscoveredAccelerationSite['site'] | null) || null,
        dnsRecordsAdded: result.accelerationResult.data?.dnsRecordsAdded || [],
        dnsRecordsSkipped: result.accelerationResult.data?.dnsRecordsSkipped || [],
        dnsErrors: result.accelerationResult.data?.dnsErrors || [],
      };
      showAccelerationResultDialog.value = true;
    }
    await refetchRecords();
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  },
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
  if (params?.enableAcceleration) {
    openAccelerationDialogForRecordAction({ kind: 'create', params });
    return;
  }
  createMutation.mutate(params);
}

function handleUpdate(recordId: string, params: any) {
  if (params?.enableAcceleration) {
    openAccelerationDialogForRecordAction({ kind: 'update', recordId, params });
    return;
  }
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

function handleAccelerationDialogSubmit(payload: AccelerationSiteDialogPayload) {
  const pendingAction = pendingAccelerationRecordAction.value;
  if (!pendingAction) {
    saveAccelerationMutation.mutate(payload);
    return;
  }
  if (pendingAction.kind === 'create') {
    createMutation.mutate({
      ...pendingAction.params,
      enableAcceleration: true,
      accelerationConfig: payload,
      autoDnsRecord: payload.autoDnsRecord,
    });
    return;
  }
  updateMutation.mutate({
    recordId: String(pendingAction.recordId || ''),
    params: {
      ...pendingAction.params,
      enableAcceleration: true,
      accelerationConfig: payload,
      autoDnsRecord: payload.autoDnsRecord,
    },
  });
}

function handleAccelerationDialogVisibleChange(value: boolean) {
  showAccelerationSiteDialog.value = value;
  if (!value) {
    pendingAccelerationRecordAction.value = null;
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
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p class="bento-section-title">加速管理</p>
          <p class="bento-section-meta">可以直接在这里填写源站类型、源站地址、IPv6、端口和 Host Header，完成当前域名的加速配置。</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <NButton
            size="small"
            type="primary"
            :disabled="!accelerationCredentials.length || !currentAccelerationDomains.length"
            @click="openAccelerationDialog"
          >
            {{ accelerationConfig ? '编辑加速域名' : '添加加速域名' }}
          </NButton>
          <NButton
            size="small"
            secondary
            @click="router.push({ path: '/accelerations', query: credentialId ? { zoneName, dnsCredentialId: String(credentialId) } : { zoneName } })"
          >
            打开加速列表
          </NButton>
          <NButton size="small" secondary @click="showAddAccelerationCredential = true">
            添加加速账户
          </NButton>
        </div>
      </div>

      <div v-if="accelerationLoading || discoveringAcceleration" class="flex justify-center py-10">
        <NSpin size="large" />
      </div>

      <div v-else class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article class="rounded-[24px] border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">当前状态</p>
          <div class="mt-3 flex items-center gap-2">
            <NTag size="small" :bordered="false" :type="accelerationStatusDisplay.type">
              {{ accelerationStatusDisplay.label }}
            </NTag>
            <NTag v-if="effectiveAccelerationView?.site?.remoteSiteId" size="small" :bordered="false">
              Site {{ effectiveAccelerationView.site.remoteSiteId }}
            </NTag>
          </div>
          <p class="mt-3 break-all text-sm font-semibold text-slate-900">{{ accelerationDomainLabel }}</p>
          <p class="mt-2 text-xs leading-6 text-slate-500">{{ accelerationStatusDisplay.detail || '当前还没有加速接入状态' }}</p>
        </article>

        <article class="rounded-[24px] border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">加速账户</p>
          <p class="mt-3 text-sm font-semibold text-slate-900">{{ accelerationSourceDetail }}</p>
          <p class="mt-2 text-xs text-slate-500">可直接在当前页面编辑，也可以进入加速列表集中管理。</p>
        </article>

        <article class="rounded-[24px] border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">回源摘要</p>
          <p class="mt-3 break-all text-sm font-semibold text-slate-900">{{ effectiveAccelerationView?.site.originValue || '-' }}</p>
          <p class="mt-2 text-xs text-slate-500">{{ accelerationOriginSummary }}</p>
        </article>

        <article class="rounded-[24px] border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">验证 / CNAME</p>
          <p class="mt-3 break-all text-sm font-semibold text-slate-900">{{ effectiveAccelerationView?.site.cnameTarget || '等待下发' }}</p>
          <p class="mt-2 text-xs text-slate-500">{{ accelerationCnameHint }}</p>
        </article>
      </div>

      <NAlert v-if="accelerationConfig?.lastError" class="mt-4" type="warning" :bordered="false">
        {{ accelerationConfig.lastError }}
      </NAlert>
      <NAlert v-else-if="!accelerationCredentials.length" class="mt-4" type="info" :bordered="false">
        还没有可用的加速账户，请先添加 EdgeOne 账户后再创建加速域名。
      </NAlert>
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
        :show-acceleration-toggle="canEnableAccelerationWhenAddingRecord"
        :acceleration-toggle-label="addRecordAccelerationLabel"
        :resolve-acceleration-state="recordAccelerationStateResolver"
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
      :show-acceleration-toggle="canEnableAccelerationWhenAddingRecord"
      :acceleration-toggle-label="addRecordAccelerationLabel"
      @submit="handleAddSubmit"
    />
    <AccelerationSiteDialog
      :show="showAccelerationSiteDialog"
      :loading="saveAccelerationMutation.isPending.value || createMutation.isPending.value || updateMutation.isPending.value"
      :mode="accelerationDialogMode"
      :domains="currentAccelerationDomains"
      :acceleration-credentials="accelerationCredentials"
      :value="accelerationDialogValue"
      :lock-domain="accelerationDialogLockDomain"
      :lock-plugin-credential="accelerationDialogLockPluginCredential"
      @update:show="handleAccelerationDialogVisibleChange"
      @submit="handleAccelerationDialogSubmit"
    />
    <AccelerationResultDialog
      :show="showAccelerationResultDialog"
      :loading="createVerifyRecordMutation.isPending.value"
      :result="accelerationResultState"
      @update:show="showAccelerationResultDialog = $event"
      @create-verify-record="createVerifyRecordMutation.mutate"
    />
    <AddAccelerationCredentialDialog
      v-model:show="showAddAccelerationCredential"
      @created="() => { refetchAccelerationCredentials(); refetchDiscoveredAcceleration(); }"
    />
  </div>
</template>
