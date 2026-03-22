<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NAlert, NButton, NSelect, NSpin, NTag, useDialog, useMessage } from 'naive-ui';
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
  updateAccelerationConfig,
  verifyAcceleration,
  syncAcceleration,
  checkAccelerationCname,
  disableAcceleration,
  setAccelerationSiteStatus,
  deleteRemoteAcceleration,
  type AccelerationConfigInput,
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
import AccelerationConfigDialog from '@/components/Acceleration/AccelerationConfigDialog.vue';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const dialog = useDialog();
const queryClient = useQueryClient();
const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const { credentialId } = useCredentialResolver();
const { isMobile } = useResponsive();

const zoneId = computed(() => route.params.zoneId as string);
const showAddDialog = ref(false);
const showAddAccelerationCredential = ref(false);
const showAccelerationConfig = ref(false);
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

function getAccelerationToneClass(type: 'success' | 'warning' | 'error' | 'default') {
  if (type === 'success') return 'bg-emerald-100 text-emerald-700';
  if (type === 'error') return 'bg-rose-100 text-rose-700';
  if (type === 'warning') return 'bg-amber-100 text-amber-700';
  return 'bg-slate-100 text-slate-600';
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

const accelerationStatusToneClass = computed(() => getAccelerationToneClass(accelerationStatusDisplay.value.type));

const accelerationRemoteMeta = computed(() =>
  effectiveAccelerationView.value
    ? getAccelerationStatusMeta(effectiveAccelerationView.value.site, {
      remote: effectiveAccelerationView.value.source === 'remote',
      lastError: effectiveAccelerationView.value.source === 'cache' ? accelerationConfig.value?.lastError : undefined,
    })
    : null,
);

const accelerationRemoteToneClass = computed(() =>
  getAccelerationToneClass(accelerationRemoteMeta.value?.type || 'default'),
);

const accelerationSiteSummary = computed(() => {
  const site = effectiveAccelerationView.value?.site;
  if (!site) return '-';
  return site.siteStatus || site.domainStatus || site.verifyStatus || '-';
});

const accelerationFeatureSummary = computed(() => {
  const site = effectiveAccelerationView.value?.site;
  if (!site) return '等待远端状态';
  return `IPv6 ${site.ipv6Status || 'follow'} · ${site.accessType || 'partial'} 接入`;
});

const accelerationManageActionLabel = computed(() => {
  if (accelerationConfig.value) return '编辑远端配置';
  if (selectedDiscoveredSite.value) return '同步远端站点';
  return '手动配置接入';
});

const accelerationManageActionPending = computed(() =>
  !accelerationConfig.value && !!selectedDiscoveredSite.value && enableAccelerationMutation.isPending.value,
);

const accelerationRefreshPending = computed(() =>
  accelerationConfig.value ? syncAccelerationMutation.isPending.value : discoveringAcceleration,
);

const accelerationDomainLabel = computed(() =>
  effectiveAccelerationView.value?.site.accelerationDomain
  || effectiveAccelerationView.value?.site.zoneName
  || zoneName.value
  || '-',
);

const accelerationHostRecordLabel = computed(() => {
  const subDomain = String(effectiveAccelerationView.value?.site.subDomain || '').trim();
  if (!subDomain || subDomain === '@') return '@';
  return subDomain;
});

const accelerationOriginSummary = computed(() => {
  const site = effectiveAccelerationView.value?.site;
  if (!site) return '-';
  const protocol = site.originProtocol || 'FOLLOW';
  const httpPort = site.httpOriginPort || 80;
  const httpsPort = site.httpsOriginPort || 443;
  return `${protocol} · HTTP ${httpPort} / HTTPS ${httpsPort}`;
});

const accelerationSourceTitle = computed(() => '加速账户');

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

const accelerationVerifyHint = computed(() => {
  const site = effectiveAccelerationView.value?.site;
  if (!site?.verifyRecordName) return '';
  return site.verified
    ? '域名归属验证已通过，保留该记录可避免后续再次校验'
    : '若未自动写入成功，可手动补录以下验证记录后重新触发验证';
});

const currentAccelerationTarget = computed(() => ({
  zoneName: zoneName.value,
  dnsCredentialId: accelerationConfig.value?.dnsCredentialId || (typeof credentialId.value === 'number' ? credentialId.value : undefined),
  pluginCredentialId: selectedDiscoveredSite.value?.pluginCredentialId || accelerationConfig.value?.pluginCredentialId || selectedAccelerationCredentialId.value || undefined,
  remoteSiteId: effectiveAccelerationView.value?.site.remoteSiteId || accelerationConfig.value?.remoteSiteId || undefined,
  accelerationDomain: effectiveAccelerationView.value?.site.accelerationDomain || accelerationConfig.value?.accelerationDomain || undefined,
  subDomain: effectiveAccelerationView.value?.site.subDomain || accelerationConfig.value?.subDomain || undefined,
}));

const canEnableAccelerationWhenAddingRecord = computed(() =>
  accelerationCredentials.value.length > 0 && typeof credentialId.value === 'number' && !!zoneName.value,
);

const addRecordAccelerationLabel = computed(() => {
  if (effectiveAccelerationView.value) {
    return '保存后同步当前记录到远端加速站点';
  }
  const selected = accelerationCredentials.value.find((item) => item.id === selectedAccelerationCredentialId.value);
  return selected ? `创建后自动接入加速（${selected.name}）` : '创建后自动接入加速';
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

function openAccelerationConfig() {
  showAccelerationConfig.value = true;
}

function confirmTakeOverAccelerationSite() {
  const site = selectedDiscoveredSite.value;
  if (!site) return;
  const targetDomain = site.site.accelerationDomain || site.site.zoneName || zoneName.value;
  dialog.info({
    title: '确认同步远端站点',
    content: `将继续管理 ${targetDomain} 的远端加速站点，并同步展示最新状态。是否继续？`,
    positiveText: '确认同步',
    negativeText: '取消',
    onPositiveClick: () => syncAccelerationMutation.mutate(),
  });
}

function confirmAccelerationSiteStatus(enabled: boolean) {
  const current = effectiveAccelerationView.value;
  if (!current) return;
  const targetDomain = current.site.accelerationDomain || current.site.zoneName || zoneName.value;
  const actionText = enabled ? '恢复' : '暂停';
  dialog.warning({
    title: `确认${actionText}站点`,
    content: `${actionText} ${targetDomain} 后会立即同步到 EdgeOne 远端站点状态，是否继续？`,
    positiveText: `确认${actionText}`,
    negativeText: '取消',
    onPositiveClick: () => accelerationSiteStatusMutation.mutate(enabled),
  });
}

function confirmDeleteAccelerationSite() {
  const current = effectiveAccelerationView.value;
  if (!current) return;
  const targetDomain = current.site.accelerationDomain || current.site.zoneName || zoneName.value;
  dialog.error({
    title: '确认删除远端站点',
    content: `删除 ${targetDomain} 后不可恢复，并会清理当前面板中的缓存映射。`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: () => deleteRemoteAccelerationMutation.mutate(),
  });
}

function confirmDisableAccelerationConfig() {
  if (!effectiveAccelerationView.value) return;
  const targetDomain = effectiveAccelerationView.value.site.accelerationDomain || effectiveAccelerationView.value.site.zoneName || zoneName.value;
  dialog.warning({
    title: '确认清理缓存映射',
    content: `清理后将不再保留 ${targetDomain} 的本地缓存信息，但不会删除远端站点。是否继续？`,
    positiveText: '确认清理',
    negativeText: '取消',
    onPositiveClick: () => disableAccelerationMutation.mutate(),
  });
}

function copyText(text: string | undefined) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(
    () => message.success('已复制'),
    () => message.error('复制失败'),
  );
}

const enableAccelerationMutation = useMutation({
  mutationFn: async (config?: AccelerationConfigInput) => {
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
      ...(config || {}),
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
    showAccelerationConfig.value = false;
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const updateAccelerationConfigMutation = useMutation({
  mutationFn: async (config: AccelerationConfigInput) => {
    if (!zoneName.value || typeof credentialId.value !== 'number') {
      throw new Error('缺少域名或 DNS 凭证');
    }
    const pluginCredentialId = currentAccelerationTarget.value.pluginCredentialId;
    if (!pluginCredentialId) {
      throw new Error('缺少加速账户');
    }
    return updateAccelerationConfig({
      zoneName: zoneName.value,
      dnsCredentialId: credentialId.value,
      pluginCredentialId,
      ...config,
    });
  },
  onSuccess: async () => {
    message.success('加速配置已更新');
    showAccelerationConfig.value = false;
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const checkAccelerationCnameMutation = useMutation({
  mutationFn: async () => {
    if (!zoneName.value) {
      throw new Error('缺少域名');
    }
    return checkAccelerationCname(currentAccelerationTarget.value);
  },
  onSuccess: async (res) => {
    message.success(res.data?.effective ? 'CNAME 已生效' : 'CNAME 尚未生效，状态已刷新');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const accelerationSiteStatusMutation = useMutation({
  mutationFn: async (enabled: boolean) => {
    if (!zoneName.value || !effectiveAccelerationView.value) {
      throw new Error('缺少可操作的加速站点');
    }
    return setAccelerationSiteStatus({
      ...currentAccelerationTarget.value,
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
    if (!zoneName.value || !effectiveAccelerationView.value) {
      throw new Error('缺少可删除的加速站点');
    }
    return deleteRemoteAcceleration({
      ...currentAccelerationTarget.value,
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
    if (!zoneName.value) {
      throw new Error('缺少域名');
    }
    return verifyAcceleration(currentAccelerationTarget.value);
  },
  onSuccess: async (res) => {
    message.success(res.data?.config?.verified || res.data?.site?.verified ? '加速验证成功' : '已提交加速验证');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const syncAccelerationMutation = useMutation({
  mutationFn: async () => {
    if (!zoneName.value) {
      throw new Error('缺少域名');
    }
    return syncAcceleration(currentAccelerationTarget.value);
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
    if (!zoneName.value) {
      throw new Error('缺少域名');
    }
    return disableAcceleration(currentAccelerationTarget.value);
  },
  onSuccess: async () => {
    message.success('已清理本地缓存映射');
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// Mutations
const createMutation = useMutation({
  mutationFn: async (params: Parameters<typeof createDNSRecord>[1] & { enableAcceleration?: boolean }) => {
    const { enableAcceleration: enableAfterCreate, ...recordParams } = params;
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
        ...buildAccelerationConfigFromRecord(recordParams),
      };
      if (accelerationConfig.value?.pluginCredentialId) {
        accelerationResult = await updateAccelerationConfig(payload);
      } else if (selectedAccelerationCredentialId.value) {
        accelerationResult = await enableAcceleration({
          ...payload,
          zoneId: zoneId.value,
          pluginCredentialId: selectedAccelerationCredentialId.value,
          autoDnsRecord: true,
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
    await refetchRecords();
    await refetchAccelerationConfig();
    await refetchDiscoveredAcceleration();
    queryClient.invalidateQueries({ queryKey: ['acceleration-configs-dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['remote-acceleration-sites-dashboard'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const updateMutation = useMutation({
  mutationFn: async (vars: { recordId: string; params: Parameters<typeof updateDNSRecord>[2] & { enableAcceleration?: boolean } }) => {
    const { enableAcceleration: enableAfterUpdate, ...recordParams } = vars.params;
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
        ...buildAccelerationConfigFromRecord(recordParams),
      };
      if (accelerationConfig.value?.pluginCredentialId) {
        accelerationResult = await updateAccelerationConfig(payload);
      } else if (selectedAccelerationCredentialId.value) {
        accelerationResult = await enableAcceleration({
          ...payload,
          zoneId: zoneId.value,
          pluginCredentialId: selectedAccelerationCredentialId.value,
          autoDnsRecord: true,
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
          检测到 EdgeOne 中已存在当前域名站点，当前展示账户：{{ selectedDiscoveredSite.pluginCredentialName }}。可直接同步远端状态并继续管理。
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
          <div class="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.95fr)]">
            <div class="rounded-[28px] border border-slate-200/80 bg-gradient-to-br from-white via-slate-50 to-sky-50/80 p-5 shadow-sm">
              <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div class="space-y-3">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="inline-flex items-center rounded-full bg-sky-100 px-3 py-1 text-xs font-semibold text-sky-700">
                      EdgeOne 加速
                    </span>
                    <span class="inline-flex items-center rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold text-white">
                      {{ accelerationDomainLabel }}
                    </span>
                    <span class="inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold" :class="accelerationStatusToneClass">
                      {{ accelerationStatusDisplay.label }}
                    </span>
                  </div>
                  <div>
                    <p class="text-sm font-semibold text-slate-800">接入域名</p>
                    <p class="mt-2 break-all font-mono text-[1.05rem] font-semibold text-slate-900">{{ accelerationDomainLabel }}</p>
                    <p class="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                      {{ accelerationStatusDisplay.detail || '当前还没有加速接入状态' }}
                    </p>
                  </div>
                </div>

                <div class="w-full max-w-[320px] rounded-3xl border border-white/70 bg-white/90 p-4 shadow-sm backdrop-blur md:w-auto">
                  <label class="mb-2 block text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">加速账户</label>
                  <NSelect
                    v-model:value="selectedAccelerationCredentialId"
                    size="small"
                    :options="accelerationCredentials.map((item) => ({ label: item.name, value: item.id }))"
                    placeholder="选择 EdgeOne 账户"
                  />
                  <div class="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-500">
                    <div class="rounded-2xl bg-slate-50 px-3 py-2">
                      <p>接入模式</p>
                      <p class="mt-1 font-semibold text-slate-700">{{ effectiveAccelerationView?.site.accessType || 'partial' }}</p>
                    </div>
                    <div class="rounded-2xl bg-slate-50 px-3 py-2">
                      <p>IPv6</p>
                      <p class="mt-1 font-semibold text-slate-700">{{ effectiveAccelerationView?.site.ipv6Status || 'follow' }}</p>
                    </div>
                  </div>
                </div>
              </div>

              <div class="mt-5 overflow-hidden rounded-[24px] border border-slate-200 bg-white/95 shadow-sm">
                <div class="border-b border-slate-200 px-5 py-4">
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p class="text-sm font-semibold text-slate-800">域名配置 · 接入管理</p>
                      <p class="mt-1 text-sm leading-6 text-slate-500">延续远端站点状态展示，可直接同步、验证、暂停和删除。</p>
                    </div>
                    <span class="inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold" :class="accelerationRemoteToneClass">
                      {{ accelerationRemoteMeta?.label || accelerationStatusDisplay.label }}
                    </span>
                  </div>
                </div>

                <div class="px-5 py-4">
                  <div class="grid gap-4 border-b border-slate-100 pb-4 xl:grid-cols-[minmax(0,1.2fr)_120px_minmax(0,1fr)_140px]">
                    <div>
                      <p class="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">加速域名 / CNAME</p>
                      <p class="mt-3 break-all font-mono text-sm font-semibold text-slate-900">{{ accelerationDomainLabel }}</p>
                      <button
                        class="mt-2 min-h-[44px] break-all text-left font-mono text-xs text-slate-500 transition-colors duration-200 hover:text-sky-700"
                        @click="copyText(effectiveAccelerationView?.site.cnameTarget)"
                      >
                        {{ effectiveAccelerationView?.site.cnameTarget || '等待下发 CNAME' }}
                      </button>
                      <div class="mt-3">
                        <span class="inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold" :class="accelerationRemoteToneClass">
                          {{ accelerationRemoteMeta?.label || accelerationStatusDisplay.label }}
                        </span>
                      </div>
                    </div>
                    <div>
                      <p class="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">源站类型</p>
                      <p class="mt-3 text-sm font-semibold text-slate-900">{{ effectiveAccelerationView?.site.originType || 'IP_DOMAIN' }}</p>
                    </div>
                    <div>
                      <p class="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">源站配置</p>
                      <p class="mt-3 break-all text-sm font-semibold text-slate-900">{{ effectiveAccelerationView?.site.originValue || '-' }}</p>
                      <p class="mt-2 text-xs leading-6 text-slate-500">{{ accelerationOriginSummary }}</p>
                    </div>
                    <div>
                      <p class="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">拓展服务</p>
                      <p class="mt-3 text-sm font-semibold text-slate-900">{{ accelerationFeatureSummary }}</p>
                      <p class="mt-2 text-xs text-slate-500">套餐：{{ effectiveAccelerationView?.site.planId || '默认' }}</p>
                    </div>
                  </div>

                  <div class="grid gap-3 border-b border-slate-100 py-4 sm:grid-cols-2 xl:grid-cols-4">
                    <article class="rounded-3xl bg-slate-50 px-4 py-4">
                      <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">站点状态</p>
                      <p class="mt-3 text-base font-semibold text-slate-900">{{ accelerationSiteSummary }}</p>
                      <p class="mt-1 text-xs text-slate-500">域名状态：{{ effectiveAccelerationView?.site.domainStatus || '-' }}</p>
                    </article>
                    <article class="rounded-3xl bg-slate-50 px-4 py-4">
                      <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">加速账户</p>
                      <p class="mt-3 text-sm font-semibold text-slate-900">{{ accelerationSourceDetail }}</p>
                      <p class="mt-1 text-xs text-slate-500">Site {{ effectiveAccelerationView?.site.remoteSiteId || '-' }}</p>
                    </article>
                    <article class="rounded-3xl bg-slate-50 px-4 py-4">
                      <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Host Header</p>
                      <p class="mt-3 break-all text-sm font-semibold text-slate-900">{{ effectiveAccelerationView?.site.hostHeader || accelerationDomainLabel }}</p>
                      <p class="mt-1 text-xs text-slate-500">接入区域：{{ effectiveAccelerationView?.site.area || 'global' }}</p>
                    </article>
                    <article class="rounded-3xl bg-slate-50 px-4 py-4">
                      <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">验证状态</p>
                      <p class="mt-3 text-sm font-semibold text-slate-900">{{ effectiveAccelerationView?.site.cnameStatus || effectiveAccelerationView?.site.identificationStatus || effectiveAccelerationView?.site.verifyStatus || '-' }}</p>
                      <p class="mt-1 text-xs text-slate-500">点击上方 CNAME 可直接复制</p>
                    </article>
                  </div>

                  <div class="flex flex-wrap gap-2 pt-4">
                    <NButton
                      v-if="!accelerationConfig && !selectedDiscoveredSite"
                      size="small"
                      type="primary"
                      @click="openAccelerationConfig"
                    >
                      {{ accelerationManageActionLabel }}
                    </NButton>
                    <NButton
                      v-if="!accelerationConfig && selectedDiscoveredSite"
                      size="small"
                      type="primary"
                      :loading="accelerationManageActionPending"
                      @click="confirmTakeOverAccelerationSite"
                    >
                      {{ accelerationManageActionLabel }}
                    </NButton>
                    <NButton
                      v-if="!accelerationConfig && selectedDiscoveredSite"
                      size="small"
                      secondary
                      @click="openAccelerationConfig"
                    >
                      按当前配置同步
                    </NButton>
                    <template v-if="accelerationConfig">
                      <NButton
                        size="small"
                        type="primary"
                        @click="openAccelerationConfig"
                      >
                        {{ accelerationManageActionLabel }}
                      </NButton>
                      <NButton
                        size="small"
                        secondary
                        :loading="syncAccelerationMutation.isPending.value"
                        @click="syncAccelerationMutation.mutate()"
                      >
                        刷新状态
                      </NButton>
                      <NButton
                        size="small"
                        secondary
                        :loading="checkAccelerationCnameMutation.isPending.value"
                        @click="checkAccelerationCnameMutation.mutate()"
                      >
                        检测生效
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
                        @click="confirmAccelerationSiteStatus(Boolean(accelerationConfig?.paused))"
                      >
                        {{ accelerationConfig?.paused ? '恢复站点' : '暂停站点' }}
                      </NButton>
                      <NButton
                        size="small"
                        tertiary
                        type="error"
                        :loading="deleteRemoteAccelerationMutation.isPending.value"
                        @click="confirmDeleteAccelerationSite"
                      >
                        删除远端
                      </NButton>
                      <NButton
                        size="small"
                        tertiary
                        :loading="disableAccelerationMutation.isPending.value"
                        @click="confirmDisableAccelerationConfig"
                      >
                        清理缓存
                      </NButton>
                    </template>
                    <template v-else-if="selectedDiscoveredSite">
                      <NButton
                        size="small"
                        secondary
                        :loading="accelerationRefreshPending"
                        @click="refetchDiscoveredAcceleration()"
                      >
                        刷新状态
                      </NButton>
                      <NButton
                        size="small"
                        secondary
                        :loading="accelerationSiteStatusMutation.isPending.value"
                        @click="confirmAccelerationSiteStatus(Boolean(selectedDiscoveredSite.site.paused))"
                      >
                        {{ selectedDiscoveredSite.site.paused ? '恢复站点' : '暂停站点' }}
                      </NButton>
                      <NButton
                        size="small"
                        tertiary
                        type="error"
                        :loading="deleteRemoteAccelerationMutation.isPending.value"
                        @click="confirmDeleteAccelerationSite"
                      >
                        删除远端
                      </NButton>
                    </template>
                    <NButton size="small" secondary @click="showAddAccelerationCredential = true">
                      新增加速账户
                    </NButton>
                  </div>
                </div>
              </div>
            </div>

            <div class="space-y-4">
              <div v-if="effectiveAccelerationView" class="rounded-[28px] border border-slate-200 bg-slate-50/80 p-5 shadow-sm">
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <p class="text-sm font-semibold text-slate-800">最后一步 · 添加 CNAME 记录</p>
                    <p class="mt-1 text-sm leading-6 text-slate-500">{{ accelerationCnameHint }}</p>
                  </div>
                  <span class="inline-flex items-center rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold text-white">
                    CNAME 接入
                  </span>
                </div>

                <div class="mt-4 space-y-3">
                  <div class="rounded-3xl border border-slate-200 bg-white px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">主机记录</p>
                    <button
                      class="mt-2 min-h-[44px] break-all text-left font-mono text-sm font-semibold text-slate-900 transition-colors duration-200 hover:text-sky-700"
                      @click="copyText(accelerationHostRecordLabel)"
                    >
                      {{ accelerationHostRecordLabel }}
                    </button>
                  </div>
                  <div class="rounded-3xl border border-slate-200 bg-white px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">记录类型</p>
                    <button
                      class="mt-2 min-h-[44px] text-left font-mono text-sm font-semibold text-slate-900 transition-colors duration-200 hover:text-sky-700"
                      @click="copyText('CNAME')"
                    >
                      CNAME
                    </button>
                  </div>
                  <div class="rounded-3xl border border-slate-200 bg-white px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">记录值</p>
                    <button
                      class="mt-2 min-h-[44px] break-all text-left font-mono text-sm font-semibold text-slate-900 transition-colors duration-200 hover:text-sky-700"
                      @click="copyText(effectiveAccelerationView.site.cnameTarget)"
                    >
                      {{ effectiveAccelerationView.site.cnameTarget || '等待下发' }}
                    </button>
                  </div>
                </div>

                <div class="mt-4 rounded-2xl border border-sky-100 bg-sky-50/80 px-4 py-3 text-xs leading-6 text-sky-800">
                  解析生效时间取决于 DNS 服务商 TTL，通常需要数分钟到数小时。若你已开启 HTTPS，证书状态会随接入进度继续更新。
                </div>
              </div>

              <div v-if="effectiveAccelerationView" class="rounded-[28px] border border-slate-200 bg-white p-5 shadow-sm">
                <p class="text-sm font-semibold text-slate-800">加速链路摘要</p>
                <div class="mt-4 grid gap-3 sm:grid-cols-2">
                  <div class="rounded-3xl bg-slate-50 px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">加速域名</p>
                    <p class="mt-2 break-all font-mono text-sm font-semibold text-slate-900">{{ accelerationDomainLabel }}</p>
                  </div>
                  <div class="rounded-3xl bg-slate-50 px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Host Header</p>
                    <p class="mt-2 break-all text-sm font-semibold text-slate-900">{{ effectiveAccelerationView.site.hostHeader || accelerationDomainLabel }}</p>
                  </div>
                  <div class="rounded-3xl bg-slate-50 px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">接入区域</p>
                    <p class="mt-2 text-sm font-semibold text-slate-900">{{ effectiveAccelerationView.site.area || 'global' }}</p>
                  </div>
                  <div class="rounded-3xl bg-slate-50 px-4 py-4">
                    <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">验证状态</p>
                    <p class="mt-2 text-sm font-semibold text-slate-900">{{ effectiveAccelerationView.site.cnameStatus || effectiveAccelerationView.site.identificationStatus || effectiveAccelerationView.site.verifyStatus || '-' }}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div v-if="effectiveAccelerationView?.site?.verifyRecordName" class="rounded-[28px] border border-amber-200 bg-amber-50/60 p-5 shadow-sm">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-amber-900">域名归属验证记录</p>
                <p class="mt-1 text-sm leading-6 text-amber-800">{{ accelerationVerifyHint }}</p>
              </div>
              <NButton
                v-if="accelerationConfig && !accelerationConfig.verified"
                size="small"
                type="primary"
                :loading="verifyAccelerationMutation.isPending.value"
                @click="verifyAccelerationMutation.mutate()"
              >
                重新验证
              </NButton>
            </div>
            <div class="mt-4 grid gap-3 md:grid-cols-3">
              <div class="rounded-2xl bg-white/80 p-4">
                <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">类型</p>
                <button class="mt-2 min-h-[44px] text-left font-mono text-sm font-semibold text-slate-900 transition-colors duration-200 hover:text-amber-700" @click="copyText(effectiveAccelerationView.site.verifyRecordType)">
                  {{ effectiveAccelerationView.site.verifyRecordType || 'TXT' }}
                </button>
              </div>
              <div class="rounded-2xl bg-white/80 p-4">
                <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">主机记录</p>
                <button class="mt-2 min-h-[44px] break-all text-left font-mono text-sm font-semibold text-slate-900 transition-colors duration-200 hover:text-amber-700" @click="copyText(effectiveAccelerationView.site.verifyRecordName)">
                  {{ effectiveAccelerationView.site.verifyRecordName }}
                </button>
              </div>
              <div class="rounded-2xl bg-white/80 p-4">
                <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">记录值</p>
                <button class="mt-2 min-h-[44px] break-all text-left font-mono text-sm font-semibold text-slate-900 transition-colors duration-200 hover:text-amber-700" @click="copyText(effectiveAccelerationView.site.verifyRecordValue)">
                  {{ effectiveAccelerationView.site.verifyRecordValue }}
                </button>
              </div>
            </div>
          </div>

          <div v-if="discoveredAccelerationSites.length > 1 && !accelerationConfig" class="rounded-[28px] border border-slate-200 bg-panel-surface p-5 shadow-sm">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-slate-800">可用远端站点</p>
                <p class="mt-1 text-sm leading-6 text-slate-500">如果同一域名在多个 EdgeOne 账户下已存在，这里会展示所有候选站点，可直接切换账户查看与管理。</p>
              </div>
              <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600">
                {{ discoveredAccelerationSites.length }} 个候选
              </span>
            </div>
            <div class="mt-4 grid gap-3">
              <div
                v-for="item in discoveredAccelerationSites"
                :key="`${item.pluginCredentialId}-${item.site.remoteSiteId}`"
                class="rounded-3xl border border-slate-200 bg-white/80 p-4 shadow-sm"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div class="flex flex-wrap items-center gap-2">
                      <p class="text-sm font-semibold text-slate-800">{{ item.pluginCredentialName }}</p>
                      <span class="inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold"
                        :class="getAccelerationStatusMeta(item.site, { remote: true }).type === 'success'
                          ? 'bg-emerald-100 text-emerald-700'
                          : getAccelerationStatusMeta(item.site, { remote: true }).type === 'warning'
                            ? 'bg-amber-100 text-amber-700'
                            : getAccelerationStatusMeta(item.site, { remote: true }).type === 'error'
                              ? 'bg-rose-100 text-rose-700'
                              : 'bg-slate-100 text-slate-600'"
                      >
                        {{ getAccelerationStatusMeta(item.site, { remote: true }).label }}
                      </span>
                    </div>
                    <p class="mt-1 text-xs text-slate-500">Site {{ item.site.remoteSiteId || '-' }} · {{ item.site.accelerationDomain || item.site.zoneName || '-' }}</p>
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
    <AddAccelerationCredentialDialog
      v-model:show="showAddAccelerationCredential"
      @created="() => { refetchAccelerationCredentials(); refetchDiscoveredAcceleration(); }"
    />
    <AccelerationConfigDialog
      :show="showAccelerationConfig"
      :zone-name="zoneName"
      :loading="enableAccelerationMutation.isPending.value || updateAccelerationConfigMutation.isPending.value"
      :value="(accelerationConfig || effectiveAccelerationView?.site) ?? null"
      @update:show="showAccelerationConfig = $event"
      @submit="(payload) => accelerationConfig ? updateAccelerationConfigMutation.mutate(payload) : enableAccelerationMutation.mutate(payload)"
    />
  </div>
</template>
