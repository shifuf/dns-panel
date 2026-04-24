<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NButton, NSpin, NTag, useMessage } from 'naive-ui';
import { Plus, RefreshCw, Globe } from 'lucide-vue-next';
import {
  getDNSRecords,
  getDNSLines,
  getDNSMinTTL,
  createDNSRecord,
  updateDNSRecord,
  deleteDNSRecord,
  setDNSRecordStatus,
  setDNSRecordAcceleration,
  refreshDNSRecords,
  batchDeleteDNSRecords,
  batchSetDNSRecordStatus,
} from '@/services/dns';
import { listAccelerationDomains, listAccelerationSites, updateAccelerationDomainStatus, finalizeAccelerationDomain, autoConfigureAccelerationCname, type AccelerationDomain } from '@/services/accelerations';
import { getDnsCredentials } from '@/services/dnsCredentials';
import { getDomainById } from '@/services/domains';
import type { DNSRecordsResponseData, RecordsResponseCapabilities } from '@/services/dns';
import { useProviderStore } from '@/stores/provider';
import { useBreadcrumbStore } from '@/stores/breadcrumb';
import { useCredentialResolver } from '@/composables/useCredentialResolver';
import type { DNSRecord, DNSRecordAcceleration } from '@/types';
import type { DnsCredential, DnsLine } from '@/types/dns';
import { normalizeProviderType } from '@/utils/provider';
import { TABLE_PAGE_SIZE } from '@/utils/constants';
import DNSRecordTable from '@/components/DNSRecordTable/DNSRecordTable.vue';
import QuickAddForm from '@/components/QuickAddForm/QuickAddForm.vue';

type ResolvedAccelerationDomain = AccelerationDomain & {
  accelerationCredentialId: number;
  accelerationCredentialName?: string;
  siteId: string;
};

const route = useRoute();
const router = useRouter();
const message = useMessage();
const queryClient = useQueryClient();
const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const { credentialId } = useCredentialResolver();

const zoneId = computed(() => route.params.zoneId as string);
const showAddDialog = ref(false);
const editingRecord = ref<DNSRecord | null>(null);
const editorDefaultOpenAcceleration = ref(false);
const editorNeedsRestoreInput = ref(false);
const editorSaving = ref(false);
const refreshing = ref(false);
const updatingRecordIds = ref<string[]>([]);
const deletingRecordIds = ref<string[]>([]);
const statusChangingRecordIds = ref<string[]>([]);
const accelerationChangingRecordIds = ref<string[]>([]);
const batchStatusLoading = ref<'enable' | 'disable' | null>(null);
const batchDeleteLoading = ref(false);
const currentPage = ref(1);
const currentPageSize = ref(TABLE_PAGE_SIZE);
const pageSizeOptions = [10, 20, 50, 100, 200];
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

function normalizeHost(value?: string | null) {
  return String(value || '').trim().replace(/\.+$/, '').toLowerCase();
}

function hasOriginalRecordSnapshot(acceleration?: DNSRecordAcceleration | null) {
  const original = acceleration?.originalRecord;
  if (!original) return false;
  return [
    original.type,
    original.value,
    original.line,
    original.remark,
  ].some((value) => String(value ?? '').trim())
    || original.ttl != null
    || original.priority != null
    || original.weight != null;
}

const { data: domainData } = useQuery({
  queryKey: computed(() => ['domain-detail', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getDomainById(zoneId.value, credentialId.value);
    return res.data?.domain || null;
  },
  enabled: computed(() => !!zoneId.value),
});

const recordsQueryKey = computed(() => [
  'dns-records',
  zoneId.value,
  credentialId.value,
  currentPage.value,
  currentPageSize.value,
]);
const accelerationDomainsQueryKey = computed(() => [
  'dns-detail-acceleration-domains',
  zoneName.value,
  accelerationCredentials.value.map((item) => item.id).join(','),
]);

// DNS records
const { data: recordsData, isLoading: recordsLoading, refetch: refetchRecords } = useQuery({
  queryKey: recordsQueryKey,
  queryFn: async () => {
    const res = await getDNSRecords(zoneId.value, {
      page: currentPage.value,
      pageSize: currentPageSize.value,
      credentialId: credentialId.value,
    });
    return res.data as DNSRecordsResponseData;
  },
  enabled: computed(() => !!zoneId.value),
});

const records = computed(() => recordsData.value?.records || []);
const totalRecords = computed(() => Math.max(0, Number(recordsData.value?.total || 0)));
const totalPages = computed(() => Math.max(1, Math.ceil(totalRecords.value / currentPageSize.value)));
const zoneName = computed(() =>
  domainData.value?.name || records.value[0]?.zoneName || ''
);
const { data: accelerationCredentialsData } = useQuery({
  queryKey: ['acceleration-credentials', 'edgeone'],
  queryFn: async () => {
    const res = await getDnsCredentials('acceleration');
    return (res.data?.credentials || []).filter((item) => normalizeProviderType(item.provider) === 'edgeone');
  },
  staleTime: 60_000,
});
const accelerationCredentials = computed<DnsCredential[]>(() => accelerationCredentialsData.value || []);
const hasAccelerationCandidates = computed(() => {
  const normalizedZone = normalizeHost(zoneName.value);
  return records.value.some((record) => {
    const normalizedName = normalizeHost(record.name);
    return ['A', 'AAAA', 'CNAME'].includes(record.type) && !!normalizedName && normalizedName !== normalizedZone;
  });
});

type RecordsQueryData = DNSRecordsResponseData;

function updateRecordsCache(updater: (records: DNSRecord[]) => DNSRecord[]) {
  const current = queryClient.getQueryData<RecordsQueryData>(recordsQueryKey.value);
  if (!current) return false;
  queryClient.setQueryData<RecordsQueryData>(recordsQueryKey.value, {
    ...current,
    records: updater([...(current.records || [])]),
  });
  return true;
}

function replaceCachedRecord(record?: DNSRecord | null) {
  if (!record) return false;
  return updateRecordsCache((current) => {
    const index = current.findIndex((item) => item.id === record.id);
    if (index < 0) return current;
    const next = [...current];
    next[index] = record;
    return next;
  });
}

async function loadAccelerationDomainsForZone(): Promise<ResolvedAccelerationDomain[]> {
  const normalizedZone = normalizeHost(zoneName.value);
  if (!normalizedZone || !accelerationCredentials.value.length || !hasAccelerationCandidates.value) return [];

  const results = await Promise.all(
    accelerationCredentials.value.map(async (credential) => {
      try {
        const sitesRes = await listAccelerationSites({
          credentialId: credential.id,
          provider: 'edgeone',
          keyword: normalizedZone,
        });
        const matchedSites = (sitesRes.data?.sites || []).filter((item) =>
          normalizeHost(item.zoneName || item.siteName) === normalizedZone
        );
        if (!matchedSites.length) return [];

        const domainGroups = await Promise.all(
          matchedSites.map(async (site) => {
            const siteId = String(site.siteId || site.zoneId || '').trim();
            if (!siteId) return [];
            const domainsRes = await listAccelerationDomains({
              credentialId: credential.id,
              provider: 'edgeone',
              siteId,
            });
            return (domainsRes.data?.domains || []).map((domain) => ({
              ...domain,
              siteId,
              accelerationCredentialId: credential.id,
              accelerationCredentialName: credential.name,
            }));
          })
        );
        return domainGroups.flat();
      } catch {
        return [];
      }
    })
  );

  return results.flat();
}

const { data: accelerationDomainsData } = useQuery({
  queryKey: accelerationDomainsQueryKey,
  queryFn: loadAccelerationDomainsForZone,
  enabled: computed(() => !!zoneName.value && accelerationCredentials.value.length > 0 && hasAccelerationCandidates.value),
  retry: false,
  staleTime: 120_000,
});

const accelerationDomainMap = computed(() => {
  if (!hasAccelerationCandidates.value) return new Map<string, ResolvedAccelerationDomain>();
  const map = new Map<string, ResolvedAccelerationDomain>();
  for (const item of accelerationDomainsData.value || []) {
    const key = normalizeHost(item.domainName);
    if (key && !map.has(key)) map.set(key, item);
  }
  return map;
});

function buildDisplayRecord(record: DNSRecord, domainMap: Map<string, ResolvedAccelerationDomain>): DNSRecord {
  const currentAcceleration = record.acceleration
    ? {
        ...record.acceleration,
        source: record.acceleration.source || 'state',
        restorable: record.acceleration.restorable ?? hasOriginalRecordSnapshot(record.acceleration),
      }
    : null;
  const matchedDomain = domainMap.get(normalizeHost(record.name));
  const matchedTarget = normalizeHost(matchedDomain?.cnameTarget);
  const targetMatched = !!matchedDomain
    && ['A', 'AAAA', 'CNAME'].includes(record.type)
    && !!matchedTarget
    && normalizeHost(record.content) === matchedTarget;

  const cnamePending = !!matchedDomain
    && ['A', 'AAAA'].includes(record.type)
    && !targetMatched
    && !currentAcceleration?.enabled;

  if (!targetMatched && !cnamePending) {
    if (currentAcceleration) {
      let uiState = matchedDomain?.uiState || currentAcceleration.uiState || 'active';
      if (currentAcceleration.enabled && record.type !== 'CNAME' && !targetMatched) {
        uiState = 'cname_pending';
      }
      if (matchedDomain?.paused) {
        uiState = 'paused';
      }
      return { ...record, acceleration: { ...currentAcceleration, uiState } };
    }
    return record;
  }

  if (cnamePending && !currentAcceleration?.enabled) {
    const domainUiState = matchedDomain?.uiState || 'cname_pending';
    return {
      ...record,
      acceleration: {
        enabled: false,
        source: 'matched',
        restorable: false,
        uiState: domainUiState === 'cname_pending' || domainUiState === 'deploying' ? domainUiState : 'cname_pending',
        provider: currentAcceleration?.provider || 'edgeone',
        credentialId: currentAcceleration?.credentialId ?? matchedDomain?.accelerationCredentialId ?? null,
        siteId: currentAcceleration?.siteId ?? matchedDomain?.siteId ?? null,
        domainName: matchedDomain?.domainName || record.name,
        target: matchedDomain?.cnameTarget || null,
        originalRecord: currentAcceleration?.originalRecord || null,
      },
    };
  }

  let uiState = matchedDomain?.uiState || currentAcceleration?.uiState || 'active';
  if (currentAcceleration?.enabled && record.type !== 'CNAME' && !targetMatched) {
    uiState = 'cname_pending';
  }
  if (matchedDomain?.paused) {
    uiState = 'paused';
  }

  return {
    ...record,
    acceleration: {
      ...(currentAcceleration || {}),
      enabled: true,
      source: currentAcceleration?.source || 'matched',
      restorable: currentAcceleration?.restorable ?? false,
      uiState,
      provider: currentAcceleration?.provider || 'edgeone',
      credentialId: currentAcceleration?.credentialId ?? matchedDomain?.accelerationCredentialId ?? null,
      siteId: currentAcceleration?.siteId ?? matchedDomain?.siteId ?? null,
      domainName: currentAcceleration?.domainName || matchedDomain?.domainName || record.name,
      target: currentAcceleration?.target || matchedDomain?.cnameTarget || null,
      originalRecord: currentAcceleration?.originalRecord || null,
    },
  };
}

const tableRecords = computed(() => {
  const domainMap = accelerationDomainMap.value;
  const hasDomainMatches = domainMap.size > 0;
  return records.value.map((record) => {
    if (!hasDomainMatches && !record.acceleration) return record;
    return buildDisplayRecord(record, domainMap);
  });
});
const visibleTableRecords = computed(() =>
  tableRecords.value.filter((r) => !(r.type === 'NS' && r.name === r.zoneName))
);
const currentPageRecordCount = computed(() => visibleTableRecords.value.length);
const hiddenRootNsCount = computed(() => tableRecords.value.length - visibleTableRecords.value.length);
const enabledCount = computed(() => visibleTableRecords.value.filter(r => r.enabled !== false).length);
const recordTypeCount = computed(() => new Set(visibleTableRecords.value.map(r => r.type)).size);
const currentPageEnabledRatio = computed(() =>
  currentPageRecordCount.value > 0 ? Math.round((enabledCount.value / currentPageRecordCount.value) * 100) : 0
);

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

// Keep provider context in sync when navigating from dashboard with credentialId.
watch(
  [zoneId, credentialId],
  () => {
    currentPage.value = 1;
  }
);

watch(
  [totalRecords, currentPageSize],
  () => {
    const maxPage = Math.max(1, Math.ceil(totalRecords.value / currentPageSize.value));
    if (currentPage.value > maxPage) {
      currentPage.value = maxPage;
    }
  },
  { immediate: true }
);

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

// Mutations
function appendPendingId(target: typeof updatingRecordIds, id: string) {
  if (!id || target.value.includes(id)) return;
  target.value = [...target.value, id];
}

function removePendingId(target: typeof updatingRecordIds, id: string) {
  target.value = target.value.filter((item) => item !== id);
}

const deleteRecordMutation = useMutation({
  mutationFn: (recordId: string) => deleteDNSRecord(zoneId.value, recordId, credentialId.value),
  onMutate: (recordId) => {
    appendPendingId(deletingRecordIds, recordId);
  },
  onSuccess: async () => {
    message.success('记录已删除');
    await refetchRecords();
  },
  onSettled: (_data, _error, recordId) => {
    removePendingId(deletingRecordIds, recordId);
  },
  onError: (err: any) => message.error(String(err)),
});

const statusMutation = useMutation({
  mutationFn: (vars: { recordId: string; enabled: boolean }) =>
    setDNSRecordStatus(zoneId.value, vars.recordId, vars.enabled, credentialId.value),
  onMutate: (vars) => {
    appendPendingId(statusChangingRecordIds, vars.recordId);
  },
  onSuccess: async (res, vars) => {
    message.success('状态已更新');
    const replaced = replaceCachedRecord(res.data?.record);
    if (!replaced) {
      const updated = updateRecordsCache((current) => current.map((item) =>
        item.id === vars.recordId ? { ...item, enabled: vars.enabled } : item
      ));
      if (!updated) await refetchRecords();
    }
  },
  onSettled: (_data, _error, vars) => {
    removePendingId(statusChangingRecordIds, vars.recordId);
  },
  onError: (err: any) => message.error(String(err)),
});

async function handleRefresh() {
  if (refreshing.value) return;
  refreshing.value = true;
  try {
    await refreshDNSRecords(zoneId.value, credentialId.value);
    await refetchRecords();
    message.success('已刷新');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    refreshing.value = false;
  }
}

function openCreate() {
  editingRecord.value = null;
  editorDefaultOpenAcceleration.value = false;
  editorNeedsRestoreInput.value = false;
  showAddDialog.value = true;
}

function handleEditRecord(record: DNSRecord, options: { focusAcceleration?: boolean } = {}) {
  editingRecord.value = record;
  editorDefaultOpenAcceleration.value = !!options.focusAcceleration;
  editorNeedsRestoreInput.value = false;
  showAddDialog.value = true;
}

async function handleSubmit(params: any) {
  if (editorSaving.value) return;
  editorSaving.value = true;
  try {
    const { recordId, acceleration, dnsChanged, ...dnsFields } = params;
    const isEdit = !!recordId;
    let resultRecord: DNSRecord | null = editingRecord.value;

    if (!isEdit) {
      const res = await createDNSRecord(zoneId.value, {
        type: dnsFields.type,
        name: dnsFields.name,
        content: dnsFields.content,
        ttl: dnsFields.ttl,
        proxied: dnsFields.proxied,
        priority: dnsFields.priority,
        weight: dnsFields.weight,
        line: dnsFields.line,
        remark: dnsFields.remark,
      }, credentialId.value);
      resultRecord = res.data?.record || null;
    } else if (dnsChanged) {
      appendPendingId(updatingRecordIds, recordId);
      try {
        const res = await updateDNSRecord(zoneId.value, recordId, {
          type: dnsFields.type,
          name: dnsFields.name,
          content: dnsFields.content,
          ttl: dnsFields.ttl,
          proxied: dnsFields.proxied,
          priority: dnsFields.priority,
          weight: dnsFields.weight,
          line: dnsFields.line,
          remark: dnsFields.remark,
        }, credentialId.value);
        resultRecord = res.data?.record || null;
        replaceCachedRecord(resultRecord);
      } finally {
        removePendingId(updatingRecordIds, recordId);
      }
    }

    const targetId: string | undefined = resultRecord?.id || recordId;
    const accelerationPayload = acceleration as
      | {
          enabled: boolean;
          origin?: {
            originType: string;
            originValue: string;
            backupOriginValue?: string;
            hostHeaderMode: 'acceleration' | 'custom';
            customHostHeader?: string;
            originProtocol: string;
            httpOriginPort: number;
            httpsOriginPort: number;
            ipv6Status: string;
          };
          restoreRecord?: { type: string; value: string; ttl?: number };
        }
      | undefined;

    if (accelerationPayload && targetId) {
      appendPendingId(accelerationChangingRecordIds, targetId);
      try {
        if (accelerationPayload.enabled) {
          const accelRes = await setDNSRecordAcceleration(zoneId.value, targetId, true, credentialId.value);
          const accel = accelRes.data?.acceleration;
          replaceCachedRecord(accelRes.data?.record ?? null);
          if (
            accelerationPayload.origin
            && accel?.domainName
            && accel?.siteId
            && accel?.credentialId
          ) {
            const o = accelerationPayload.origin;
            const hostHeader = o.hostHeaderMode === 'custom' ? String(o.customHostHeader || '').trim() : undefined;
            try {
              await finalizeAccelerationDomain(accel.domainName, {
                credentialId: accel.credentialId,
                provider: accel.provider || 'edgeone',
                siteId: accel.siteId,
                originType: o.originType,
                originValue: o.originValue,
                backupOriginValue: o.backupOriginValue || undefined,
                hostHeader: hostHeader || undefined,
                originProtocol: o.originProtocol,
                httpOriginPort: o.httpOriginPort,
                httpsOriginPort: o.httpsOriginPort,
                ipv6Status: o.ipv6Status,
                dnsCredentialId: credentialId.value,
                autoMatchDns: true,
              });
            } catch (finalizeErr: any) {
              try {
                await autoConfigureAccelerationCname({
                  credentialId: accel.credentialId,
                  provider: accel.provider || 'edgeone',
                  siteId: accel.siteId,
                  domainName: accel.domainName,
                  dnsCredentialId: credentialId.value,
                  autoMatchDns: true,
                });
              } catch (_cnameErr: any) {
                void _cnameErr;
              }
            }
          } else if (accel?.domainName && accel?.siteId && accel?.credentialId) {
            try {
              await autoConfigureAccelerationCname({
                credentialId: accel.credentialId,
                provider: accel.provider || 'edgeone',
                siteId: accel.siteId,
                domainName: accel.domainName,
                dnsCredentialId: credentialId.value,
                autoMatchDns: true,
              });
            } catch (_cnameErr: any) {
              void _cnameErr;
            }
          }
          void queryClient.invalidateQueries({ queryKey: accelerationDomainsQueryKey.value });
        } else {
          const disableRes = await setDNSRecordAcceleration(zoneId.value, targetId, false, credentialId.value, {
            restoreRecord: accelerationPayload.restoreRecord,
          });
          if (disableRes.data?.needsRestoreInput) {
            if (disableRes.data.currentRecord) editingRecord.value = disableRes.data.currentRecord;
            editorDefaultOpenAcceleration.value = true;
            editorNeedsRestoreInput.value = true;
            message.warning(disableRes.message || '请填写原始记录值后再取消加速');
            return;
          }
          replaceCachedRecord(disableRes.data?.record ?? null);
          void queryClient.invalidateQueries({ queryKey: accelerationDomainsQueryKey.value });
        }
      } finally {
        removePendingId(accelerationChangingRecordIds, targetId);
      }
    }

    message.success(isEdit ? '记录已保存' : '记录已添加');
    showAddDialog.value = false;
    editingRecord.value = null;
    editorNeedsRestoreInput.value = false;
    editorDefaultOpenAcceleration.value = false;
    if (!isEdit && currentPage.value !== 1) {
      currentPage.value = 1;
    } else {
      await refetchRecords();
    }
  } catch (err: any) {
    message.error(String(err?.message || err));
  } finally {
    editorSaving.value = false;
  }
}

function handleDelete(recordId: string) {
  deleteRecordMutation.mutate(recordId);
}

function handleStatusChange(recordId: string, enabled: boolean) {
  statusMutation.mutate({ recordId, enabled });
}

function handlePageChange(page: number) {
  currentPage.value = Math.max(1, Number(page || 1));
}

function handlePageSizeChange(pageSize: number) {
  currentPageSize.value = Math.max(1, Number(pageSize || TABLE_PAGE_SIZE));
  currentPage.value = 1;
}

async function handleBatchDelete(recordIds: string[]) {
  if (!recordIds.length || batchDeleteLoading.value) return;
  batchDeleteLoading.value = true;
  try {
    const res = await batchDeleteDNSRecords(zoneId.value, recordIds, credentialId.value);
    const success = Number(res.data?.successCount || 0);
    const failed = Number(res.data?.failedCount || 0);
    if (failed > 0) {
      message.warning(`批量删除完成：成功 ${success}，失败 ${failed}`);
    } else {
      message.success(`已删除 ${success} 条记录`);
    }
    const successIds = (res.data?.results || [])
      .filter((item) => item.success)
      .map((item) => String(item.recordId || '').trim())
      .filter(Boolean);
    if (successIds.length > 0) {
      await refetchRecords();
    }
  } catch (err: any) {
    message.error(String(err));
  } finally {
    batchDeleteLoading.value = false;
  }
}

async function handleBatchStatusChange(recordIds: string[], enabled: boolean) {
  if (!recordIds.length || batchStatusLoading.value) return;
  batchStatusLoading.value = enabled ? 'enable' : 'disable';
  try {
    const res = await batchSetDNSRecordStatus(zoneId.value, recordIds, enabled, credentialId.value);
    const success = Number(res.data?.successCount || 0);
    const failed = Number(res.data?.failedCount || 0);
    if (failed > 0) {
      message.warning(`批量${enabled ? '启用' : '禁用'}完成：成功 ${success}，失败 ${failed}`);
    } else {
      message.success(`已${enabled ? '启用' : '禁用'} ${success} 条记录`);
    }
    const successIds = new Set(
      (res.data?.results || [])
        .filter((item) => item.success)
        .map((item) => String(item.recordId || '').trim())
        .filter(Boolean)
    );
    if (!successIds.size || !updateRecordsCache((current) => current.map((item) =>
      successIds.has(item.id) ? { ...item, enabled } : item
    ))) {
      await refetchRecords();
    }
  } catch (err: any) {
    message.error(String(err));
  } finally {
    batchStatusLoading.value = null;
  }
}

async function toggleAccelerationDomainEnabled(record: DNSRecord, enabled: boolean) {
  const accel = record.acceleration;
  const domainName = accel?.domainName || record.name;
  let accelCredentialId = accel?.credentialId;
  let siteId = accel?.siteId;

  if (!accelCredentialId || !siteId) {
    const normalized = normalizeHost(domainName);
    const matched = accelerationDomainMap.value.get(normalized);
    if (matched) {
      accelCredentialId = accelCredentialId || matched.accelerationCredentialId;
      siteId = siteId || matched.siteId;
    }
  }

  if (!accelCredentialId || !siteId || !domainName) {
    message.error('缺少加速域名信息，无法切换');
    return;
  }
  appendPendingId(accelerationChangingRecordIds, record.id);
  try {
    await updateAccelerationDomainStatus(domainName, {
      credentialId: accelCredentialId,
      provider: accel?.provider || 'edgeone',
      siteId,
      enabled,
    });
    if (!enabled && accel?.restorable) {
      try {
        const restoreRes = await setDNSRecordAcceleration(zoneId.value, record.id, false, credentialId.value);
        if (!restoreRes.data?.needsRestoreInput) {
          replaceCachedRecord(restoreRes.data?.record ?? null);
        }
      } catch (_restoreErr: any) {
        void _restoreErr;
      }
    }
    if (enabled) {
      try {
        const reAccelRes = await setDNSRecordAcceleration(zoneId.value, record.id, true, accelCredentialId);
        replaceCachedRecord(reAccelRes.data?.record ?? null);
      } catch (_reAccelErr: any) {
        void _reAccelErr;
      }
    }
    void queryClient.invalidateQueries({ queryKey: accelerationDomainsQueryKey.value });
    await refetchRecords();
    message.success(enabled ? '加速已恢复' : '加速已暂停，DNS已恢复源站');
  } catch (err: any) {
    message.error(String(err?.message || err));
  } finally {
    removePendingId(accelerationChangingRecordIds, record.id);
  }
}

function handlePauseAcceleration(record: DNSRecord) {
  void toggleAccelerationDomainEnabled(record, false);
}

function handleResumeAcceleration(record: DNSRecord) {
  void toggleAccelerationDomainEnabled(record, true);
}

async function handleRestoreOrigin(record: DNSRecord) {
  appendPendingId(accelerationChangingRecordIds, record.id);
  try {
    const res = await setDNSRecordAcceleration(zoneId.value, record.id, false, credentialId.value);
    if (res.data?.needsRestoreInput) {
      editingRecord.value = res.data.currentRecord || record;
      editorDefaultOpenAcceleration.value = true;
      editorNeedsRestoreInput.value = true;
      showAddDialog.value = true;
      message.warning(res.message || '请填写原始记录值后再取消加速');
      return;
    }
    replaceCachedRecord(res.data?.record ?? null);
    void queryClient.invalidateQueries({ queryKey: accelerationDomainsQueryKey.value });
    await refetchRecords();
    message.success('已返回源站');
  } catch (err: any) {
    message.error(String(err?.message || err));
  } finally {
    removePendingId(accelerationChangingRecordIds, record.id);
  }
}

const accelerationPollingTimer = ref<ReturnType<typeof setInterval> | null>(null);

const hasTransitionalAcceleration = computed(() => {
  return visibleTableRecords.value.some((r: DNSRecord) => {
    const ui = r.acceleration?.uiState;
    return r.acceleration?.enabled && (ui === 'deploying' || ui === 'cname_pending');
  });
});

function startAccelerationPolling() {
  if (accelerationPollingTimer.value) return;
  accelerationPollingTimer.value = setInterval(async () => {
    if (!hasTransitionalAcceleration.value) {
      stopAccelerationPolling();
      return;
    }
    try {
      await refetchRecords();
    } catch {
      void 0;
    }
  }, 15000);
}

function stopAccelerationPolling() {
  if (accelerationPollingTimer.value) {
    clearInterval(accelerationPollingTimer.value);
    accelerationPollingTimer.value = null;
  }
}

watch(hasTransitionalAcceleration, (val) => {
  if (val) startAccelerationPolling();
  else stopAccelerationPolling();
});

onMounted(() => {
  if (hasTransitionalAcceleration.value) startAccelerationPolling();
});

onUnmounted(() => {
  stopAccelerationPolling();
});

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
            当前页启用 {{ enabledCount }}
          </NTag>
          <NTag size="small" :bordered="false">
            当前页类型 {{ recordTypeCount }}
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
          <NButton size="small" type="primary" @click="openCreate">
            <template #icon><Plus :size="14" /></template>
            添加记录
          </NButton>
          <NButton size="small" secondary :loading="refreshing" @click="handleRefresh">
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
              <p class="text-5xl bg-gradient-to-r from-indigo-600 to-violet-600 bg-clip-text text-transparent">{{ totalRecords }}</p>
            </div>
            <div class="mt-3 h-2.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-indigo-500 to-violet-500 rounded-full" :style="{ width: currentPageEnabledRatio + '%' }"></div>
            </div>
            <p class="mt-3 text-xs text-slate-500">
              当前页 {{ currentPageRecordCount }} 条 · 启用 {{ enabledCount }} 条 · 共 {{ totalPages }} 页
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
      <div class="mb-4">
        <p class="bento-section-title">记录列表</p>
        <p class="bento-section-meta">支持批量启用/禁用、批量删除、字段自定义显示</p>
      </div>

      <div v-if="recordsLoading" class="flex justify-center py-20">
        <NSpin size="large" />
      </div>

      <DNSRecordTable
        v-else
        :records="visibleTableRecords"
        :page="currentPage"
        :page-size="currentPageSize"
        :total="totalRecords"
        :total-pages="totalPages"
        :page-size-options="pageSizeOptions"
        :lines="lines"
        :min-ttl="minTTL"
        :capabilities="capabilities"
        :update-loading-ids="updatingRecordIds"
        :delete-loading-ids="deletingRecordIds"
        :status-loading-ids="statusChangingRecordIds"
        :acceleration-loading-ids="accelerationChangingRecordIds"
        :batch-status-loading="batchStatusLoading"
        :batch-delete-loading="batchDeleteLoading"
        @edit="handleEditRecord"
        @delete="handleDelete"
        @status-change="handleStatusChange"
        @batch-delete="handleBatchDelete"
        @batch-status-change="handleBatchStatusChange"
        @page-change="handlePageChange"
        @page-size-change="handlePageSizeChange"
        @pause-acceleration="handlePauseAcceleration"
        @resume-acceleration="handleResumeAcceleration"
        @restore-origin="handleRestoreOrigin"
      />
    </section>

    <QuickAddForm
      v-model:show="showAddDialog"
      :mode="editingRecord ? 'edit' : 'create'"
      :initial-record="editingRecord"
      :lines="lines"
      :min-ttl="minTTL"
      :loading="editorSaving"
      :zone-id="zoneId"
      :zone-name="zoneName"
      :acceleration-state="editingRecord?.acceleration || null"
      :default-open-acceleration="editorDefaultOpenAcceleration"
      :needs-restore-input="editorNeedsRestoreInput"
      @submit="handleSubmit"
    />
  </div>
</template>
