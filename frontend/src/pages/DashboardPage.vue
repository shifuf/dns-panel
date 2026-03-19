<script setup lang="ts">
import { ref, computed, watch, h, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NDataTable, NInput, NButton, NTag, NEmpty, NSpin, NPagination, NSelect, NDrawer, NModal, NSwitch, useMessage, useDialog } from 'naive-ui';
import { Search, RefreshCw, Plus, Trash2, Download, ArrowUpDown, ShieldCheck, AlertTriangle, Clock3, Layers3, Tag, Check } from 'lucide-vue-next';
import type { DataTableColumns } from 'naive-ui';
import { useProviderStore } from '@/stores/provider';
import { useBreadcrumbStore } from '@/stores/breadcrumb';
import { useResponsive } from '@/composables/useResponsive';
import { getDomains, refreshDomains, deleteZone } from '@/services/domains';
import { getLogs } from '@/services/logs';
import { lookupDomainExpiry } from '@/services/domainExpiry';
import { listEsaSites, ESA_SUPPORTED_REGIONS } from '@/services/aliyunEsa';
import { listAccelerationConfigs, type DomainAccelerationConfig } from '@/services/accelerations';
import {
  runDomainInspection,
  listSyncJobs,
  retrySyncJob,
  listAlertRules,
  upsertAlertRule,
  listAlertEvents,
  acknowledgeAlertEvent,
  listDashboardViews,
  createDashboardView,
  deleteDashboardView,
  listDomainTags,
  upsertDomainTags,
  type SyncJob,
  type AlertRule,
  type AlertEvent,
  type DashboardViewPreset,
  type DomainTagEntry,
} from '@/services/dashboard';
import { getStoredUser } from '@/services/auth';
import { formatRelativeTime } from '@/utils/formatters';
import { TABLE_PAGE_SIZE } from '@/utils/constants';
import type { Domain, Log } from '@/types';
import type { ProviderType } from '@/types/dns';
import { getProviderDisplayName } from '@/utils/provider';
import ProviderAccountTabs from '@/components/Dashboard/ProviderAccountTabs.vue';
import AddEsaSiteDialog from '@/components/Dashboard/AddEsaSiteDialog.vue';
import AddDnsCredentialDialog from '@/components/Dashboard/AddDnsCredentialDialog.vue';

const router = useRouter();
const route = useRoute();
const queryClient = useQueryClient();
const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const message = useMessage();
const dialog = useDialog();
const { isMobile } = useResponsive();

const DASHBOARD_SYNC_TASKS_KEY = 'dns_dashboard_sync_tasks';
const DASHBOARD_ALERT_RULES_KEY = 'dns_dashboard_alert_rules';
const DASHBOARD_ALERT_EVENTS_KEY = 'dns_dashboard_alert_events';
const DASHBOARD_VIEWS_KEY = 'dns_dashboard_saved_views';
const DASHBOARD_TAGS_KEY = 'dns_dashboard_domain_tags';

const search = ref('');
const expandedId = ref<string | null>(null);
const currentPage = ref(1);
const pageSize = TABLE_PAGE_SIZE;
const showAddEsa = ref(false);
const showAddCredential = ref(false);
const panelMode = ref<'dns' | 'esa'>('dns');
const quickFilter = ref<'all' | 'active' | 'issue' | 'expiring' | 'recent'>('all');
const sortBy = ref<'updatedAt' | 'name' | 'status'>('updatedAt');
const sortOrder = ref<'asc' | 'desc'>('desc');
const lastRefreshedAt = ref<number | null>(null);
const selectedRowKeys = ref<string[]>([]);
const selectedTagFilter = ref<string | null>(null);
const selectedViewId = ref<string | null>(null);
const showSyncCenter = ref(false);
const showAlertCenter = ref(false);
const showAuditCenter = ref(false);
const showTagCenter = ref(false);
const showSaveViewModal = ref(false);
const newViewName = ref('');
const activeTagDomain = ref('');
const tagInput = ref('');

const sortOptions = [
  { label: '按更新时间', value: 'updatedAt' },
  { label: '按域名', value: 'name' },
  { label: '按状态', value: 'status' },
];

const localSyncTasks = ref<SyncJob[]>([]);
const localAlertRules = ref<AlertRule[]>([]);
const localAlertEvents = ref<AlertEvent[]>([]);
const localSavedViews = ref<DashboardViewPreset[]>([]);
const localDomainTags = ref<Record<string, string[]>>({});

const DEFAULT_ALERT_RULES: AlertRule[] = [
  {
    id: 'local-rule-status-issue',
    name: '异常状态告警',
    enabled: true,
    type: 'status_issue',
    threshold: 1,
    channels: ['inapp'],
    createdAt: new Date().toISOString(),
  },
  {
    id: 'local-rule-expiry-warning',
    name: '到期预警告警',
    enabled: true,
    type: 'expiry_warning',
    threshold: 7,
    channels: ['inapp'],
    createdAt: new Date().toISOString(),
  },
  {
    id: 'local-rule-sync-failure',
    name: '同步失败告警',
    enabled: true,
    type: 'sync_failure',
    threshold: 1,
    channels: ['inapp'],
    createdAt: new Date().toISOString(),
  },
];

function readJsonStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeJsonStorage(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {}
}

function getDomainRowKey(domain: Domain): string {
  return `${domain.id}::${domain.credentialId ?? 'none'}::${domain.provider ?? 'none'}`;
}

function normalizeLogPayload(payload: any): Log[] {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.logs)) return payload.logs;
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
}

const HEALTHY_STATUS = new Set([
  'active', 'online', 'healthy', 'enabled', 'enable', 'normal', 'ok', 'success', 'running', 'available', 'valid',
]);
const ISSUE_STATUS = new Set([
  'offline', 'paused', 'suspended', 'disabled', 'disable', 'inactive', 'error', 'failed', 'fail',
  'moved', 'blocked', 'abnormal', 'down', 'expired',
]);
const WARNING_STATUS = new Set(['pending', 'initializing', 'processing', 'verifying']);

function normalizeStatus(status: string | undefined | null): string {
  return String(status || '').trim().toLowerCase();
}

function isDomainIssue(domain: Domain): boolean {
  const s = normalizeStatus(domain.status);
  if (!s || s === '-' || s === 'unknown') return false;
  if (ISSUE_STATUS.has(s)) return true;
  if (HEALTHY_STATUS.has(s) || WARNING_STATUS.has(s)) return false;
  if (s.includes('error') || s.includes('fail') || s.includes('down')) return true;
  return false;
}

function isDomainHealthy(domain: Domain): boolean {
  const s = normalizeStatus(domain.status);
  if (!s || s === '-' || s === 'unknown') return true;
  if (HEALTHY_STATUS.has(s)) return true;
  if (ISSUE_STATUS.has(s)) return false;
  if (WARNING_STATUS.has(s)) return true;
  if (s.includes('error') || s.includes('fail') || s.includes('down')) return false;
  return true;
}

const isAllScope = computed(() =>
  (route.query.scope === 'all' || !providerStore.selectedProvider) && !providerStore.selectedProvider
);
const isEsaPanel = computed(() => panelMode.value === 'esa' && providerStore.selectedProvider === 'aliyun');

// Resolve credentials for query
const effectiveCredentialId = computed<number | 'all' | null>(() => {
  if (isAllScope.value) return 'all';
  return providerStore.selectedCredentialId;
});

const isZoneManageProvider = computed(() => {
  const p = providerStore.selectedProvider;
  return p === 'cloudflare' || p === 'aliyun' || p === 'namesilo' || p === 'spaceship';
});

const scopedCredentials = computed(() => {
  if (providerStore.selectedProvider) {
    return providerStore.getCredentialsByProvider(providerStore.selectedProvider);
  }
  return providerStore.credentials;
});

const selectedProviderName = computed(() => {
  if (!providerStore.selectedProvider) return '';
  const mapped = getProviderDisplayName(providerStore.selectedProvider);
  const configName = providerStore.providers.find((p) => p.type === providerStore.selectedProvider)?.name;
  return mapped || configName || providerStore.selectedProvider;
});

const dashboardTitle = computed(() =>
  selectedProviderName.value ? `${selectedProviderName.value}域名管理` : '域名管理总览'
);

const addDialogCredentials = computed(() => {
  if (!providerStore.selectedProvider) return providerStore.credentials;
  return providerStore.getCredentialsByProvider(providerStore.selectedProvider);
});

const addInitialCredId = computed<number | undefined>(() => {
  if (typeof providerStore.selectedCredentialId === 'number') return providerStore.selectedCredentialId;
  return addDialogCredentials.value[0]?.id;
});

// Domain data query
const { data: domainsData, isLoading, refetch } = useQuery({
  queryKey: computed(() => ['domains', providerStore.selectedProvider, effectiveCredentialId.value, isEsaPanel.value]),
  queryFn: async () => {
    if (isEsaPanel.value) {
      const creds = effectiveCredentialId.value === 'all'
        ? providerStore.getCredentialsByProvider('aliyun')
        : providerStore.credentials.filter(c => c.id === effectiveCredentialId.value);

      const allSites: Domain[] = [];
      const seen = new Set<string>();

      for (const cred of creds) {
        for (const region of ESA_SUPPORTED_REGIONS) {
          let page = 1;
          while (true) {
            const res = await listEsaSites({ credentialId: cred.id, region, page, pageSize: 100 });
            const sites = res.data?.sites || [];
            for (const s of sites) {
              if (!seen.has(s.siteId)) {
                seen.add(s.siteId);
                allSites.push({
                  id: s.siteId,
                  name: s.siteName,
                  status: s.status || 'unknown',
                  credentialId: cred.id,
                  provider: 'aliyun',
                  region: s.region || region,
                  accessType: s.accessType,
                  coverage: s.coverage,
                  instanceId: s.instanceId,
                  planName: s.planName,
                  planSpecName: s.planSpecName,
                  updatedAt: s.updateTime,
                  tags: s.tags,
                });
              }
            }
            if (sites.length < 100) break;
            page++;
          }
        }
      }
      return allSites;
    }

    // DNS mode
    const credId = effectiveCredentialId.value;
    if (credId === 'all') {
      const creds = scopedCredentials.value;
      const all: Domain[] = [];
      for (const cred of creds) {
        const res = await getDomains(cred.id);
        const domains = (res.data?.domains || []).map(d => ({
          ...d,
          credentialId: cred.id,
          credentialName: cred.name,
          provider: cred.provider,
        }));
        all.push(...domains);
      }
      return all;
    }
    if (typeof credId === 'number') {
      const cred = providerStore.credentials.find(c => c.id === credId);
      const res = await getDomains(credId);
      return (res.data?.domains || []).map(d => ({
        ...d,
        credentialId: credId,
        credentialName: cred?.name,
        provider: cred?.provider,
      }));
    }
    return [];
  },
  enabled: computed(() => !providerStore.isLoading),
});

const domains = computed(() => domainsData.value || []);

onMounted(() => {
  localSyncTasks.value = readJsonStorage<SyncJob[]>(DASHBOARD_SYNC_TASKS_KEY, []);
  localAlertRules.value = readJsonStorage<AlertRule[]>(DASHBOARD_ALERT_RULES_KEY, DEFAULT_ALERT_RULES);
  localAlertEvents.value = readJsonStorage<AlertEvent[]>(DASHBOARD_ALERT_EVENTS_KEY, []);
  localSavedViews.value = readJsonStorage<DashboardViewPreset[]>(DASHBOARD_VIEWS_KEY, []);
  localDomainTags.value = readJsonStorage<Record<string, string[]>>(DASHBOARD_TAGS_KEY, {});
});

watch(localSyncTasks, (v) => writeJsonStorage(DASHBOARD_SYNC_TASKS_KEY, v), { deep: true });
watch(localAlertRules, (v) => writeJsonStorage(DASHBOARD_ALERT_RULES_KEY, v), { deep: true });
watch(localAlertEvents, (v) => writeJsonStorage(DASHBOARD_ALERT_EVENTS_KEY, v), { deep: true });
watch(localSavedViews, (v) => writeJsonStorage(DASHBOARD_VIEWS_KEY, v), { deep: true });
watch(localDomainTags, (v) => writeJsonStorage(DASHBOARD_TAGS_KEY, v), { deep: true });

const { data: logs24hData } = useQuery({
  queryKey: computed(() => ['dashboard-logs-24h', providerStore.selectedProvider]),
  queryFn: async () => {
    try {
      const startDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const res = await getLogs({
        page: 1,
        limit: 300,
        startDate,
      });
      return normalizeLogPayload(res.data as any);
    } catch {
      return [] as Log[];
    }
  },
});

const { data: remoteSyncJobsData, refetch: refetchRemoteSyncJobs } = useQuery({
  queryKey: ['dashboard-sync-jobs'],
  queryFn: async () => {
    try {
      const res = await listSyncJobs({ page: 1, limit: 100 });
      return res.data?.jobs || [];
    } catch {
      return [] as SyncJob[];
    }
  },
});

const { data: remoteAlertRulesData } = useQuery({
  queryKey: ['dashboard-alert-rules'],
  queryFn: async () => {
    try {
      const res = await listAlertRules();
      return res.data?.rules || [];
    } catch {
      return [] as AlertRule[];
    }
  },
});

const { data: remoteAlertEventsData } = useQuery({
  queryKey: ['dashboard-alert-events'],
  queryFn: async () => {
    try {
      const res = await listAlertEvents({ status: 'open', limit: 100 });
      return res.data?.events || [];
    } catch {
      return [] as AlertEvent[];
    }
  },
});

const { data: remoteSavedViewsData } = useQuery({
  queryKey: ['dashboard-saved-views'],
  queryFn: async () => {
    try {
      const res = await listDashboardViews();
      return res.data?.views || [];
    } catch {
      return [] as DashboardViewPreset[];
    }
  },
});

const { data: remoteDomainTagsData } = useQuery({
  queryKey: ['dashboard-domain-tags'],
  queryFn: async () => {
    try {
      const res = await listDomainTags();
      return res.data?.items || [];
    } catch {
      return [] as DomainTagEntry[];
    }
  },
});

const { data: auditLogsData } = useQuery({
  queryKey: ['dashboard-audit-list'],
  queryFn: async () => {
    try {
      const res = await getLogs({ page: 1, limit: 120 });
      return normalizeLogPayload(res.data as any);
    } catch {
      return [] as Log[];
    }
  },
});

const { data: accelerationConfigsData } = useQuery({
  queryKey: ['acceleration-configs-dashboard'],
  queryFn: async () => {
    try {
      const res = await listAccelerationConfigs();
      return res.data?.items || [];
    } catch {
      return [] as DomainAccelerationConfig[];
    }
  },
});

const logs24h = computed<Log[]>(() => logs24hData.value || []);
const auditLogs = computed<Log[]>(() => auditLogsData.value || []);
const remoteSyncJobs = computed<SyncJob[]>(() => remoteSyncJobsData.value || []);
const remoteAlertRules = computed<AlertRule[]>(() => remoteAlertRulesData.value || []);
const remoteAlertEvents = computed<AlertEvent[]>(() => remoteAlertEventsData.value || []);
const remoteSavedViews = computed<DashboardViewPreset[]>(() => remoteSavedViewsData.value || []);
const remoteTagItems = computed<DomainTagEntry[]>(() => remoteDomainTagsData.value || []);
const accelerationConfigs = computed<DomainAccelerationConfig[]>(() => accelerationConfigsData.value || []);

function getAccelerationKey(domain: Domain): string {
  return `${domain.credentialId ?? 'none'}::${String(domain.name || '').toLowerCase()}`;
}

const accelerationConfigMap = computed(() => {
  const map = new Map<string, DomainAccelerationConfig>();
  for (const item of accelerationConfigs.value) {
    map.set(`${item.dnsCredentialId}::${String(item.zoneName || '').toLowerCase()}`, item);
  }
  return map;
});

function getAccelerationConfig(domain: Domain): DomainAccelerationConfig | null {
  return accelerationConfigMap.value.get(getAccelerationKey(domain)) || null;
}

function getAccelerationLabel(domain: Domain): string {
  const config = getAccelerationConfig(domain);
  if (!config) return '未接入';
  if (config.verified) return '已验证';
  if (config.lastError) return '异常';
  return '待验证';
}

function getAccelerationType(domain: Domain): 'success' | 'warning' | 'error' | 'default' {
  const config = getAccelerationConfig(domain);
  if (!config) return 'default';
  if (config.verified) return 'success';
  if (config.lastError) return 'error';
  return 'warning';
}

const mergedSyncJobs = computed<SyncJob[]>(() => {
  const map = new Map<string, SyncJob>();
  for (const item of remoteSyncJobs.value) map.set(item.id, item);
  for (const item of localSyncTasks.value) {
    if (!map.has(item.id)) map.set(item.id, item);
  }
  return Array.from(map.values()).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
});

const mergedAlertRules = computed<AlertRule[]>(() => {
  const map = new Map<string, AlertRule>();
  for (const item of remoteAlertRules.value) map.set(item.id, item);
  for (const item of localAlertRules.value) {
    if (!map.has(item.id)) map.set(item.id, item);
  }
  return Array.from(map.values());
});

const mergedAlertEvents = computed<AlertEvent[]>(() => {
  const map = new Map<string, AlertEvent>();
  for (const item of remoteAlertEvents.value) map.set(item.id, item);
  for (const item of localAlertEvents.value) {
    if (!map.has(item.id)) map.set(item.id, item);
  }
  return Array.from(map.values()).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
});

const mergedSavedViews = computed<DashboardViewPreset[]>(() => {
  const map = new Map<string, DashboardViewPreset>();
  for (const item of remoteSavedViews.value) map.set(item.id, item);
  for (const item of localSavedViews.value) {
    if (!map.has(item.id)) map.set(item.id, item);
  }
  return Array.from(map.values()).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
});

const domainTagsMap = computed<Record<string, string[]>>(() => {
  const next: Record<string, string[]> = { ...localDomainTags.value };
  for (const row of remoteTagItems.value) {
    next[row.domain] = Array.isArray(row.tags) ? row.tags : [];
  }
  return next;
});

const allTagOptions = computed(() => {
  const set = new Set<string>();
  for (const tags of Object.values(domainTagsMap.value)) {
    for (const t of tags) {
      if (t) set.add(t);
    }
  }
  return Array.from(set).sort((a, b) => a.localeCompare(b, 'zh-CN')).map((item) => ({ label: item, value: item }));
});

const viewOptions = computed(() =>
  mergedSavedViews.value.map((v) => ({ label: v.name, value: v.id })),
);

const selectedDomains = computed(() => {
  const set = new Set(selectedRowKeys.value);
  return sortedDomains.value.filter((d) => set.has(getDomainRowKey(d)));
});

const recentUpdatedCount = computed(() => {
  const threshold = Date.now() - 24 * 60 * 60 * 1000;
  return domains.value.filter((d) => {
    const ts = d.updatedAt ? Date.parse(d.updatedAt) : NaN;
    return Number.isFinite(ts) && ts >= threshold;
  }).length;
});

watch(domainsData, (data) => {
  if (data) lastRefreshedAt.value = Date.now();
});

// Search filter
const filteredDomains = computed(() => {
  const filteredByQuick = domains.value.filter((d) => {
    if (quickFilter.value === 'active') return isDomainHealthy(d);
    if (quickFilter.value === 'issue') return isDomainIssue(d);
    if (quickFilter.value === 'recent') {
      const ts = d.updatedAt ? Date.parse(d.updatedAt) : NaN;
      if (!Number.isFinite(ts)) return false;
      return ts >= Date.now() - 24 * 60 * 60 * 1000;
    }
    if (quickFilter.value === 'expiring') {
      const days = expiryDaysMap.value.get(d.name);
      return typeof days === 'number' && days >= 0 && days <= 14;
    }
    return true;
  });
  const filteredByTag = selectedTagFilter.value
    ? filteredByQuick.filter((d) => getDomainTags(d.name).includes(selectedTagFilter.value as string))
    : filteredByQuick;
  if (!search.value) return filteredByTag;
  const q = search.value.toLowerCase();
  return filteredByTag.filter(d => d.name.toLowerCase().includes(q));
});

const sortedDomains = computed(() => {
  const list = [...filteredDomains.value];

  list.sort((a, b) => {
    if (sortBy.value === 'name') {
      const cmp = a.name.localeCompare(b.name, 'zh-CN');
      return sortOrder.value === 'asc' ? cmp : -cmp;
    }

    if (sortBy.value === 'status') {
      const levelA = isDomainIssue(a) ? 2 : isDomainHealthy(a) ? 0 : 1;
      const levelB = isDomainIssue(b) ? 2 : isDomainHealthy(b) ? 0 : 1;
      if (levelA !== levelB) {
        return sortOrder.value === 'asc' ? levelA - levelB : levelB - levelA;
      }
      const statusCmp = normalizeStatus(a.status).localeCompare(normalizeStatus(b.status), 'zh-CN');
      return sortOrder.value === 'asc' ? statusCmp : -statusCmp;
    }

    const ta = a.updatedAt ? Date.parse(a.updatedAt) : NaN;
    const tb = b.updatedAt ? Date.parse(b.updatedAt) : NaN;
    const safeA = Number.isFinite(ta) ? ta : 0;
    const safeB = Number.isFinite(tb) ? tb : 0;
    return sortOrder.value === 'asc' ? safeA - safeB : safeB - safeA;
  });

  return list;
});

// Pagination
const paginatedDomains = computed(() => {
  const start = (currentPage.value - 1) * pageSize;
  return sortedDomains.value.slice(start, start + pageSize);
});

const activeDomainCount = computed(() =>
  domains.value.filter((d) => isDomainHealthy(d)).length,
);

const issueDomainCount = computed(() =>
  domains.value.filter((d) => isDomainIssue(d)).length,
);

const providerCount = computed(() =>
  new Set(
    domains.value
      .map(d => d.provider || d.credentialName || '')
      .filter(Boolean),
  ).size,
);

const providerAvailability = computed(() => {
  const map = new Map<string, { total: number; healthy: number; issue: number }>();
  for (const item of domains.value) {
    const key = item.provider ? getProviderDisplayName(item.provider) : (item.credentialName || 'Unknown');
    const row = map.get(key) || { total: 0, healthy: 0, issue: 0 };
    row.total += 1;
    if (isDomainIssue(item)) row.issue += 1;
    if (isDomainHealthy(item)) row.healthy += 1;
    map.set(key, row);
  }
  return Array.from(map.entries())
    .map(([provider, stat]) => ({
      provider,
      successRate: stat.total ? Math.round((stat.healthy / stat.total) * 100) : 0,
      timeoutRate: stat.total ? Math.round((stat.issue / stat.total) * 100) : 0,
      total: stat.total,
    }))
    .sort((a, b) => b.successRate - a.successRate);
});

// Domain expiry
const domainNames = computed(() => domains.value.map(d => d.name));
const user = getStoredUser();
const expiryDisplayMode = computed(() => user?.domainExpiryDisplayMode || 'date');

const { data: expiryData } = useQuery({
  queryKey: computed(() => ['domainExpiry', domainNames.value]),
  queryFn: () => lookupDomainExpiry(domainNames.value),
  enabled: computed(() => domainNames.value.length > 0),
  staleTime: 600_000,
});

const expiringSoonCount = computed(() => {
  const results = expiryData.value?.data?.results || [];
  return results.filter((r) => {
    if (!r.expiresAt) return false;
    const days = Math.ceil((new Date(r.expiresAt).getTime() - Date.now()) / 86400000);
    return days >= 0 && days <= 14;
  }).length;
});

const expiryDaysMap = computed(() => {
  const map = new Map<string, number>();
  const results = expiryData.value?.data?.results || [];
  for (const item of results) {
    if (!item.expiresAt) continue;
    const days = Math.ceil((new Date(item.expiresAt).getTime() - Date.now()) / 86400000);
    map.set(item.domain, days);
  }
  return map;
});

const expiring7dCount = computed(() => {
  let count = 0;
  for (const days of expiryDaysMap.value.values()) {
    if (days >= 0 && days <= 7) count += 1;
  }
  return count;
});

const expiring30dCount = computed(() => {
  let count = 0;
  for (const days of expiryDaysMap.value.values()) {
    if (days >= 0 && days <= 30) count += 1;
  }
  return count;
});

const riskyChangeCount24h = computed(() =>
  logs24h.value.filter((log) => {
    if (log.action === 'DELETE') return true;
    if (log.action === 'UPDATE') {
      const text = `${log.newValue || ''} ${log.oldValue || ''}`.toLowerCase();
      return text.includes('disable') || text.includes('paused') || text.includes('inactive');
    }
    return false;
  }).length,
);

const recordTypeDistribution = computed(() => {
  const map = new Map<string, number>();
  for (const log of logs24h.value) {
    const type = String(log.recordType || '').trim().toUpperCase();
    if (!type) continue;
    map.set(type, (map.get(type) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
});

function getDomainTags(name: string): string[] {
  return domainTagsMap.value[name] || [];
}

function computeDomainHealthScore(domain: Domain): number {
  let score = 100;
  if (isDomainIssue(domain)) score -= 40;
  if (!isDomainHealthy(domain)) score -= 20;
  const days = expiryDaysMap.value.get(domain.name);
  if (typeof days === 'number') {
    if (days <= 7) score -= 25;
    else if (days <= 30) score -= 12;
  }
  const updatedAt = domain.updatedAt ? Date.parse(domain.updatedAt) : NaN;
  if (Number.isFinite(updatedAt)) {
    const ageDays = (Date.now() - updatedAt) / 86400000;
    if (ageDays > 30) score -= 10;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

const avgHealthScore = computed(() => {
  if (!domains.value.length) return 0;
  const sum = domains.value.reduce((acc, item) => acc + computeDomainHealthScore(item), 0);
  return Math.round(sum / domains.value.length);
});

function getExpiryText(domainName: string): string {
  const results = expiryData.value?.data?.results || [];
  const entry = results.find(r => r.domain === domainName);
  if (!entry?.expiresAt) return '-';
  const d = new Date(entry.expiresAt);
  if (expiryDisplayMode.value === 'days') {
    const days = Math.ceil((d.getTime() - Date.now()) / 86400000);
    return days > 0 ? `${days} 天` : '已过期';
  }
  return d.toLocaleDateString('zh-CN');
}

const lastRefreshText = computed(() => {
  if (!lastRefreshedAt.value) return '未刷新';
  return new Date(lastRefreshedAt.value).toLocaleString('zh-CN', { hour12: false });
});

const syncMetrics24h = computed(() => {
  const threshold = Date.now() - 24 * 60 * 60 * 1000;
  const jobs = mergedSyncJobs.value.filter((item) => {
    const ts = Date.parse(item.createdAt);
    return Number.isFinite(ts) && ts >= threshold;
  });
  const success = jobs.filter((item) => item.status === 'success').length;
  const failed = jobs.filter((item) => item.status === 'failed').length;
  const done = success + failed;
  const avgDuration = jobs
    .map((item) => Number(item.durationMs || 0))
    .filter((n) => Number.isFinite(n) && n > 0);
  const avgDurationMs = avgDuration.length
    ? Math.round(avgDuration.reduce((a, b) => a + b, 0) / avgDuration.length)
    : 0;
  return {
    successRate: done ? Math.round((success / done) * 100) : 100,
    failedCount: failed,
    avgDurationMs,
  };
});

const generatedAlertEvents = computed<AlertEvent[]>(() => {
  const list: AlertEvent[] = [];
  if (issueDomainCount.value > 0) {
    list.push({
      id: `gen-issue-${issueDomainCount.value}`,
      level: issueDomainCount.value > 3 ? 'high' : 'medium',
      status: 'open',
      title: '域名状态异常',
      message: `当前有 ${issueDomainCount.value} 个域名状态异常`,
      createdAt: new Date().toISOString(),
    });
  }
  if (expiring7dCount.value > 0) {
    list.push({
      id: `gen-expiry-${expiring7dCount.value}`,
      level: expiring7dCount.value > 3 ? 'high' : 'medium',
      status: 'open',
      title: '短期到期预警',
      message: `有 ${expiring7dCount.value} 个域名将在 7 天内到期`,
      createdAt: new Date().toISOString(),
    });
  }
  const failedSync = syncMetrics24h.value.failedCount;
  if (failedSync > 0) {
    list.push({
      id: `gen-sync-failed-${failedSync}`,
      level: failedSync > 3 ? 'critical' : 'high',
      status: 'open',
      title: '同步任务失败',
      message: `24 小时内同步失败 ${failedSync} 次`,
      createdAt: new Date().toISOString(),
    });
  }
  return list;
});

const pendingAlertCount = computed(() =>
  [...mergedAlertEvents.value, ...generatedAlertEvents.value].filter((item) => item.status === 'open').length,
);

const displayAlertEvents = computed<AlertEvent[]>(() =>
  [...mergedAlertEvents.value, ...generatedAlertEvents.value]
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .slice(0, 50),
);

function toggleSortOrder() {
  sortOrder.value = sortOrder.value === 'asc' ? 'desc' : 'asc';
}

function escapeCsvCell(value: string | number | null | undefined): string {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function exportFilteredDomainsCsv() {
  const rows = sortedDomains.value;
  if (rows.length === 0) {
    message.warning('当前没有可导出的域名');
    return;
  }

  const header = ['域名', '状态', '账户', '服务商', '更新时间', '到期时间', '记录数'];
  const lines = [header.map(escapeCsvCell).join(',')];
  for (const row of rows) {
    const providerName = row.provider ? getProviderDisplayName(row.provider) : '';
    lines.push(
      [
        row.name,
        row.status || 'unknown',
        row.credentialName || '-',
        providerName || row.provider || '-',
        row.updatedAt || '-',
        getExpiryText(row.name),
        row.recordCount ?? '-',
      ].map(escapeCsvCell).join(','),
    );
  }

  const csv = `\uFEFF${lines.join('\n')}`;
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dns-domains-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  message.success(`已导出 ${rows.length} 条域名`);
}

function startLocalSyncTask(partial: Partial<SyncJob> & { scope: SyncJob['scope'] }): string {
  const id = `local-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const task: SyncJob = {
    id,
    status: 'running',
    scope: partial.scope,
    provider: partial.provider ?? null,
    credentialId: partial.credentialId ?? null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  localSyncTasks.value = [task, ...localSyncTasks.value].slice(0, 150);
  return id;
}

function finishLocalSyncTask(id: string, data: { status: 'success' | 'failed'; durationMs?: number; error?: string }) {
  localSyncTasks.value = localSyncTasks.value.map((item) => {
    if (item.id !== id) return item;
    return {
      ...item,
      status: data.status,
      durationMs: data.durationMs ?? item.durationMs,
      error: data.error,
      updatedAt: new Date().toISOString(),
    };
  });
}

async function handleOneClickInspection() {
  const target = selectedDomains.value.length ? selectedDomains.value : sortedDomains.value;
  if (!target.length) {
    message.warning('当前没有可巡检的域名');
    return;
  }

  const taskId = startLocalSyncTask({
    scope: selectedDomains.value.length ? 'credential' : (providerStore.selectedProvider ? 'provider' : 'all'),
    provider: providerStore.selectedProvider ?? null,
    credentialId: typeof effectiveCredentialId.value === 'number' ? effectiveCredentialId.value : null,
  });
  const begin = Date.now();

  try {
    let issues = 0;
    try {
      const res = await runDomainInspection({
        provider: providerStore.selectedProvider ?? undefined,
        credentialId: effectiveCredentialId.value,
        domains: target.map((d) => d.name),
      });
      issues = Number(res.data?.issues || 0);
    } catch {
      issues = target.filter((d) => isDomainIssue(d)).length;
    }

    const durationMs = Date.now() - begin;
    finishLocalSyncTask(taskId, { status: 'success', durationMs });
    if (issues > 0) {
      localAlertEvents.value = [
        {
          id: `inspect-${Date.now()}`,
          level: issues > 3 ? 'high' : 'medium',
          status: 'open',
          title: '巡检发现异常',
          message: `本次巡检发现 ${issues} 个异常域名`,
          createdAt: new Date().toISOString(),
        },
        ...localAlertEvents.value,
      ].slice(0, 200);
    }
    message.success(`巡检完成，检测 ${target.length} 个域名，异常 ${issues} 个`);
    await refetchRemoteSyncJobs();
  } catch (err: any) {
    finishLocalSyncTask(taskId, { status: 'failed', durationMs: Date.now() - begin, error: String(err) });
    message.error(`巡检失败: ${String(err)}`);
  }
}

async function handleBatchRefresh() {
  const target = selectedDomains.value.length ? selectedDomains.value : paginatedDomains.value;
  if (!target.length) {
    message.warning('请先选择域名');
    return;
  }
  const credIds = Array.from(new Set(target.map((d) => d.credentialId).filter((x): x is number => typeof x === 'number')));
  if (!credIds.length && typeof effectiveCredentialId.value !== 'number') {
    message.warning('批量同步需要可用的账户上下文');
    return;
  }

  const taskId = startLocalSyncTask({
    scope: providerStore.selectedProvider ? 'provider' : 'all',
    provider: providerStore.selectedProvider ?? null,
    credentialId: typeof effectiveCredentialId.value === 'number' ? effectiveCredentialId.value : null,
  });
  const begin = Date.now();
  try {
    if (credIds.length) {
      await Promise.all(credIds.map((id) => refreshDomains(id)));
    } else if (typeof effectiveCredentialId.value === 'number') {
      await refreshDomains(effectiveCredentialId.value);
    }
    await refetch();
    finishLocalSyncTask(taskId, { status: 'success', durationMs: Date.now() - begin });
    message.success(`已同步 ${target.length} 个域名所属账户`);
    await refetchRemoteSyncJobs();
  } catch (err: any) {
    finishLocalSyncTask(taskId, { status: 'failed', durationMs: Date.now() - begin, error: String(err) });
    message.error(`批量同步失败: ${String(err)}`);
  }
}

function confirmBatchDelete() {
  const target = selectedDomains.value;
  if (!target.length) {
    message.warning('请先勾选要删除的域名');
    return;
  }

  dialog.warning({
    title: '确认批量删除',
    content: `将删除 ${target.length} 个域名，此操作不可恢复，是否继续？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      let success = 0;
      let failed = 0;
      for (const item of target) {
        if (!item.credentialId) continue;
        try {
          await deleteZone(item.credentialId, item.id);
          success += 1;
        } catch {
          failed += 1;
        }
      }
      selectedRowKeys.value = [];
      await refetch();
      if (failed === 0) message.success(`已删除 ${success} 个域名`);
      else message.warning(`删除完成，成功 ${success}，失败 ${failed}`);
    },
  });
}

function upsertDomainTag(domainName: string, tags: string[]) {
  const unique = Array.from(new Set(tags.map((t) => t.trim()).filter(Boolean)));
  localDomainTags.value = {
    ...localDomainTags.value,
    [domainName]: unique,
  };
  upsertDomainTags({ domain: domainName, tags: unique }).catch(() => {});
}

function addTagForActiveDomain() {
  const domainName = activeTagDomain.value.trim();
  const nextTag = tagInput.value.trim();
  if (!domainName || !nextTag) return;
  const current = getDomainTags(domainName);
  upsertDomainTag(domainName, [...current, nextTag]);
  tagInput.value = '';
}

function removeTagForDomain(domainName: string, tag: string) {
  const current = getDomainTags(domainName);
  upsertDomainTag(domainName, current.filter((item) => item !== tag));
}

function openTagCenter(domainName?: string) {
  activeTagDomain.value = domainName || sortedDomains.value[0]?.name || '';
  showTagCenter.value = true;
}

function handleCheckedRowKeys(keys: Array<string | number>) {
  selectedRowKeys.value = keys.map((item) => String(item));
}

function openSaveCurrentViewModal() {
  newViewName.value = '';
  showSaveViewModal.value = true;
}

async function saveCurrentView() {
  const name = newViewName.value.trim();
  if (!name) {
    message.warning('请输入视图名称');
    return;
  }
  const payload = {
    search: search.value,
    quickFilter: quickFilter.value,
    sortBy: sortBy.value,
    sortOrder: sortOrder.value,
    selectedTagFilter: selectedTagFilter.value,
    panelMode: panelMode.value,
  };
  const localView: DashboardViewPreset = {
    id: `local-view-${Date.now()}`,
    name,
    payload,
    createdAt: new Date().toISOString(),
  };
  localSavedViews.value = [localView, ...localSavedViews.value].slice(0, 40);
  showSaveViewModal.value = false;
  message.success('已保存视图');
  createDashboardView({ name, payload }).catch(() => {});
}

async function deleteView(viewId: string) {
  localSavedViews.value = localSavedViews.value.filter((item) => item.id !== viewId);
  if (selectedViewId.value === viewId) selectedViewId.value = null;
  await deleteDashboardView(viewId).catch(() => {});
  message.success('视图已删除');
}

async function retryRemoteSync(jobId: string) {
  try {
    await retrySyncJob(jobId);
    await refetchRemoteSyncJobs();
    message.success('已重试同步任务');
  } catch (err: any) {
    message.error(`重试失败: ${String(err)}`);
  }
}

async function ackAlert(eventId: string) {
  localAlertEvents.value = localAlertEvents.value.map((item) =>
    item.id === eventId ? { ...item, status: 'acknowledged' } : item,
  );
  try {
    await acknowledgeAlertEvent(eventId);
  } catch {}
}

async function toggleRuleEnabled(rule: AlertRule, enabled: boolean) {
  localAlertRules.value = localAlertRules.value.map((item) =>
    item.id === rule.id ? { ...item, enabled } : item,
  );
  try {
    await upsertAlertRule({
      id: rule.id,
      name: rule.name,
      type: rule.type,
      enabled,
      threshold: rule.threshold,
      channels: rule.channels,
    });
  } catch {}
}

// Refresh
async function handleRefresh() {
  const taskId = startLocalSyncTask({
    scope: providerStore.selectedProvider ? 'provider' : 'all',
    provider: providerStore.selectedProvider ?? null,
    credentialId: typeof effectiveCredentialId.value === 'number' ? effectiveCredentialId.value : null,
  });
  const begin = Date.now();
  try {
    if (!isEsaPanel.value && typeof effectiveCredentialId.value === 'number') {
      await refreshDomains(effectiveCredentialId.value);
    } else if (!isEsaPanel.value && effectiveCredentialId.value === 'all') {
      await Promise.all(scopedCredentials.value.map(c => refreshDomains(c.id)));
    }
    await refetch();
    lastRefreshedAt.value = Date.now();
    finishLocalSyncTask(taskId, { status: 'success', durationMs: Date.now() - begin });
    await refetchRemoteSyncJobs();
    message.success('已刷新');
  } catch (err: any) {
    finishLocalSyncTask(taskId, { status: 'failed', durationMs: Date.now() - begin, error: String(err) });
    message.error(String(err));
  }
}

// Delete zone
const deleteMutation = useMutation({
  mutationFn: (vars: { credentialId: number; zoneId: string }) => deleteZone(vars.credentialId, vars.zoneId),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['domains'] });
    message.success('域名已删除');
  },
  onError: (err: any) => message.error(String(err)),
});

function confirmDeleteZone(domain: Domain) {
  dialog.warning({
    title: '确认删除',
    content: `确定要删除域名 ${domain.name} 吗？此操作不可恢复。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: () => {
      if (domain.credentialId) {
        deleteMutation.mutate({ credentialId: domain.credentialId, zoneId: domain.id });
      }
    },
  });
}

// Status config
function getStatusType(status: string): 'success' | 'warning' | 'error' | 'info' | 'default' {
  const map: Record<string, 'success' | 'warning' | 'error' | 'info' | 'default'> = {
    active: 'success', pending: 'warning', initializing: 'info', moved: 'error',
    online: 'success', offline: 'error', paused: 'warning',
    enabled: 'success', enable: 'success', normal: 'success', ok: 'success', success: 'success', running: 'success',
    disabled: 'error', inactive: 'error', failed: 'error', fail: 'error', error: 'error',
    unknown: 'default',
  };
  return map[normalizeStatus(status)] || 'default';
}

// Navigate to domain
function goToDomain(domain: Domain) {
  const rawId = String(domain.id ?? '').trim();
  if (!rawId) return;

  const credId = typeof domain.credentialId === 'number' && Number.isFinite(domain.credentialId)
    ? domain.credentialId
    : undefined;
  const query = credId !== undefined ? { credentialId: String(credId) } : {};

  if (isEsaPanel.value) {
    // ESA domains expand inline
    expandedId.value = expandedId.value === rawId ? null : rawId;
    return;
  }

  // Ensure provider/credential context is aligned before entering detail page.
  if (credId !== undefined) {
    const cred = providerStore.credentials.find(c => c.id === credId);
    const provider = (cred?.provider ?? domain.provider) as ProviderType | undefined;
    if (provider) providerStore.selectProvider(provider);
    providerStore.selectCredential(credId);
  } else if (domain.provider) {
    providerStore.selectProvider(domain.provider);
  }

  breadcrumbStore.setLabel(`zone:${rawId}`, domain.name);
  router.push({ name: 'DomainDetail', params: { zoneId: rawId }, query });
}

function goToAddCredential() {
  showAddCredential.value = true;
}

// Table columns for desktop
const columns = computed<DataTableColumns<Domain>>(() => {
  const cols: DataTableColumns<Domain> = [
    {
      type: 'selection',
      width: 46,
      fixed: 'left',
    },
    {
      title: '域名',
      key: 'name',
      minWidth: 200,
      render(row) {
        return h('button', {
          class: 'text-left text-accent hover:text-accent-hover font-medium transition-colors',
          onClick: () => goToDomain(row),
        }, row.name);
      },
    },
    {
      title: '健康分',
      key: 'healthScore',
      width: 96,
      render(row) {
        const score = computeDomainHealthScore(row);
        const type = score >= 85 ? 'success' : score >= 65 ? 'warning' : 'error';
        return h(NTag, {
          type,
          size: 'small',
          bordered: false,
        }, () => `${score}`);
      },
    },
    {
      title: '标签',
      key: 'tags',
      minWidth: 160,
      render(row) {
        const tags = getDomainTags(row.name);
        const children: any[] = tags.slice(0, 2).map((item) =>
          h(NTag, { size: 'small', bordered: false, style: { marginRight: '4px' } }, () => item),
        );
        if (tags.length > 2) {
          children.push(h('span', { class: 'text-xs text-slate-500' }, `+${tags.length - 2}`));
        }
        children.push(h(NButton, {
          text: true,
          size: 'small',
          onClick: (e: Event) => { e.stopPropagation(); openTagCenter(row.name); },
        }, { icon: () => h(Tag, { size: 12 }) }));
        return h('div', { class: 'flex items-center flex-wrap gap-1' }, children);
      },
    },
  ];

  if (effectiveCredentialId.value === 'all') {
    cols.push({
      title: '账户',
      key: 'credentialName',
      width: 140,
      render(row) {
        return h('span', { class: 'text-slate-400 text-sm' }, row.credentialName || '-');
      },
    });
  }

  cols.push(
    {
      title: '状态',
      key: 'status',
      width: 100,
      render(row) {
        return h(NTag, {
          type: getStatusType(row.status),
          size: 'small',
          bordered: false,
        }, () => row.status);
      },
    },
  );

  if (!isEsaPanel.value) {
    cols.push({
      title: '加速',
      key: 'acceleration',
      width: 110,
      render(row) {
        return h(NTag, {
          type: getAccelerationType(row),
          size: 'small',
          bordered: false,
        }, () => getAccelerationLabel(row));
      },
    });
  }

  cols.push(
    {
      title: '更新时间',
      key: 'updatedAt',
      width: 140,
      render(row) {
        return h('span', { class: 'text-slate-500 text-sm' }, row.updatedAt ? formatRelativeTime(row.updatedAt) : '-');
      },
    },
    {
      title: '到期时间',
      key: 'expiry',
      width: 120,
      render(row) {
        return h('span', { class: 'text-slate-500 text-sm' }, getExpiryText(row.name));
      },
    },
    {
      title: '',
      key: 'actions',
      width: 50,
      fixed: 'right',
      render(row) {
        if (!isZoneManageProvider.value || !row.credentialId) return null;
        return h(NButton, {
          text: true,
          type: 'error',
          size: 'small',
          onClick: (e: Event) => { e.stopPropagation(); confirmDeleteZone(row); },
        }, { icon: () => h(Trash2, { size: 14 }) });
      },
    },
  );

  return cols;
});

// Reset page on filter change
watch([search, effectiveCredentialId, quickFilter, sortBy, sortOrder, panelMode, selectedTagFilter], () => { currentPage.value = 1; });

watch(sortedDomains, (list) => {
  const valid = new Set(list.map(getDomainRowKey));
  selectedRowKeys.value = selectedRowKeys.value.filter((key) => valid.has(key));
});

watch(selectedViewId, (id) => {
  if (!id) return;
  const view = mergedSavedViews.value.find((item) => item.id === id);
  if (!view || !view.payload) return;
  const payload = view.payload as Record<string, any>;
  search.value = String(payload.search || '');
  quickFilter.value = (payload.quickFilter || 'all') as typeof quickFilter.value;
  sortBy.value = (payload.sortBy || 'updatedAt') as typeof sortBy.value;
  sortOrder.value = (payload.sortOrder || 'desc') as typeof sortOrder.value;
  selectedTagFilter.value = payload.selectedTagFilter || null;
  panelMode.value = (payload.panelMode || 'dns') as typeof panelMode.value;
  message.success(`已应用视图：${view.name}`);
});

watch(domains, (list) => {
  if (!list.length) return;
  const next = { ...localDomainTags.value };
  let changed = false;
  for (const item of list) {
    if (next[item.name]) continue;
    const tags = item.tags ? Object.entries(item.tags).map(([k, v]) => `${k}:${String(v)}`) : [];
    if (tags.length) {
      next[item.name] = tags;
      changed = true;
    }
  }
  if (changed) localDomainTags.value = next;
}, { immediate: true });

</script>

<template>
  <div class="bento-grid">
    <section class="bento-hero col-span-12 md:col-span-8">
      <div class="toolbar-row">
        <div>
          <div class="section-badge">
            <span class="dot" />
            <span class="label">Operations Center</span>
          </div>
          <h1 class="page-title">
            {{ dashboardTitle }}
            <span class="gradient-text"> 工作台</span>
          </h1>
          <p class="page-subtitle">统一管理 DNS Zone 与阿里云 ESA 站点，支持多账户切换与快速检索。</p>
        </div>
        <div class="flex-1" />

        <template v-if="providerStore.selectedProvider === 'aliyun'">
          <div class="panel-muted flex overflow-hidden p-1.5">
            <button
              class="rounded-xl px-3 py-2 text-xs font-semibold"
              :class="panelMode === 'dns' ? 'bg-[#e7f1fd] text-[#2f6fbd]' : 'text-slate-500 hover:text-slate-700'"
              @click="panelMode = 'dns'"
            >
              DNS 区域
            </button>
            <button
              class="rounded-xl px-3 py-2 text-xs font-semibold"
              :class="panelMode === 'esa' ? 'bg-[#e7f1fd] text-[#2f6fbd]' : 'text-slate-500 hover:text-slate-700'"
              @click="panelMode = 'esa'"
            >
              ESA 站点
            </button>
          </div>
        </template>

        <NButton
          v-if="providerStore.selectedProvider === 'cloudflare'"
          size="small"
          secondary
          @click="router.push('/tunnels')"
        >
          Tunnel 管理
        </NButton>
        <NButton
          v-if="providerStore.selectedProvider"
          size="small"
          type="primary"
          @click="goToAddCredential"
        >
          <template #icon><Plus :size="14" /></template>
          添加 DNS 账户
        </NButton>
        <NButton
          v-if="isEsaPanel"
          size="small"
          type="primary"
          @click="showAddEsa = true"
        >
          <template #icon><Plus :size="14" /></template>
          添加 ESA 站点
        </NButton>
        <NButton size="small" secondary :loading="isLoading" @click="handleRefresh">
          <template #icon><RefreshCw :size="14" /></template>
        </NButton>
      </div>

      <div class="feature-strip mt-4">
        <span class="feature-kicker">Featured</span>
        <span class="feature-text">支持“全部账户”聚合视图，跨凭证批量检查域名状态与更新时间。</span>
      </div>

      <div class="mt-4 flex flex-wrap gap-4">
        <button class="bento-chip" :class="{ 'bento-chip-active': quickFilter === 'all' }" @click="quickFilter = 'all'">
          全部 ({{ domains.length }})
        </button>
        <button class="bento-chip" :class="{ 'bento-chip-active': quickFilter === 'active' }" @click="quickFilter = 'active'">
          在线 ({{ activeDomainCount }})
        </button>
        <button class="bento-chip" :class="{ 'bento-chip-active': quickFilter === 'expiring' }" @click="quickFilter = 'expiring'">
          到期预警 ({{ expiringSoonCount }})
        </button>
        <button class="bento-chip" :class="{ 'bento-chip-active': quickFilter === 'recent' }" @click="quickFilter = 'recent'">
          24h 更新 ({{ recentUpdatedCount }})
        </button>
        <button class="bento-chip" :class="{ 'bento-chip-active': quickFilter === 'issue' }" @click="quickFilter = 'issue'">
          异常状态 ({{ issueDomainCount }})
        </button>
      </div>
    </section>

    <section class="col-span-12 md:col-span-4 grid grid-cols-2 gap-4">
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -right-10 -top-10 w-40 h-40 rounded-full bg-gradient-to-br from-sky-500/20 to-blue-500/20 blur-2xl" />
        <div class="absolute right-3 top-3 w-16 h-16 rounded-full bg-gradient-to-br from-sky-400/30 to-blue-400/30 blur-xl" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">域名总数</p>
          <div class="mt-2 flex items-end gap-1">
            <p class="text-6xl bg-gradient-to-r from-sky-600 to-blue-600 bg-clip-text text-transparent">{{ domains.length }}</p>
          </div>
          <div class="mt-3 flex items-center gap-2">
            <span class="text-xs text-slate-500">管理中</span>
            <div class="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-sky-500 to-blue-500 rounded-full" style="width: 75%"></div>
            </div>
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -left-12 -bottom-12 w-36 h-36 rounded-full bg-gradient-to-br from-emerald-500/18 to-green-500/18 blur-xl" />
        <div class="absolute left-3 bottom-3 w-14 h-14 rounded-full bg-gradient-to-br from-emerald-400/28 to-green-400/28 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">在线</p>
          <div class="mt-2 flex items-center gap-1.5">
            <span class="w-3.5 h-3.5 rounded-full bg-emerald-500 animate-pulse shadow-lg shadow-emerald-500/40"></span>
            <p class="text-5xl text-emerald-600">{{ activeDomainCount }}</p>
          </div>
          <div class="mt-3 flex items-center gap-2">
            <span class="text-xs text-slate-500">健康域名</span>
            <div class="flex gap-0.5">
              <span v-for="i in 4" :key="i" class="w-1.5 h-1.5 rounded-full bg-emerald-200" :class="i <= Math.ceil((activeDomainCount / Math.max(1, domains.length)) * 4) ? 'bg-emerald-500' : ''"></span>
            </div>
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -right-14 -top-14 w-40 h-40 rounded-full bg-gradient-to-br from-orange-500/18 to-amber-500/18 blur-xl" />
        <div class="absolute right-4 top-4 w-12 h-12 rounded-full bg-gradient-to-br from-orange-400/25 to-amber-400/25 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">预警</p>
          <div class="mt-2 flex items-center gap-1.5">
            <span class="w-3.5 h-3.5 rounded-full bg-orange-500 shadow-lg shadow-orange-500/35"></span>
            <p class="text-5xl text-orange-600">{{ expiringSoonCount }}</p>
          </div>
          <div class="mt-3 flex items-center gap-2">
            <span class="text-xs text-slate-500">14天内到期</span>
            <div class="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-orange-500 to-amber-500 rounded-full" style="width: 45%"></div>
            </div>
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -left-14 -top-14 w-40 h-40 rounded-full bg-gradient-to-br from-fuchsia-500/18 to-violet-500/18 blur-xl" />
        <div class="absolute left-4 top-4 w-12 h-12 rounded-full bg-gradient-to-br from-fuchsia-400/25 to-violet-400/25 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">服务源</p>
          <div class="mt-2 flex items-center gap-1.5">
            <span class="w-3.5 h-3.5 rounded-full bg-fuchsia-500 shadow-lg shadow-fuchsia-500/35"></span>
            <p class="text-5xl text-fuchsia-600">{{ providerCount }}</p>
          </div>
          <div class="mt-3 flex items-center gap-2">
            <span class="text-xs text-slate-500">已配置账户</span>
            <div class="flex gap-0.5">
              <span v-for="i in 3" :key="i" class="w-1.5 h-1.5 rounded-full bg-fuchsia-200" :class="i <= providerCount ? 'bg-fuchsia-500' : ''"></span>
            </div>
          </div>
        </div>
      </article>
    </section>

    <section class="col-span-12">
      <ProviderAccountTabs :mode="isAllScope ? 'all' : 'provider'" />
    </section>

    <section class="col-span-12 grid grid-cols-1 gap-4 lg:grid-cols-3">
      <article class="bento-card p-5">
        <div class="flex items-center justify-between">
          <p class="text-xs uppercase tracking-widest text-slate-500">同步健康</p>
          <ShieldCheck :size="16" class="text-slate-500" />
        </div>
        <div class="mt-3 flex items-end gap-2">
          <p class="text-4xl text-slate-800">{{ syncMetrics24h.successRate }}</p>
          <span class="text-xl text-slate-400">%</span>
        </div>
        <p class="mt-2 text-xs text-slate-500">24h 失败 {{ syncMetrics24h.failedCount }} 次 · 平均耗时 {{ syncMetrics24h.avgDurationMs }}ms</p>
      </article>

      <article class="bento-card p-5">
        <div class="flex items-center justify-between">
          <p class="text-xs uppercase tracking-widest text-slate-500">风险变更</p>
          <AlertTriangle :size="16" class="text-slate-500" />
        </div>
        <p class="mt-3 text-4xl text-rose-600">{{ riskyChangeCount24h }}</p>
        <p class="mt-2 text-xs text-slate-500">最近 24h 删除/高风险更新次数</p>
      </article>

      <article class="bento-card p-5">
        <div class="flex items-center justify-between">
          <p class="text-xs uppercase tracking-widest text-slate-500">服务商可用性</p>
          <Layers3 :size="16" class="text-slate-500" />
        </div>
        <div class="mt-3 space-y-2 text-xs">
          <div v-for="item in providerAvailability.slice(0, 3)" :key="item.provider" class="flex items-center justify-between">
            <span class="text-slate-600">{{ item.provider }}</span>
            <span class="font-semibold text-slate-700">{{ item.successRate }}%</span>
          </div>
          <p v-if="providerAvailability.length === 0" class="text-slate-500">暂无可用数据</p>
        </div>
      </article>

      <article class="bento-card p-5">
        <div class="flex items-center justify-between">
          <p class="text-xs uppercase tracking-widest text-slate-500">到期窗口</p>
          <Clock3 :size="16" class="text-slate-500" />
        </div>
        <div class="mt-3 flex items-center gap-5">
          <div>
            <p class="text-3xl text-amber-600">{{ expiring7dCount }}</p>
            <p class="text-xs text-slate-500">7 天内</p>
          </div>
          <div>
            <p class="text-3xl text-orange-600">{{ expiring30dCount }}</p>
            <p class="text-xs text-slate-500">30 天内</p>
          </div>
        </div>
      </article>

      <article class="bento-card p-5">
        <div class="flex items-center justify-between">
          <p class="text-xs uppercase tracking-widest text-slate-500">记录类型分布</p>
          <Tag :size="16" class="text-slate-500" />
        </div>
        <div class="mt-3 space-y-2 text-xs">
          <div v-for="item in recordTypeDistribution.slice(0, 4)" :key="item.type" class="flex items-center justify-between">
            <span class="text-slate-600">{{ item.type }}</span>
            <span class="font-semibold text-slate-700">{{ item.count }}</span>
          </div>
          <p v-if="recordTypeDistribution.length === 0" class="text-slate-500">暂无分布数据</p>
        </div>
      </article>

      <article class="bento-card p-5">
        <div class="flex items-center justify-between">
          <p class="text-xs uppercase tracking-widest text-slate-500">待处理告警</p>
          <AlertTriangle :size="16" class="text-slate-500" />
        </div>
        <p class="mt-3 text-4xl text-red-600">{{ pendingAlertCount }}</p>
        <p class="mt-2 text-xs text-slate-500">状态为 Open 的告警事件</p>
      </article>
    </section>

    <section class="bento-card col-span-12 md:col-span-9">
      <div class="toolbar-row mb-4">
        <div>
          <p class="bento-section-title">域名列表</p>
          <p class="bento-section-meta">共 {{ filteredDomains.length }} 条结果 · 最近刷新 {{ lastRefreshText }} · 已选 {{ selectedDomains.length }}</p>
        </div>
        <div class="flex-1" />
        <NButton size="small" secondary @click="handleOneClickInspection">
          <template #icon><ShieldCheck :size="14" /></template>
          一键巡检
        </NButton>
        <NButton size="small" secondary :disabled="selectedDomains.length === 0" @click="handleBatchRefresh">
          <template #icon><RefreshCw :size="14" /></template>
          批量同步
        </NButton>
        <NButton size="small" secondary :disabled="selectedDomains.length === 0" @click="confirmBatchDelete">
          <template #icon><Trash2 :size="14" /></template>
          批量删除
        </NButton>
        <NButton size="small" secondary @click="showSyncCenter = true">同步任务</NButton>
        <NButton size="small" secondary @click="showAlertCenter = true">告警中心</NButton>
        <NButton size="small" secondary @click="showAuditCenter = true">变更审计</NButton>
        <NButton size="small" secondary @click="openSaveCurrentViewModal">保存视图</NButton>
        <NButton size="small" secondary @click="openTagCenter()">标签中心</NButton>
      </div>

      <div class="toolbar-row mb-4">
        <NSelect
          v-model:value="selectedViewId"
          size="small"
          clearable
          :options="viewOptions"
          placeholder="选择已保存视图"
          class="!w-48"
        />
        <NButton v-if="selectedViewId" size="small" secondary @click="selectedViewId && deleteView(selectedViewId)">
          删除视图
        </NButton>
        <NSelect
          v-model:value="selectedTagFilter"
          size="small"
          clearable
          :options="allTagOptions"
          placeholder="按标签筛选"
          class="!w-36"
        />
        <NSelect
          v-model:value="sortBy"
          size="small"
          :options="sortOptions"
          class="!w-36"
        />
        <NButton size="small" secondary @click="toggleSortOrder">
          <template #icon><ArrowUpDown :size="14" /></template>
          {{ sortOrder === 'desc' ? '降序' : '升序' }}
        </NButton>
        <NInput
          v-model:value="search"
          placeholder="搜索域名..."
          clearable
          size="small"
          class="!w-72"
        >
          <template #prefix><Search :size="14" class="text-slate-500" /></template>
        </NInput>
        <NButton size="small" secondary @click="exportFilteredDomainsCsv">
          <template #icon><Download :size="14" /></template>
          导出 CSV
        </NButton>
      </div>

      <div v-if="isLoading" class="flex justify-center py-20">
        <NSpin size="large" />
      </div>

      <NEmpty v-else-if="filteredDomains.length === 0" class="py-20" description="暂无域名数据">
        <template #extra>
          <NButton
            v-if="providerStore.selectedProvider"
            size="small"
            secondary
            @click="goToAddCredential"
          >
            添加 {{ selectedProviderName || providerStore.selectedProvider }} 账户
          </NButton>
        </template>
      </NEmpty>

      <div v-else-if="isMobile" class="space-y-4">
        <div
          v-for="domain in paginatedDomains"
          :key="domain.id"
          class="bento-card-muted"
        >
          <div class="mb-3 flex items-center justify-between">
            <button
              class="text-sm font-semibold text-accent hover:text-accent-hover"
              @click="goToDomain(domain)"
            >
              {{ domain.name }}
            </button>
            <div class="flex items-center gap-2">
              <NTag size="small" :bordered="false">{{ computeDomainHealthScore(domain) }}</NTag>
              <NTag :type="getStatusType(domain.status)" size="small" :bordered="false">
                {{ domain.status }}
              </NTag>
              <NTag v-if="!isEsaPanel" :type="getAccelerationType(domain)" size="small" :bordered="false">
                {{ getAccelerationLabel(domain) }}
              </NTag>
            </div>
          </div>
          <div class="flex items-center justify-between text-xs text-slate-500">
            <span v-if="domain.credentialName">{{ domain.credentialName }}</span>
            <span>{{ domain.updatedAt ? formatRelativeTime(domain.updatedAt) : '-' }}</span>
          </div>
          <div v-if="getDomainTags(domain.name).length" class="mt-2 flex flex-wrap gap-1">
            <NTag v-for="item in getDomainTags(domain.name).slice(0, 3)" :key="item" size="small" :bordered="false">{{ item }}</NTag>
          </div>
        </div>
      </div>

      <NDataTable
        v-else
        :columns="columns"
        :data="paginatedDomains"
        :row-key="(row: Domain) => getDomainRowKey(row)"
        :checked-row-keys="selectedRowKeys"
        @update:checked-row-keys="handleCheckedRowKeys"
        :bordered="false"
        size="small"
        class="table-scrollable !bg-transparent"
        :scroll-x="1180"
        :max-height="620"
        :virtual-scroll="paginatedDomains.length > 120"
      />

      <div v-if="filteredDomains.length > pageSize" class="mt-4 flex justify-end">
        <NPagination
          v-model:page="currentPage"
          :page-size="pageSize"
          :item-count="filteredDomains.length"
          show-quick-jumper
          size="small"
        />
      </div>
    </section>

    <section class="col-span-12 md:col-span-3 space-y-4">
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -right-12 -top-12 w-44 h-44 rounded-full bg-gradient-to-br from-teal-500/22 to-emerald-500/22 blur-2xl" />
        <div class="absolute right-4 top-4 w-14 h-14 rounded-full bg-gradient-to-br from-teal-400/30 to-emerald-400/30 blur-xl" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">可用率</p>
          <div class="mt-2 flex items-end gap-1">
            <p class="text-5xl bg-gradient-to-r from-teal-600 to-emerald-600 bg-clip-text text-transparent">
              {{ domains.length > 0 ? Math.round((activeDomainCount / domains.length) * 100) : 0 }}
            </p>
            <span class="text-2xl text-slate-400 mb-1">%</span>
          </div>
          <div class="mt-4 h-3.5 bg-slate-100 rounded-full overflow-hidden">
            <div class="h-full bg-gradient-to-r from-teal-500 to-emerald-500 rounded-full" :style="{ width: Math.min(100, (activeDomainCount / Math.max(1, domains.length)) * 100) + '%' }"></div>
          </div>
          <div class="mt-3 text-xs text-slate-500">
            {{ activeDomainCount }} / {{ domains.length }} 健康
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -left-12 -bottom-12 w-36 h-36 rounded-full bg-gradient-to-br from-red-500/18 to-rose-500/18 blur-xl" />
        <div class="absolute left-4 bottom-4 w-12 h-12 rounded-full bg-gradient-to-br from-red-400/25 to-rose-400/25 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">异常域名</p>
          <div class="mt-2 flex items-center gap-1.5">
            <span class="w-3.5 h-3.5 rounded-full bg-red-500 shadow-lg shadow-red-500/35"></span>
            <p class="text-5xl text-red-600">{{ issueDomainCount }}</p>
          </div>
          <div class="mt-3 flex items-center gap-2">
            <span class="text-xs text-slate-500">需要关注</span>
            <div class="flex gap-0.5">
              <span v-for="i in 5" :key="i" class="w-1.5 h-1.5 rounded-full bg-red-200" :class="i <= issueDomainCount ? 'bg-red-500' : ''"></span>
            </div>
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -right-14 -top-14 w-44 h-44 rounded-full bg-gradient-to-br from-indigo-500/18 to-violet-500/18 blur-xl" />
        <div class="absolute right-4 top-4 w-12 h-12 rounded-full bg-gradient-to-br from-indigo-400/25 to-violet-400/25 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">平均健康分</p>
          <div class="mt-3 flex items-center gap-2">
            <Check :size="16" class="text-indigo-500" />
            <p class="text-3xl bg-gradient-to-r from-indigo-600 to-violet-600 bg-clip-text text-transparent">{{ avgHealthScore }}</p>
          </div>
          <div class="mt-3 flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-indigo-500 animate-pulse"></span>
            <span class="text-xs text-slate-500">当前面板：{{ isEsaPanel ? '阿里云 ESA' : '标准 DNS' }}</span>
          </div>
        </div>
      </article>
    </section>

    <NDrawer v-model:show="showSyncCenter" placement="right" :width="460" :trap-focus="true">
      <div class="h-full overflow-y-auto p-4">
        <h3 class="text-base font-bold text-slate-700">同步任务中心</h3>
        <p class="mt-1 text-xs text-slate-500">手动刷新、巡检、重试任务都会记录在这里</p>
        <div class="mt-4 space-y-3">
          <div v-for="job in mergedSyncJobs.slice(0, 30)" :key="job.id" class="panel-muted p-3">
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-slate-700">{{ job.scope === 'all' ? '全局任务' : job.scope === 'provider' ? '服务商任务' : '账户任务' }}</p>
                <p class="text-xs text-slate-500">{{ new Date(job.createdAt).toLocaleString('zh-CN') }}</p>
              </div>
              <NTag :type="job.status === 'success' ? 'success' : job.status === 'failed' ? 'error' : 'warning'" size="small" :bordered="false">
                {{ job.status }}
              </NTag>
            </div>
            <p class="mt-2 text-xs text-slate-500">耗时: {{ job.durationMs || 0 }} ms</p>
            <p v-if="job.error" class="mt-1 text-xs text-red-500">{{ job.error }}</p>
            <div v-if="job.status === 'failed'" class="mt-2">
              <NButton size="tiny" secondary @click="retryRemoteSync(job.id)">重试</NButton>
            </div>
          </div>
        </div>
      </div>
    </NDrawer>

    <NDrawer v-model:show="showAlertCenter" placement="right" :width="500" :trap-focus="true">
      <div class="h-full overflow-y-auto p-4">
        <h3 class="text-base font-bold text-slate-700">告警中心</h3>
        <p class="mt-1 text-xs text-slate-500">规则配置与待处理告警事件</p>

        <div class="mt-4">
          <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">告警规则</p>
          <div class="mt-2 space-y-2">
            <div v-for="rule in mergedAlertRules" :key="rule.id" class="panel-muted flex items-center justify-between p-3">
              <div>
                <p class="text-sm font-semibold text-slate-700">{{ rule.name }}</p>
                <p class="text-xs text-slate-500">{{ rule.type }} · 阈值 {{ rule.threshold ?? '-' }}</p>
              </div>
              <NSwitch :value="rule.enabled" @update:value="(v) => toggleRuleEnabled(rule, v)" />
            </div>
          </div>
        </div>

        <div class="mt-5">
          <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">告警事件</p>
          <div class="mt-2 space-y-2">
            <div v-for="event in displayAlertEvents.slice(0, 40)" :key="event.id" class="panel-muted p-3">
              <div class="flex items-start justify-between gap-3">
                <div>
                  <p class="text-sm font-semibold text-slate-700">{{ event.title }}</p>
                  <p class="mt-1 text-xs text-slate-500">{{ event.message || '-' }}</p>
                  <p class="mt-1 text-xs text-slate-500">{{ new Date(event.createdAt).toLocaleString('zh-CN') }}</p>
                </div>
                <NTag :type="event.status === 'open' ? 'error' : event.status === 'acknowledged' ? 'warning' : 'success'" size="small" :bordered="false">
                  {{ event.status }}
                </NTag>
              </div>
              <div v-if="event.status === 'open'" class="mt-2">
                <NButton size="tiny" secondary @click="ackAlert(event.id)">标记已确认</NButton>
              </div>
            </div>
          </div>
        </div>
      </div>
    </NDrawer>

    <NDrawer v-model:show="showAuditCenter" placement="right" :width="500" :trap-focus="true">
      <div class="h-full overflow-y-auto p-4">
        <h3 class="text-base font-bold text-slate-700">变更审计</h3>
        <p class="mt-1 text-xs text-slate-500">最近变更记录与状态追踪</p>
        <div class="mt-4 space-y-2">
          <div v-for="item in auditLogs.slice(0, 60)" :key="item.id" class="panel-muted p-3">
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-semibold text-slate-700">{{ item.domain || item.recordName || '-' }}</p>
              <NTag :type="item.status === 'SUCCESS' ? 'success' : 'error'" size="small" :bordered="false">{{ item.status }}</NTag>
            </div>
            <p class="mt-1 text-xs text-slate-500">{{ item.action }} · {{ item.resourceType }}</p>
            <p class="mt-1 text-xs text-slate-500">{{ new Date(item.timestamp).toLocaleString('zh-CN') }}</p>
          </div>
        </div>
      </div>
    </NDrawer>

    <NDrawer v-model:show="showTagCenter" placement="right" :width="420" :trap-focus="true">
      <div class="h-full overflow-y-auto p-4">
        <h3 class="text-base font-bold text-slate-700">域名标签中心</h3>
        <div class="mt-3 space-y-3">
          <NSelect
            v-model:value="activeTagDomain"
            filterable
            :options="domains.map((d) => ({ label: d.name, value: d.name }))"
            placeholder="选择域名"
          />
          <div class="flex items-center gap-2">
            <NInput v-model:value="tagInput" placeholder="输入标签，例如 prod / core / billing" />
            <NButton size="small" type="primary" @click="addTagForActiveDomain">添加</NButton>
          </div>
          <div v-if="activeTagDomain" class="panel-muted p-3">
            <p class="mb-2 text-xs text-slate-500">当前标签</p>
            <div class="flex flex-wrap gap-1">
              <NTag
                v-for="item in getDomainTags(activeTagDomain)"
                :key="item"
                size="small"
                closable
                @close.prevent="removeTagForDomain(activeTagDomain, item)"
              >
                {{ item }}
              </NTag>
              <span v-if="getDomainTags(activeTagDomain).length === 0" class="text-xs text-slate-500">暂无标签</span>
            </div>
          </div>
        </div>
      </div>
    </NDrawer>

    <NModal v-model:show="showSaveViewModal" preset="dialog" title="保存当前视图" positive-text="保存" negative-text="取消" @positive-click="saveCurrentView">
      <div class="space-y-3">
        <NInput v-model:value="newViewName" placeholder="输入视图名称，例如 生产域名巡检视图" />
        <div class="panel-muted p-3 text-xs text-slate-500">
          将保存当前筛选、排序、标签过滤、分页大小与面板模式。
        </div>
      </div>
    </NModal>

    <AddEsaSiteDialog
      v-model:show="showAddEsa"
      :credentials="addDialogCredentials"
      :initial-credential-id="addInitialCredId"
    />
    <AddDnsCredentialDialog
      v-model:show="showAddCredential"
      :preset-provider="providerStore.selectedProvider"
      @created="refetch"
    />
  </div>
</template>
