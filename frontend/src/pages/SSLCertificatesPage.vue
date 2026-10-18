<script setup lang="ts">
import { ref, computed, watch, h, onUnmounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { keepPreviousData } from '@tanstack/vue-query';
import {
  NButton, NTag, NDataTable, NModal, NFormItem, NInput, NSelect, NAlert,
  NEmpty, NSpin, NPagination, NDrawer, NDrawerContent, NDescriptions,
  NDescriptionsItem, NSwitch, NTooltip, NTabs, NTabPane, NInputNumber, NDropdown, useMessage, useDialog,
} from 'naive-ui';
import { RefreshCw, Search, Plus, Upload, Download, Trash2, Eye, CheckCircle, KeyRound, Pencil, AlertTriangle, RotateCw, ArrowUpDown, FileDown, ListChecks, FileText, Rocket, Copy, Zap } from 'lucide-vue-next';
import {
  getSslCredentials, createSslCredential, updateSslCredential, deleteSslCredential as deleteSslCred,
  getSslCertificates, getSslCertificateDetail, applySslCertificate,
  completeSslCertificate, downloadSslCertificate, uploadSslCertificate,
  deleteSslCertificate, syncSslCertificates, reconcileSslCertificates, cleanExpiredSslCertificates, renewExpiredCertificates,
  autoDnsSslCertificate, cleanupDnsSslCertificate,
  getSslAutoRenew, setSslAutoRenew, issueAcmeCertificate, setCertificateAutoRenew,
  getSslAcmeJobs, retrySslAcmeJob, cancelSslAcmeJob, getSslDeploymentEvents,
  retrySslDeploymentEvent, getSslNotificationSettings, saveSslNotificationSettings,
  testSslNotification, getSslTaskLogs, getSslTaskStats, downloadSslTaskLogs,
  viewSslCertificate, deploySslCertificate,
  batchDeploySslCertificates, batchSetSslAutoRenew, checkSslExpiry,
  getSslAcmeCas, getSslDeploymentsBySite,
  getSslEdgeOneBindings, syncSslCertToEdgeOne,
} from '@/services/ssl';
import type { SslCaOption, SiteDeploymentOverview, EdgeOneCertBinding } from '@/services/ssl';
import { getDnsCredentials } from '@/services/dnsCredentials';
import { getDomains } from '@/services/domains';
import AddZoneDialog from '@/components/Dashboard/AddZoneDialog.vue';
import type { SslCredential, RenewResult, SslAcmeJob, SslDeploymentEvent, SslNotificationSettings } from '@/services/ssl';
import { useResponsive } from '@/composables/useResponsive';
import { TABLE_PAGE_SIZE } from '@/utils/constants';
import type { SslCertificate, SslCertificateDetail, SslCertificateStatus } from '@/types/ssl';
import type { Domain } from '@/types';

const route = useRoute();
const router = useRouter();
// Channel tabs: 'all' | 'tencent' | 'letsencrypt'. Deep links (?channel=) and
// the legacy /letsencrypt route select the initial tab.
type ChannelTab = 'all' | 'tencent' | 'letsencrypt';
const channelTab = ref<ChannelTab>('all');
const isLetsEncryptPage = computed(() => channelTab.value === 'letsencrypt');
const message = useMessage();
const dialog = useDialog();
const queryClient = useQueryClient();
const { isMobile } = useResponsive();

// ── Credential selection ───────────────────────────────────────
const SSL_CRED_STORAGE_KEY = 'ssl_selected_credential';
const savedCredId = localStorage.getItem(SSL_CRED_STORAGE_KEY);
const selectedCredentialId = ref<number | 'all' | null>(
  savedCredId === 'all' ? 'all' : savedCredId ? parseInt(savedCredId, 10) || 'all' : 'all',
);

watch(selectedCredentialId, (id) => {
  if (id) localStorage.setItem(SSL_CRED_STORAGE_KEY, String(id));
  else localStorage.removeItem(SSL_CRED_STORAGE_KEY);
});

const { data: sslCredentials, isLoading: credsLoading, error: credsError } = useQuery({
  queryKey: ['ssl-credentials'],
  queryFn: async () => {
    const res = await getSslCredentials();
    return (res.data || []) as SslCredential[];
  },
});

const credentialOptions = computed(() => {
  const opts: Array<{ label: string; value: number | 'all' }> = [
    { label: isLetsEncryptPage.value ? "全部 Let's Encrypt 证书" : (channelTab.value === 'tencent' ? '全部腾讯云证书' : '全部证书'), value: 'all' },
  ];
  const list = sslCredentials.value || [];
  for (const c of list) {
    const suffix = c.provider === 'dnspod' ? '（DNS 共用）' : '';
    opts.push({ label: `${c.name}${suffix}`, value: c.id });
  }
  return opts;
});

watch(sslCredentials, (list) => {
  if (!list) return;
  if (selectedCredentialId.value === 'all') return;
  if (selectedCredentialId.value && list.some(c => c.id === selectedCredentialId.value)) return;
  selectedCredentialId.value = 'all';
}, { immediate: true });

function credNameById(id?: number) {
  if (!id) return '';
  const c = (sslCredentials.value || []).find(x => x.id === id);
  return c ? c.name : `#${id}`;
}

// ── Channel tabs ───────────────────────────────────────────────
// "全部" is always available; 腾讯云 shows when the account has Tencent SSL
// credentials; Let's Encrypt shows when ACME-capable DNS credentials exist.
const acmeDnsCredsAvailable = computed(() =>
  (dnsCredentials.value || []).some(c =>
    ['cloudflare', 'dnspod', 'dnspod_token', 'aliyun'].includes(String(c.provider))),
);

const channelTabs = computed(() => {
  const tabs: Array<{ key: ChannelTab; label: string; count?: number }> = [
    { key: 'all', label: '全部', count: sourceCountsAll.value },
  ];
  const hasTencentCreds = (sslCredentials.value || []).length > 0
    || (sourceCounts.value.tencent || 0) > 0;
  if (hasTencentCreds) {
    tabs.push({ key: 'tencent', label: '腾讯云', count: sourceCounts.value.tencent });
  }
  const hasAcme = acmeDnsCredsAvailable.value || (sourceCounts.value.letsencrypt || 0) > 0;
  if (hasAcme) {
    tabs.push({ key: 'letsencrypt', label: "Let's Encrypt", count: sourceCounts.value.letsencrypt });
  }
  return tabs;
});

const sourceCountsAll = computed(() => {
  const counts = sourceCounts.value;
  return Object.values(counts).reduce((sum, n) => sum + (n || 0), 0);
});

function selectChannelTab(tab: ChannelTab) {
  if (channelTab.value === tab) return;
  channelTab.value = tab;
  statusFilter.value = null;
  filterCredentialId.value = null;
  selectedCredentialId.value = 'all';
  page.value = 1;
  // Keep the URL shareable: /ssl?channel=letsencrypt
  router.replace({ path: '/ssl', query: tab === 'all' ? {} : { channel: tab } }).catch(() => undefined);
}

// Initialize the tab from the URL (?channel=), then keep it in sync when the
// user follows a deep link / back-forward navigation.
function syncChannelFromRoute() {
  const q = String(route.query.channel || '').toLowerCase();
  if (q === 'tencent' || q === 'letsencrypt') {
    channelTab.value = q;
  } else if (route.path === '/letsencrypt') {
    channelTab.value = 'letsencrypt';
  } else {
    channelTab.value = 'all';
  }
}
syncChannelFromRoute();
watch(() => route.query.channel, syncChannelFromRoute);

// ── Add credential dialog ──────────────────────────────────────
const showAddCred = ref(false);
const addCredName = ref('');
const addCredSecretId = ref('');
const addCredSecretKey = ref('');
const addCredError = ref('');

const addCredMutation = useMutation({
  mutationFn: () => createSslCredential({
    name: addCredName.value.trim(),
    secretId: addCredSecretId.value.trim(),
    secretKey: addCredSecretKey.value.trim(),
  }),
  onSuccess: (res) => {
    message.success('SSL 凭证已添加');
    showAddCred.value = false;
    addCredName.value = '';
    addCredSecretId.value = '';
    addCredSecretKey.value = '';
    addCredError.value = '';
    queryClient.invalidateQueries({ queryKey: ['ssl-credentials'] });
    if (res.data?.id) {
      selectedCredentialId.value = res.data.id;
    }
  },
  onError: (err: any) => { addCredError.value = String(err); },
});

function openAddCred() {
  addCredError.value = '';
  addCredName.value = '';
  addCredSecretId.value = '';
  addCredSecretKey.value = '';
  showAddCred.value = true;
}

// ── Edit credential dialog ────────────────────────────────────
const showEditCred = ref(false);
const editCredId = ref<number | null>(null);
const editCredName = ref('');
const editCredSecretId = ref('');
const editCredSecretKey = ref('');
const editCredError = ref('');

const editCredMutation = useMutation({
  mutationFn: () => {
    const payload: Record<string, string> = {};
    if (editCredName.value.trim()) payload.name = editCredName.value.trim();
    if (editCredSecretId.value.trim() && editCredSecretKey.value.trim()) {
      payload.secretId = editCredSecretId.value.trim();
      payload.secretKey = editCredSecretKey.value.trim();
    }
    return updateSslCredential(editCredId.value!, payload);
  },
  onSuccess: () => {
    message.success('凭证已更新');
    showEditCred.value = false;
    queryClient.invalidateQueries({ queryKey: ['ssl-credentials'] });
  },
  onError: (err: any) => { editCredError.value = String(err); },
});

function openEditCred(cred: SslCredential) {
  editCredId.value = cred.id;
  editCredName.value = cred.name;
  editCredSecretId.value = '';
  editCredSecretKey.value = '';
  editCredError.value = '';
  showEditCred.value = true;
}

// ── Delete credential ────────────────────────────────────────
function handleDeleteCred(cred: SslCredential) {
  dialog.warning({
    title: '删除 SSL 凭证',
    content: `确定要删除凭证「${cred.name}」及其关联的证书缓存吗？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteSslCred(cred.id);
        message.success('凭证已删除');
        queryClient.invalidateQueries({ queryKey: ['ssl-credentials'] });
        queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
        if (selectedCredentialId.value === cred.id) {
          selectedCredentialId.value = null;
        }
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}

const showCredList = ref(false);

// ── Certificate list ───────────────────────────────────────────
const page = ref(1);
const pageSize = TABLE_PAGE_SIZE;
const searchKeyword = ref('');
const filterCredentialId = ref<number | null>(null);
const statusFilter = ref<SslCertificateStatus | null>(null);
// Source filter follows the active channel tab: the tab IS the source scope.
const sourceFilter = computed<'tencent' | 'letsencrypt' | null>(() =>
  channelTab.value === 'all' ? null : channelTab.value,
);
const hasActiveApplying = ref(false);


const {
  data: certsResponse,
  isLoading,
  isFetching: certsFetching,
  error: certsError,
} = useQuery({
  queryKey: computed(() => [
    'ssl-certificates',
    selectedCredentialId.value,
    page.value,
    pageSize,
    searchKeyword.value,
    filterCredentialId.value,
    statusFilter.value,
    sourceFilter.value,
  ]),
  queryFn: async () => {
    if (!selectedCredentialId.value) return { data: [], pagination: { total: 0, page: 1, limit: pageSize, pages: 0 }, errors: undefined };
    const res = await getSslCertificates(selectedCredentialId.value, {
      page: page.value,
      limit: pageSize,
      search: searchKeyword.value || undefined,
      filterCredentialId: filterCredentialId.value || undefined,
      status: selectedCredentialId.value === 'all' ? (statusFilter.value || undefined) : undefined,
      source: selectedCredentialId.value === 'all' ? (sourceFilter.value || undefined) : undefined,
    });
    return {
      data: res.data || [],
      pagination: res.pagination || { total: 0, page: 1, limit: pageSize, pages: 0 },
      errors: res.errors,
      statusSummary: res.statusSummary,
      sourceSummary: res.sourceSummary,
      credentialSummary: res.credentialSummary,
    };
  },
  enabled: computed(() => !!selectedCredentialId.value),
  refetchInterval: computed(() => hasActiveApplying.value ? 15000 : false),
  placeholderData: keepPreviousData,
  staleTime: 5_000,
});

const certificates = computed(() => certsResponse.value?.data || []);
const totalCount = computed(() => certsResponse.value?.pagination?.total || 0);
const aggregationErrors = computed(() => certsResponse.value?.errors || []);
const certsErrorMsg = computed(() => certsError.value ? String(certsError.value) : '');
watch(certificates, (list) => {
  hasActiveApplying.value = list.some(c => c.status === 'applying' || c.status === 'validating');
}, { immediate: true });
// ── Persistent ACME jobs and incremental deployment events ─────
const showTaskDrawer = ref(false);
const taskDrawerTab = ref('acme');
// Deep link from the overview: /ssl?tasks=edgeone opens the task drawer on the
// 加速绑定 tab so a drift red-dot click lands exactly where the fix lives.
{
  const q = String(route.query.tasks || '').toLowerCase();
  if (q === 'edgeone' || q === 'bindings') {
    taskDrawerTab.value = 'edgeone';
    showTaskDrawer.value = true;
  }
}
watch(() => route.query.tasks, (val) => {
  const q = String(val || '').toLowerCase();
  if (q === 'edgeone' || q === 'bindings') {
    taskDrawerTab.value = 'edgeone';
    showTaskDrawer.value = true;
  }
});
const deploymentStatusFilter = ref<string | null>(null);
const deploymentSourceFilter = ref<string | null>(null);
const deploymentDomainFilter = ref('');
const { data: acmeJobs, isFetching: acmeJobsFetching } = useQuery({
  queryKey: ['ssl-acme-jobs'],
  queryFn: async () => (await getSslAcmeJobs()).data || [],
  enabled: computed(() => showTaskDrawer.value),
  refetchInterval: computed(() => showTaskDrawer.value ? 5000 : false),
});
const { data: deploymentEvents, isFetching: deploymentEventsFetching } = useQuery({
  queryKey: computed(() => ['ssl-deployment-events', deploymentStatusFilter.value, deploymentSourceFilter.value, deploymentDomainFilter.value]),
  queryFn: async () => (await getSslDeploymentEvents({
    status: deploymentStatusFilter.value || undefined,
    source: deploymentSourceFilter.value || undefined,
    domain: deploymentDomainFilter.value.trim() || undefined,
    limit: 100,
  })).data || [],
  enabled: computed(() => showTaskDrawer.value || certificates.value.length > 0),
  refetchInterval: computed(() => showTaskDrawer.value || hasActiveApplying.value ? 5000 : false),
});

const { data: taskLogs, isFetching: taskLogsFetching } = useQuery({
  queryKey: ['ssl-task-logs'],
  queryFn: async () => (await getSslTaskLogs({ page: 1, limit: 50 })).data || [],
  enabled: computed(() => showTaskDrawer.value),
  refetchInterval: computed(() => showTaskDrawer.value ? 10000 : false),
});
const { data: taskStats } = useQuery({
  queryKey: ['ssl-task-stats'],
  queryFn: async () => (await getSslTaskStats()).data,
  enabled: computed(() => showTaskDrawer.value),
  refetchInterval: computed(() => showTaskDrawer.value ? 10000 : false),
});

// ── Per-site deployment trend (task drawer "站点部署" tab) ─────
const { data: siteDeployments, isFetching: siteDeploymentsFetching } = useQuery({
  queryKey: ['ssl-deployments-by-site'],
  queryFn: async () => (await getSslDeploymentsBySite()).data || [] as SiteDeploymentOverview[],
  enabled: computed(() => showTaskDrawer.value),
  refetchInterval: computed(() => showTaskDrawer.value ? 15000 : false),
});

// ── EdgeOne acceleration certificate bindings (task drawer "加速绑定" tab) ──
// Runs always (not just when the drawer opens) so the toolbar can surface a
// drift red-dot when the CDN edge is serving a stale cert.
const { data: edgeOneBindings, isFetching: edgeOneBindingsFetching } = useQuery({
  queryKey: ['ssl-edgeone-bindings'],
  queryFn: async () => (await getSslEdgeOneBindings()).data || [] as EdgeOneCertBinding[],
  enabled: computed(() => !!selectedCredentialId.value),
  staleTime: 30_000,
  refetchInterval: computed(() => showTaskDrawer.value ? 20000 : 60000),
});

// Bindings whose edge cert is stale or whose last sync failed.
const edgeOneDriftCount = computed(() =>
  (edgeOneBindings.value || []).filter(b =>
    b.status === 'failed' || b.upToDate === false,
  ).length,
);

function openTaskDrawer() {
  // With drift present, land on the 加速绑定 tab where "重新同步" lives.
  taskDrawerTab.value = edgeOneDriftCount.value > 0 ? 'edgeone' : 'acme';
  showTaskDrawer.value = true;
}

// Manual full sync: reconcile every issued cert against its acceleration domains.
const syncEdgeOneMutation = useMutation({
  mutationFn: (payload: { certId?: string; dryRun?: boolean }) => syncSslCertToEdgeOne(payload),
  onSuccess: (res, vars) => {
    const n = res.data?.totalSynced || 0;
    if (vars.dryRun) {
      message.info(`预览：${n} 个加速域名将被绑定`);
    } else {
      message.success(res.message || `已同步 ${n} 个加速域名`);
    }
    queryClient.invalidateQueries({ queryKey: ['ssl-edgeone-bindings'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// Per-row sync from the certificate list.
async function syncCertRowToEdgeOne(row: SslCertificate) {
  try {
    const res = await syncSslCertToEdgeOne({ certId: row.remoteCertId });
    const n = res.data?.totalSynced || 0;
    if (n) {
      message.success(`已将「${row.domain}」同步到 ${n} 个加速域名`);
      queryClient.invalidateQueries({ queryKey: ['ssl-edgeone-bindings'] });
    } else {
      const r = res.data?.results?.[0];
      message.info(r?.skipped || '该域名没有已启用的加速');
    }
  } catch (err: any) {
    message.error(String(err));
  }
}

const showNotificationSettings = ref(false);
const notificationLoading = ref(false);
const notificationForm = ref<SslNotificationSettings>({
  enabled: false, emailEnabled: false, emailTo: '', webhookEnabled: false,
  webhookUrl: '', wecomEnabled: false, wecomWebhookUrl: '', notifySuccessWebhook: false, retentionDays: 30,
});
async function openNotificationSettings() {
  showNotificationSettings.value = true;
  notificationLoading.value = true;
  try {
    const res = await getSslNotificationSettings();
    if (res.data) notificationForm.value = { ...res.data };
  } catch (err: any) {
    message.error(String(err));
  } finally {
    notificationLoading.value = false;
  }
}
const saveNotificationMutation = useMutation({
  mutationFn: () => saveSslNotificationSettings(notificationForm.value),
  onSuccess: () => { message.success('SSL 通知和任务清理设置已保存'); showNotificationSettings.value = false; },
  onError: (err: any) => message.error(String(err)),
});
const testNotificationMutation = useMutation({
  mutationFn: () => testSslNotification(),
  onSuccess: (res) => {
    const failed = (res.data?.deliveries || []).filter(item => !item.success);
    if (failed.length) message.warning(`测试完成，${failed.length} 个通道发送失败`);
    else message.success('所有已启用通知通道测试成功');
  },
  onError: (err: any) => message.error(String(err)),
});
// Run the 30/7/1-day expiry scan immediately (same logic as the daily worker).
const checkExpiryMutation = useMutation({
  mutationFn: () => checkSslExpiry(),
  onSuccess: (res) => {
    const d = res.data;
    message.success(`到期检查完成：检查 ${d?.checked || 0} 个证书，已推送 ${d?.notified || 0} 条提醒`
      + (d?.expired ? `（含已过期 ${d.expired} 个）` : ''));
  },
  onError: (err: any) => message.error(String(err)),
});
async function handleDownloadTaskLogs() {
  try {
    await downloadSslTaskLogs({
      status: deploymentStatusFilter.value || undefined,
      source: deploymentSourceFilter.value || undefined,
      domain: deploymentDomainFilter.value.trim() || undefined,
    });
  } catch (err: any) {
    message.error(String(err));
  }
}

const deploymentByCertificate = computed(() => {
  const result = new Map<string, SslDeploymentEvent>();
  for (const event of deploymentEvents.value || []) {
    result.set(`${event.provider}:${event.remoteCertId}`, event);
  }
  return result;
});

function deploymentFor(row: SslCertificate) {
  return deploymentByCertificate.value.get(`${row.provider || 'tencent_ssl'}:${row.remoteCertId}`);
}

const taskActionMutation = useMutation({
  mutationFn: ({ id, action }: { id: number; action: 'retry' | 'cancel' }) =>
    action === 'retry' ? retrySslAcmeJob(id) : cancelSslAcmeJob(id),
  onSuccess: (_res, variables) => {
    message.success(variables.action === 'retry' ? '任务已重新排队' : '任务已取消');
    queryClient.invalidateQueries({ queryKey: ['ssl-acme-jobs'] });
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const deploymentRetryMutation = useMutation({
  mutationFn: (id: number) => retrySslDeploymentEvent(id),
  onSuccess: () => {
    message.success('部署事件已重新排队，宝塔插件下次同步时会立即处理');
    queryClient.invalidateQueries({ queryKey: ['ssl-deployment-events'] });
  },
  onError: (err: any) => message.error(String(err)),
});

function parseCertDate(v?: string): Date | null {
  if (!v) return null;
  let raw = String(v).trim();
  if (!raw) return null;
  // Backend stores UTC. Legacy rows may lack the timezone designator
  // ("2026-04-24 08:00:00"); JS would parse those as *local* time, shifting
  // the displayed date/time. Normalize to explicit UTC before parsing.
  if (!/[zZ]$|[+-]\d{2}:?\d{2}$/.test(raw)) {
    raw = raw.replace(' ', 'T') + 'Z';
  }
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d;
}

function formatDateTime(v?: string) {
  if (!v) return '-';
  const d = parseCertDate(v);
  if (!d) return v;
  return d.toLocaleString('zh-CN');
}

const jobStatusLabel: Record<SslAcmeJob['status'], string> = {
  queued: '等待中', running: '执行中', success: '成功', failed: '失败', cancelled: '已取消',
};
const deploymentStatusLabel: Record<SslDeploymentEvent['status'], string> = {
  queued: '待部署', running: '部署中', success: '已部署', failed: '部署失败', skipped: '已跳过',
};

// ── Expiring/expired certificate detection ─────────────────────
const expiringCerts = computed(() => {
  const now = new Date();
  const threshold = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  return certificates.value.filter(c => {
    if (!c.notAfter || (c.status !== 'issued' && c.status !== 'expired')) return false;
    const d = parseCertDate(c.notAfter);
    return d ? d <= threshold : false;
  });
});

// ── Status styling ─────────────────────────────────────────────
const statusConfig: Record<SslCertificateStatus, { type: 'success' | 'warning' | 'error' | 'info' | 'default'; label: string }> = {
  applying: { type: 'info', label: '申请中' },
  validating: { type: 'warning', label: '验证中' },
  issued: { type: 'success', label: '已签发' },
  expired: { type: 'error', label: '已过期' },
  failed: { type: 'error', label: '失败' },
  cancelled: { type: 'default', label: '已取消' },
  revoked: { type: 'error', label: '已吊销' },
  upload: { type: 'info', label: '已上传' },
};

function formatDate(v?: string) {
  if (!v) return '-';
  const d = parseCertDate(v);
  if (!d) return v;
  return d.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' });
}

function expiryDaysText(notAfter?: string): { text: string; type: 'success' | 'warning' | 'error' | 'default' } | null {
  if (!notAfter) return null;
  const d = parseCertDate(notAfter);
  if (!d) return null;
  try {
    const diff = Math.floor((d.getTime() - Date.now()) / 86400000);
    if (diff < 0) return { text: `已过期 ${Math.abs(diff)} 天`, type: 'error' };
    if (diff <= 7) return { text: `剩余 ${diff} 天`, type: 'error' };
    if (diff <= 30) return { text: `剩余 ${diff} 天`, type: 'warning' };
    return { text: `剩余 ${diff} 天`, type: 'success' };
  } catch { return null; }
}

function withinDays(notAfter?: string, days = 30): boolean {
  const d = parseCertDate(notAfter);
  if (!d) return false;
  return d.getTime() - Date.now() < days * 86400000;
}

// ── Status filter ───────────────────────────────────────────────
watch([selectedCredentialId, searchKeyword, filterCredentialId, statusFilter, sourceFilter, channelTab], () => { page.value = 1; });

const statusCounts = computed(() => certsResponse.value?.statusSummary || certificates.value.reduce((counts, cert) => {
  counts[cert.status] = (counts[cert.status] || 0) + 1;
  return counts;
}, {} as Record<string, number>));
const sourceCounts = computed(() => certsResponse.value?.sourceSummary || {});
const statusTotal = computed(() => Object.values(statusCounts.value).reduce((sum, count) => sum + count, 0));

async function toggleCertificateAutoRenew(cert: SslCertificate) {
  if (!cert.credentialId) return;
  const enabled = !cert.autoRenew;
  try {
    await setCertificateAutoRenew(cert.credentialId, cert.remoteCertId, enabled);
    message.success(cert.provider === 'acme'
      ? `该证书自动续期已${enabled ? '开启' : '关闭'}`
      : `腾讯云自动续费已${enabled ? '开启' : '关闭'}`);
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  } catch (err) {
    message.error(String(err));
  }
}

const filteredCertificates = computed(() => {
  if (selectedCredentialId.value === 'all') return certificates.value;
  if (!statusFilter.value) return certificates.value;
  return certificates.value.filter(c => c.status === statusFilter.value);
});

// ── Client-side sorting ─────────────────────────────────────────
const sortBy = ref<'domain' | 'notAfter' | 'status' | 'remoteCreatedAt'>('notAfter');
const sortAsc = ref(true);

const sortOptions = [
  { label: '过期时间', value: 'notAfter' },
  { label: '域名', value: 'domain' },
  { label: '状态', value: 'status' },
  { label: '创建时间', value: 'remoteCreatedAt' },
];

const statusOrder: Record<string, number> = {
  validating: 0, applying: 1, issued: 2, expired: 3, failed: 4, cancelled: 5, revoked: 6, upload: 7,
};

const sortedCertificates = computed(() => {
  const list = [...filteredCertificates.value];
  const dir = sortAsc.value ? 1 : -1;
  list.sort((a, b) => {
    let cmp = 0;
    if (sortBy.value === 'domain') {
      cmp = (a.domain || '').localeCompare(b.domain || '');
    } else if (sortBy.value === 'notAfter') {
      const ta = parseCertDate(a.notAfter)?.getTime() ?? Number.MAX_SAFE_INTEGER;
      const tb = parseCertDate(b.notAfter)?.getTime() ?? Number.MAX_SAFE_INTEGER;
      cmp = ta - tb;
    } else if (sortBy.value === 'status') {
      cmp = (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99);
    } else if (sortBy.value === 'remoteCreatedAt') {
      const ta = parseCertDate(a.remoteCreatedAt)?.getTime() ?? 0;
      const tb = parseCertDate(b.remoteCreatedAt)?.getTime() ?? 0;
      cmp = ta - tb;
    }
    return cmp * dir;
  });
  return list;
});

// ── Batch operations ────────────────────────────────────────────
const checkedRowKeys = ref<string[]>([]);
const batchDeleting = ref(false);

watch([selectedCredentialId, statusFilter], () => { checkedRowKeys.value = []; });

async function handleBatchDelete() {
  const keys = checkedRowKeys.value;
  if (!keys.length) return;
  dialog.warning({
    title: '批量删除证书',
    content: `确定要删除选中的 ${keys.length} 个证书吗？此操作不可撤销。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      batchDeleting.value = true;
      let ok = 0;
      let fail = 0;
      for (const certId of keys) {
        const cert = certificates.value.find(c => c.remoteCertId === certId);
        const credId = cert ? getCredIdForCert(cert) : null;
        if (!credId) { fail++; continue; }
        try {
          await deleteSslCertificate(credId, certId);
          ok++;
        } catch {
          fail++;
        }
      }
      batchDeleting.value = false;
      checkedRowKeys.value = [];
      queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
      message.success(`批量删除完成：成功 ${ok}${fail > 0 ? `，失败 ${fail}` : ''}`);
    },
  });
}

// ── Batch deploy / batch auto-renew ────────────────────────────
const batchDeployMutation = useMutation({
  mutationFn: (certIds: string[]) => batchDeploySslCertificates(certIds),
  onSuccess: (res) => {
    const d = res.data;
    message.success(`批量部署：${d?.queued?.length || 0} 个已入队`
      + (d?.skipped?.length ? `，${d.skipped.length} 个跳过` : '')
      + (d?.errors?.length ? `，${d.errors.length} 个失败` : ''));
    checkedRowKeys.value = [];
    queryClient.invalidateQueries({ queryKey: ['ssl-deployment-events'] });
  },
  onError: (err: any) => message.error(String(err)),
});

const batchAutoRenewMutation = useMutation({
  mutationFn: (vars: { certIds: string[]; enabled: boolean }) => batchSetSslAutoRenew(vars.certIds, vars.enabled),
  onSuccess: (res, vars) => {
    const d = res.data;
    message.success(`批量${vars.enabled ? '开启' : '关闭'}自动续费：${d?.updated?.length || 0} 个成功`
      + (d?.skipped?.length ? `，${d.skipped.length} 个跳过` : '')
      + (d?.errors?.length ? `，${d.errors.length} 个失败` : ''));
    checkedRowKeys.value = [];
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

function handleBatchDeploy() {
  const deployable = checkedRowKeys.value.filter((id) => {
    const cert = certificates.value.find(c => c.remoteCertId === id);
    return cert && cert.status === 'issued';
  });
  if (!deployable.length) {
    message.warning('选中的证书中没有可部署（已签发）的证书');
    return;
  }
  dialog.info({
    title: '批量部署证书',
    content: `将 ${deployable.length} 个证书加入部署队列？宝塔插件下次同步时自动部署到匹配站点。`,
    positiveText: '加入部署队列',
    negativeText: '取消',
    onPositiveClick: () => batchDeployMutation.mutate(deployable),
  });
}

function handleBatchAutoRenew(enabled: boolean) {
  if (!checkedRowKeys.value.length) return;
  batchAutoRenewMutation.mutate({ certIds: [...checkedRowKeys.value], enabled });
}

// ── CSV export ──────────────────────────────────────────────────
function exportCsv() {
  const rows = sortedCertificates.value;
  if (!rows.length) {
    message.warning('没有可导出的数据');
    return;
  }
  const header = ['域名', '状态', '产品类型', '颁发者', '生效时间', '过期时间', '账号', '证书ID'];
  const csvRows = rows.map(r => [
    r.domain || '',
    (statusConfig[r.status] || statusConfig.applying).label,
    r.productName || r.certType || '',
    r.issuer || '',
    r.notBefore || '',
    r.notAfter || '',
    r.credentialName || credNameById(r.credentialId) || '',
    r.remoteCertId || '',
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
  const csv = '\uFEFF' + header.join(',') + '\n' + csvRows.join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ssl-certificates-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  message.success(`已导出 ${rows.length} 条证书记录`);
}

// ── DNS record cleanup ──────────────────────────────────────────
const cleanupDnsLoading = ref(false);

async function cleanupDnsForDetail() {
  const credId = detailCredentialId.value;
  const certId = detailData.value?.remoteCertId;
  if (!credId || !certId) {
    message.error('缺少凭证或证书 ID');
    return;
  }
  dialog.warning({
    title: '清理 DNS 验证记录',
    content: '将删除该证书关联的所有 DNS 验证记录（CNAME/TXT）。确定继续？',
    positiveText: '清理',
    negativeText: '取消',
    onPositiveClick: async () => {
      cleanupDnsLoading.value = true;
      try {
        const res = await cleanupDnsSslCertificate(credId, certId);
        const d = res.data;
        if (d?.deleted?.length) {
          message.success(`已清理 ${d.deleted.length} 条 DNS 验证记录`);
        } else {
          message.info('未找到可清理的验证记录');
        }
        if (d?.errors?.length) {
          for (const e of d.errors) {
            message.warning(e.error || e.key);
          }
        }
      } catch (err: any) {
        message.error(String(err));
      } finally {
        cleanupDnsLoading.value = false;
      }
    },
  });
}

// ── DNS credentials for auto-DNS ───────────────────────────────
const { data: dnsCredentials } = useQuery({
  queryKey: ['dns-credentials-for-ssl'],
  queryFn: async () => {
    const res = await getDnsCredentials();
    return res.data?.credentials || [];
  },
});

const zoneManageCredentials = computed(() =>
  (dnsCredentials.value || []).filter(c => ['cloudflare', 'dnspod', 'dnspod_token'].includes(String(c.provider))),
);

const dnsCredentialOptions = computed(() =>
  (zoneManageCredentials.value || []).map(c => ({
    label: `${c.name} (${c.provider})`,
    value: c.id,
  })),
);

function normalizeDomainInput(raw: string): string {
  let s = String(raw || '').trim();
  if (!s) return '';
  s = s.replace(/^https?:\/\//i, '');
  s = s.replace(/\/.*$/, '');
  s = s.replace(/:\d+$/, '');
  s = s.replace(/\.$/, '');
  return s.toLowerCase();
}

type ManagedDomain = Domain & { credentialName?: string; provider?: string };

const { data: managedDomains, isLoading: managedDomainsLoading } = useQuery({
  queryKey: computed(() => ['managed-domains-for-ssl', zoneManageCredentials.value.map(c => c.id).join(',')]),
  queryFn: async () => {
    const creds = zoneManageCredentials.value;
    if (!creds.length) return [] as ManagedDomain[];
    const all: ManagedDomain[] = [];
    await Promise.all(creds.map(async (cred) => {
      try {
        const res = await getDomains(cred.id);
        const list = res.data?.domains || [];
        for (const d of list) {
          all.push({
            ...d,
            credentialId: cred.id,
            credentialName: cred.name,
            provider: String(cred.provider),
          });
        }
      } catch {
        // ignore unsupported/failed credentials
      }
    }));
    const uniq = new Map<string, ManagedDomain>();
    for (const d of all) {
      const key = normalizeDomainInput(d.name);
      if (!key) continue;
      if (!uniq.has(key)) uniq.set(key, d);
    }
    return Array.from(uniq.values()).sort((a, b) => a.name.localeCompare(b.name));
  },
  enabled: computed(() => zoneManageCredentials.value.length > 0),
  staleTime: 60 * 1000,
});

function findBestManagedZone(domain: string): ManagedDomain | null {
  const d0 = normalizeDomainInput(domain).replace(/^\*\./, '');
  if (!d0) return null;
  let best: ManagedDomain | null = null;
  for (const z of managedDomains.value || []) {
    const zn = normalizeDomainInput(z.name);
    if (!zn) continue;
    if (d0 === zn || d0.endsWith(`.${zn}`)) {
      if (!best || zn.length > normalizeDomainInput(best.name).length) best = z;
    }
  }
  return best;
}

function isManagedDomain(domain: string): boolean {
  return !!findBestManagedZone(domain);
}

// ── Add Zone dialog (domain management shortcut) ────────────────
const showAddZone = ref(false);
const addZoneInitialText = ref('');
const addZoneInitialCredId = ref<number | undefined>(undefined);

function openAddZoneForDomain(domain: string) {
  const normalized = normalizeDomainInput(domain).replace(/^\*\./, '');
  if (!normalized) {
    message.error('域名为空');
    return;
  }
  if (!zoneManageCredentials.value.length) {
    message.warning('暂无可用的 DNS 凭证用于添加域名（仅 Cloudflare / DNSPod 支持）');
    return;
  }
  addZoneInitialText.value = normalized;
  addZoneInitialCredId.value = zoneManageCredentials.value[0]?.id;
  showAddZone.value = true;
}

// ── Apply modal ────────────────────────────────────────────────
const showApply = ref(false);
// Issuance channel: 'tencent' = 腾讯云 DV, 'acme' = Let's Encrypt (acme.sh).
const applyChannel = ref<'tencent' | 'acme'>(isLetsEncryptPage.value ? 'acme' : 'tencent');
const applyDomain = ref('');
const applyDomainMode = ref<'managed' | 'manual'>('managed');
const applyManagedRoot = ref<string | null>(null);
const applySubdomain = ref('');
const applyWildcard = ref(false);
const applyDvMethod = ref<string>('DNS');
const applyDnsCredId = ref<number | null>(null);
const applyAutoDns = ref(true);
const applyDnsCredTouched = ref(false);
const applyOldCertId = ref<string | null>(null);
const applySslCredId = ref<number | null>(null);
const _settingApplyDnsCredId = ref(false);
// acme-specific: key type and the DNS credential used for the DNS-01 challenge.
const applyAcmeKeyLength = ref<string>('2048');
const applyAcmeDnsCredId = ref<number | null>(null);

const channelOptions = [
  { label: '腾讯云 DV（TrustAsia 免费证书）', value: 'tencent' },
  { label: "Let's Encrypt（acme.sh，DNS-01 自动验证）", value: 'acme' },
];

const acmeKeyLengthOptions = [
  { label: 'RSA 2048', value: '2048' },
  { label: 'RSA 4096', value: '4096' },
  { label: 'ECC 256（ec-256）', value: 'ec-256' },
  { label: 'ECC 384（ec-384）', value: 'ec-384' },
];

// ── CA selection (Let's Encrypt / ZeroSSL / Buypass) ──────────
const applyAcmeCa = ref<string>('letsencrypt');
const applyAcmeEabKid = ref('');
const applyAcmeEabHmac = ref('');
const { data: acmeCasData } = useQuery({
  queryKey: ['ssl-acme-cas'],
  queryFn: async () => (await getSslAcmeCas()).data,
  staleTime: 3600_000,
});
const acmeCaOptions = computed(() =>
  (acmeCasData.value?.cas || [{ value: 'letsencrypt', label: "Let's Encrypt" }])
    .map((c: SslCaOption) => ({ label: c.label, value: c.value })),
);
const applyAcmeCaRequiresEab = computed(() =>
  !!acmeCasData.value?.cas?.find(c => c.value === applyAcmeCa.value)?.requiresEab,
);

// acme.sh can drive Cloudflare / DNSPod / 阿里云 for the DNS-01 challenge.
const acmeDnsCredentials = computed(() =>
  (dnsCredentials.value || []).filter(c =>
    ['cloudflare', 'dnspod', 'dnspod_token', 'aliyun'].includes(String(c.provider))),
);

const acmeDnsCredentialOptions = computed(() =>
  (acmeDnsCredentials.value || []).map(c => ({
    label: `${c.name} (${c.provider})`,
    value: c.id,
  })),
);

function setApplyDnsCredId(val: number | null) {
  _settingApplyDnsCredId.value = true;
  applyDnsCredId.value = val;
  _settingApplyDnsCredId.value = false;
}

watch(applyDnsCredId, () => {
  if (_settingApplyDnsCredId.value) return;
  if (!showApply.value) return;
  applyDnsCredTouched.value = true;
});

const managedDomainOptions = computed(() =>
  (managedDomains.value || []).map(d => ({
    label: d.credentialName ? `${d.name} · ${d.credentialName}` : d.name,
    value: d.name,
  })),
);

const applyFinalDomain = computed(() => {
  if (applyDomainMode.value === 'managed') {
    const root = normalizeDomainInput(applyManagedRoot.value || '');
    if (!root) return '';
    const sub = normalizeDomainInput(applySubdomain.value).replace(/\.+$/, '');
    if (applyWildcard.value && !sub) return `*.${root}`;
    if (sub) return `${sub}.${root}`;
    return root;
  }
  return normalizeDomainInput(applyDomain.value);
});

const applyManagedHint = computed(() => {
  const d = applyFinalDomain.value;
  if (!d) return null;
  return findBestManagedZone(d);
});

watch([showApply, applyFinalDomain, applyAutoDns, applyDvMethod], () => {
  if (!showApply.value) return;
  if (applyDvMethod.value !== 'DNS') return;
  if (!applyAutoDns.value) return;
  if (applyDnsCredTouched.value) return;
  const best = findBestManagedZone(applyFinalDomain.value);
  const bestCredId = typeof best?.credentialId === 'number' ? best.credentialId : null;
  setApplyDnsCredId(bestCredId);
}, { immediate: true });

const dvMethodOptions = [
  { label: 'DNS 验证（推荐，支持 Cloudflare / DNSPod 自动添加记录）', value: 'DNS' },
  { label: 'DNS 自动验证（仅限域名 NS 已指向 DNSPod）', value: 'DNS_AUTO' },
  { label: '文件验证', value: 'FILE' },
];

const applyEffectiveCredId = computed(() => {
  if (selectedCredentialId.value !== 'all') return selectedCredentialId.value;
  return applySslCredId.value;
});

const applyMutation = useMutation({
  mutationFn: () => {
    const credId = applyEffectiveCredId.value;
    if (!credId) throw new Error('请先选择一个具体的 SSL 凭证（不能使用"全部账号"）');
    const finalDomain = applyFinalDomain.value;
    if (!finalDomain) throw new Error('请选择或输入域名');
    const isDns = applyDvMethod.value === 'DNS';
    const hasDnsCred = isDns && applyAutoDns.value && !!applyDnsCredId.value;
    const autoMatch = isDns && applyAutoDns.value && !applyDnsCredId.value;
    return applySslCertificate({
      credentialId: credId,
      domain: finalDomain,
      dvAuthMethod: applyDvMethod.value as any,
      dnsCredentialId: hasDnsCred ? applyDnsCredId.value! : undefined,
      autoDnsRecord: applyAutoDns.value && isDns,
      autoMatchDns: autoMatch,
      oldCertificateId: applyOldCertId.value || undefined,
    });
  },
  onSuccess: (res) => {
    const certId = res.data?.CertificateId || '';
    const added = res.data?.dnsRecordsAdded || [];
    const dnsErrs = res.data?.dnsErrors || [];
    const credId = applyEffectiveCredId.value;
    const isDns = applyDvMethod.value === 'DNS';
    const isManualDns = isDns && !applyAutoDns.value;
    let msg = `证书申请已提交，ID: ${certId}`;
    if (added.length > 0) msg += `\n已自动添加 ${added.length} 条 DNS 验证记录`;
    if (dnsErrs.length > 0) msg += `\n${dnsErrs.length} 条 DNS 记录添加失败`;
    message.success(msg);
    showApply.value = false;
    applyDomain.value = '';
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });

    if (certId && credId && typeof credId === 'number' && (isManualDns || dnsErrs.length > 0)) {
      if (dnsErrs.length > 0) {
        message.warning('自动添加 DNS 记录未完全成功：已为你打开证书详情，可手动补齐 DNS 记录后点击「检测并提交验证」。');
      } else {
        message.info('已进入手动验证步骤：请按证书详情中的提示添加 DNS 记录，然后点击「检测并提交验证」。');
      }
      openDetailById(credId, certId);
    }
  },
  onError: (err: any) => message.error(String(err)),
});

// acme.sh (Let's Encrypt) issuance — async on the backend: it returns an
// 'applying' cert immediately, then finishes in a worker after DNS-01 validates.
const acmeMutation = useMutation({
  mutationFn: () => {
    const finalDomain = applyFinalDomain.value;
    if (!finalDomain) throw new Error('请选择或输入域名');
    if (!applyAcmeDnsCredId.value) throw new Error('请选择用于 DNS 验证的 DNS 凭证（Cloudflare / DNSPod / 阿里云）');
    if (applyAcmeCaRequiresEab.value && (!applyAcmeEabKid.value.trim() || !applyAcmeEabHmac.value.trim())) {
      throw new Error('该 CA（如 ZeroSSL）需要 EAB 凭据，请填写 EAB Key ID 和 HMAC Key');
    }
    return issueAcmeCertificate({
      dnsCredentialId: applyAcmeDnsCredId.value,
      domain: finalDomain,
      keyLength: applyAcmeKeyLength.value,
      ca: applyAcmeCa.value || undefined,
      eabKid: applyAcmeEabKid.value.trim() || undefined,
      eabHmac: applyAcmeEabHmac.value.trim() || undefined,
    });
  },
  onSuccess: (res) => {
    message.success(res.message || "已开始通过 Let's Encrypt 签发，请稍后刷新列表查看结果");
    showApply.value = false;
    applyDomain.value = '';
    selectedCredentialId.value = 'all';
    filterCredentialId.value = null;
    statusFilter.value = null;
    page.value = 1;
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// Dispatch apply to the right channel.
function submitApply() {
  if (applyChannel.value === 'acme') {
    acmeMutation.mutate();
  } else {
    applyMutation.mutate();
  }
}

// ── Quick re-apply for expired/expiring certs ──────────────────
function quickReapply(cert: SslCertificate) {
  const credId = getCredIdForCert(cert);
  if (!credId) {
    message.error('无法确定凭证，请在单一账号下操作');
    return;
  }
  selectedCredentialId.value = cert.provider === 'acme' ? 'all' : credId;
  applySslCredId.value = cert.provider === 'acme' ? null : credId;
  // Re-apply keeps the cert's original channel so renewal flows stay consistent.
  applyChannel.value = cert.provider === 'acme' ? 'acme' : 'tencent';
  applyDomain.value = cert.domain || '';
  applyDomainMode.value = 'manual';
  applyManagedRoot.value = null;
  applySubdomain.value = '';
  applyWildcard.value = cert.domain?.startsWith('*.') || false;
  applyDvMethod.value = 'DNS';
  applyAutoDns.value = true;
  applyDnsCredTouched.value = false;
  setApplyDnsCredId(null);
  // For acme re-issue, preselect the DNS credential the cert was issued with.
  applyAcmeDnsCredId.value = cert.provider === 'acme' && typeof cert.credentialId === 'number'
    ? cert.credentialId : (acmeDnsCredentialOptions.value[0]?.value ?? null);
  applyAcmeKeyLength.value = cert.provider === 'acme' && cert.keyLength ? cert.keyLength : '2048';
  // Preserve the certificate's original CA on re-issue (defaults to LE).
  applyAcmeCa.value = cert.provider === 'acme' && cert.ca ? cert.ca : 'letsencrypt';
  applyAcmeEabKid.value = '';
  applyAcmeEabHmac.value = '';
  // Pass old cert ID for Tencent renewal flow (only for issued tencent certs).
  // acme re-issue ignores it, so never set it for acme certs.
  applyOldCertId.value = cert.provider !== 'acme' && cert.status === 'issued' ? cert.remoteCertId : null;
  showApply.value = true;
}

function openApply() {
  // Channel follows the active tab: within 腾讯云 tab apply via Tencent DV,
  // within Let's Encrypt tab via acme.sh; on 全部 let the user choose.
  if (channelTab.value === 'tencent') {
    applyChannel.value = 'tencent';
  } else if (channelTab.value === 'letsencrypt') {
    applyChannel.value = 'acme';
  } else {
    applyChannel.value = (sslCredentials.value || []).length > 0 ? 'tencent' : 'acme';
  }
  applyDomain.value = '';
  applyDomainMode.value = managedDomainOptions.value.length > 0 ? 'managed' : 'manual';
  applyManagedRoot.value = managedDomainOptions.value.length > 0 ? managedDomainOptions.value[0].value : null;
  applySubdomain.value = '';
  applyWildcard.value = false;
  applyDvMethod.value = 'DNS';
  applyAutoDns.value = true;
  applyDnsCredTouched.value = false;
  setApplyDnsCredId(null);
  applyOldCertId.value = null;
  applySslCredId.value = selectedCredentialId.value === 'all'
    ? (sslCredentials.value?.[0]?.id ?? null)
    : selectedCredentialId.value;
  applyAcmeKeyLength.value = '2048';
  applyAcmeCa.value = 'letsencrypt';
  applyAcmeEabKid.value = '';
  applyAcmeEabHmac.value = '';
  applyAcmeDnsCredId.value = acmeDnsCredentialOptions.value[0]?.value ?? null;
  showApply.value = true;
}

// ── Upload modal ───────────────────────────────────────────────
const showUpload = ref(false);
const uploadPublicKey = ref('');
const uploadPrivateKey = ref('');
const uploadAlias = ref('');

const uploadMutation = useMutation({
  mutationFn: () => {
    const credId = applyEffectiveCredId.value;
    if (!credId) throw new Error('请先选择一个具体的 SSL 凭证');
    return uploadSslCertificate({
      credentialId: credId,
      publicKey: uploadPublicKey.value,
      privateKey: uploadPrivateKey.value,
      alias: uploadAlias.value || undefined,
    });
  },
  onSuccess: () => {
    message.success('证书上传成功');
    showUpload.value = false;
    uploadPublicKey.value = '';
    uploadPrivateKey.value = '';
    uploadAlias.value = '';
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// ── Sync ───────────────────────────────────────────────────────
const reconcileMutation = useMutation({
  mutationFn: () => reconcileSslCertificates(selectedCredentialId.value === 'all' ? 'all' : (selectedCredentialId.value || undefined)),
  onSuccess: (res) => {
    const d = res.data;
    message.success(`状态检查完成${d?.failed ? `，${d.failed} 个账号失败` : ''}`);
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// ── Clean dead cloud certificates (expired / revoked / failed) ──
const cleanExpiredOptions = [
  { label: '预览（不删除）', key: 'preview' },
  { label: '清理已被替代的失效证书', key: 'clean' },
  { label: `仅清理失效超过 30 天的`, key: 'stale30' },
];

const cleanExpiredMutation = useMutation({
  mutationFn: (payload: { dryRun?: boolean; staleDays?: number }) => cleanExpiredSslCertificates(payload),
  onSuccess: (res, variables) => {
    const d = res.data;
    if (variables.dryRun) {
      const count = d?.cleaned?.length || 0;
      const kept = d?.kept?.length || 0;
      if (count) {
        dialog.info({
          title: '清理预览',
          content: `将清理 ${count} 个失效证书${kept ? `，保留 ${kept} 个（域名暂无有效证书）` : ''}。确认后可点击「清理已被替代的失效证书」执行。`,
          positiveText: '知道了',
        });
      } else {
        message.success(`没有可清理的失效证书${kept ? `（${kept} 个因域名暂无有效证书被保留）` : ''}`);
      }
      return;
    }
    const count = d?.cleaned?.length || 0;
    const failed = d?.errors?.length || 0;
    message.success(`已清理 ${count} 个失效证书${failed ? `，${failed} 个失败` : ''}`);
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

function handleCleanExpired(key: string) {
  if (key === 'preview') {
    cleanExpiredMutation.mutate({ dryRun: true });
  } else if (key === 'stale30') {
    cleanExpiredMutation.mutate({ staleDays: 30, dryRun: false });
  } else {
    cleanExpiredMutation.mutate({ dryRun: false });
  }
}

const syncMutation = useMutation({
  mutationFn: () => {
    const credId = applyEffectiveCredId.value;
    if (!credId) throw new Error('请先选择一个具体的 SSL 凭证');
    return syncSslCertificates(credId);
  },
  onSuccess: (res) => {
    message.success(res.message || '同步完成');
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
  },
  onError: (err: any) => message.error(String(err)),
});

// ── Auto-renew expired ────────────────────────────────────────
const showRenewModal = ref(false);
const renewDnsCredId = ref<number | null>(null);
const renewDays = ref(30);
const showRenewResult = ref(false);
const renewResultData = ref<RenewResult | null>(null);

const renewMutation = useMutation({
  mutationFn: () => renewExpiredCertificates({
    renewDays: renewDays.value,
    dnsCredentialId: renewDnsCredId.value || undefined,
  }),
  onSuccess: (res) => {
    const r = res.data;
    showRenewModal.value = false;
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
    if (!r || (r.renewed.length === 0 && r.failed.length === 0 && r.skipped.length === 0)) {
      message.success('无需续期的证书');
      return;
    }
    renewResultData.value = r;
    showRenewResult.value = true;
  },
  onError: (err: any) => message.error(String(err)),
});

function openRenew() {
  renewDnsCredId.value = null;
  renewDays.value = 30;
  showRenewModal.value = true;
}

// ── Auto-renew toggle (panel-side daily scheduler) ─────────────
const { data: autoRenewData, refetch: refetchAutoRenew } = useQuery({
  queryKey: ['ssl-auto-renew'],
  queryFn: async () => {
    const res = await getSslAutoRenew();
    return res.data || { enabled: false, days: 7 };
  },
  staleTime: 60_000,
});
const autoRenewEnabled = computed(() => !!autoRenewData.value?.enabled);
const autoRenewToggling = ref(false);
async function toggleAutoRenew(val: boolean) {
  autoRenewToggling.value = true;
  try {
    await setSslAutoRenew(val, autoRenewData.value?.days || 7);
    await refetchAutoRenew();
    message.success(val ? '已开启自动续期：每日检查，剩余 ≤7 天自动续期并清理过期证书' : '已关闭自动续期');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    autoRenewToggling.value = false;
  }
}

// ── Detail drawer ──────────────────────────────────────────────
const showDetail = ref(false);
const detailData = ref<SslCertificateDetail | null>(null);
const detailLoading = ref(false);
const detailCredentialId = ref<number | null>(null);

async function openDetail(cert: SslCertificate) {
  const credId = cert.credentialId || (selectedCredentialId.value !== 'all' ? selectedCredentialId.value : null);
  if (!credId || typeof credId !== 'number') {
    message.error('无法确定该证书的凭证');
    return;
  }
  showDetail.value = true;
  detailLoading.value = true;
  detailCredentialId.value = credId;
  try {
    const res = await getSslCertificateDetail(credId, cert.remoteCertId);
    detailData.value = res.data ? ({ ...res.data, credentialId: credId } as any) : null;
  } catch (err: any) {
    message.error(String(err));
  } finally {
    detailLoading.value = false;
  }
}

async function openDetailById(credId: number, certId: string) {
  if (!credId || !certId) return;
  showDetail.value = true;
  detailLoading.value = true;
  detailCredentialId.value = credId;
  try {
    const res = await getSslCertificateDetail(credId, certId);
    detailData.value = res.data ? ({ ...res.data, credentialId: credId } as any) : null;
  } catch (err: any) {
    message.error(String(err));
  } finally {
    detailLoading.value = false;
  }
}

async function refreshDetail() {
  const credId = detailCredentialId.value;
  const certId = detailData.value?.remoteCertId;
  if (!credId || !certId) {
    message.error('无法刷新详情：缺少凭证或证书 ID');
    return;
  }
  detailLoading.value = true;
  try {
    const res = await getSslCertificateDetail(credId, certId);
    detailData.value = res.data ? ({ ...res.data, credentialId: credId } as any) : null;
  } catch (err: any) {
    message.error(String(err));
  } finally {
    detailLoading.value = false;
  }
}

async function checkAndCompleteDetail() {
  const credId = detailCredentialId.value;
  const certId = detailData.value?.remoteCertId;
  if (!credId || !certId) {
    message.error('无法提交验证：缺少凭证或证书 ID');
    return;
  }
  try {
    await completeSslCertificate(credId, certId);
    message.success('已提交域名验证');
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
    await new Promise((r) => setTimeout(r, 1200));
    await refreshDetail();
  } catch (err: any) {
    message.error(String(err));
  }
}

// ── Auto-DNS for existing cert from detail drawer ───────────
const autoDnsLoading = ref(false);

async function autoDnsForDetail() {
  const credId = detailCredentialId.value;
  const certId = detailData.value?.remoteCertId;
  if (!credId || !certId) {
    message.error('缺少凭证或证书 ID');
    return;
  }
  autoDnsLoading.value = true;
  try {
    const res = await autoDnsSslCertificate(credId, certId);
    const d = res.data;
    if (d?.dnsRecordsAdded?.length) {
      message.success(`已添加 ${d.dnsRecordsAdded.length} 条 DNS 验证记录${d.completed ? '，已自动提交验证' : ''}`);
    } else {
      message.warning('未能添加任何 DNS 记录');
    }
    if (d?.dnsErrors?.length) {
      for (const e of d.dnsErrors) {
        message.error(e.error || e.key);
      }
    }
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
    await new Promise((r) => setTimeout(r, 1000));
    await refreshDetail();
  } catch (err: any) {
    message.error(String(err));
  } finally {
    autoDnsLoading.value = false;
  }
}

// ── Copy to clipboard helper ────────────────────────────────
function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(
    () => message.success('已复制到剪贴板'),
    () => message.error('复制失败'),
  );
}

// ── Auto-polling for applying/validating certs ──────────────
let detailPollTimer: ReturnType<typeof setInterval> | null = null;

function startDetailPoll() {
  stopDetailPoll();
  detailPollTimer = setInterval(async () => {
    if (!showDetail.value || !detailData.value || detailLoading.value) return;
    const st = detailData.value.status;
    if (st !== 'applying' && st !== 'validating') {
      stopDetailPoll();
      return;
    }
    try {
      const credId = detailCredentialId.value;
      const certId = detailData.value.remoteCertId;
      if (!credId || !certId) return;
      const res = await getSslCertificateDetail(credId, certId);
      if (res.data) {
        detailData.value = { ...res.data, credentialId: credId } as any;
        if (res.data.status !== 'applying' && res.data.status !== 'validating') {
          stopDetailPoll();
          queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
          if (res.data.status === 'issued') {
            message.success('证书已签发！');
          }
        }
      }
    } catch {
      // silent — next poll will retry
    }
  }, 10000);
}

function stopDetailPoll() {
  if (detailPollTimer) {
    clearInterval(detailPollTimer);
    detailPollTimer = null;
  }
}

watch(showDetail, (visible) => {
  if (!visible) stopDetailPoll();
});

watch(() => detailData.value?.status, (st) => {
  if (st === 'applying' || st === 'validating') {
    startDetailPoll();
  } else {
    stopDetailPoll();
  }
});

onUnmounted(() => stopDetailPoll());

// ── Detail drawer: has DNS credentials check ────────────────
const detailHasDnsCreds = computed(() => {
  return (zoneManageCredentials.value || []).length > 0;
});

// ── Actions ────────────────────────────────────────────────────
function getCredIdForCert(cert: SslCertificate): number | null {
  return cert.credentialId || (selectedCredentialId.value !== 'all' ? selectedCredentialId.value as number : null);
}

function handleDownload(cert: SslCertificate) {
  const credId = getCredIdForCert(cert);
  if (!credId) { message.error('无法确定凭证'); return; }
  downloadSslCertificate(credId, cert.remoteCertId).catch((err: any) => message.error(String(err)));
}

// ── Online certificate viewer (no download) ────────────────────
const showCertView = ref(false);
const certViewLoading = ref(false);
const certViewData = ref<{ certId: string; domain: string; credentialId: number; publicKey: string; meta: Record<string, any> } | null>(null);

async function openCertView(cert: SslCertificate) {
  const credId = getCredIdForCert(cert) || (typeof cert.credentialId === 'number' ? cert.credentialId : 0);
  if (!credId) { message.error('无法确定凭证'); return; }
  showCertView.value = true;
  certViewLoading.value = true;
  certViewData.value = null;
  try {
    const res = await viewSslCertificate(credId, cert.remoteCertId);
    certViewData.value = {
      certId: cert.remoteCertId,
      domain: cert.domain || cert.remoteCertId,
      credentialId: credId,
      publicKey: res.data?.publicKey || '',
      meta: (res.data?.meta || {}) as Record<string, any>,
    };
  } catch (err: any) {
    message.error(String(err));
  } finally {
    certViewLoading.value = false;
  }
}

function downloadViewedCert() {
  const d = certViewData.value;
  if (!d) return;
  downloadSslCertificate(d.credentialId, d.certId).catch((err: any) => message.error(String(err)));
}

async function copyCertPem() {
  const pem = certViewData.value?.publicKey;
  if (!pem) return;
  try {
    await navigator.clipboard.writeText(pem);
    message.success('证书内容已复制到剪贴板');
  } catch {
    message.error('复制失败，请手动选择复制');
  }
}

// ── Manual deploy (queues a deployment event for the BaoTa plugin) ──
const deployMutation = useMutation({
  mutationFn: (certId: string) => deploySslCertificate(certId),
  onSuccess: (res) => {
    message.success(res.message || '已加入部署队列：宝塔插件下次同步时自动部署到匹配站点');
    queryClient.invalidateQueries({ queryKey: ['ssl-deployment-events'] });
  },
  onError: (err: any) => message.error(String(err)),
});

function handleDeploy(cert: SslCertificate) {
  dialog.info({
    title: '部署证书',
    content: cert.provider === 'acme'
      ? `将 ${cert.domain} 加入部署队列：宝塔插件下次同步时自动部署到匹配站点（可在「任务」中查看部署结果与目标站点）。`
      : `将 ${cert.domain} 加入部署队列：宝塔插件下次同步时自动部署到匹配站点（可在「任务」中查看部署结果与目标站点）。`,
    positiveText: '加入部署队列',
    negativeText: '取消',
    onPositiveClick: () => deployMutation.mutate(cert.remoteCertId),
  });
}

function handleComplete(cert: SslCertificate) {
  const credId = getCredIdForCert(cert);
  if (!credId) { message.error('无法确定凭证'); return; }
  dialog.info({
    title: '提交域名验证',
    content: `确认对 ${cert.domain || cert.remoteCertId} 提交域名验证？`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await completeSslCertificate(credId, cert.remoteCertId);
        message.success('域名验证已提交');
        queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}

function handleDelete(cert: SslCertificate) {
  const credId = getCredIdForCert(cert);
  if (!credId) { message.error('无法确定凭证'); return; }
  dialog.warning({
    title: '删除证书',
    content: `确定要删除 ${cert.domain || cert.remoteCertId} 的证书吗？此操作不可撤销。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteSslCertificate(credId, cert.remoteCertId);
        message.success('证书已删除');
        queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] });
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}

// ── Filter chips: accounts that ACTUALLY have certificates in view ──
// Sourced from the backend credentialSummary (joined with live certificate
// rows and scoped to the active channel), so the chips never list unused
// credentials and each name carries its true channel suffix.
const credentialSummary = computed(() =>
  certsResponse.value?.credentialSummary || [],
);

const filterOptions = computed(() => {
  const list = credentialSummary.value.map(item => ({
    id: item.credentialId,
    // Lead with the channel so a Tencent SSL credential and a DNS credential
    // that happen to share a name (e.g. both "腾讯云Shifuf") are never read as
    // one merged account.
    name: `${item.source === 'letsencrypt' ? "Let's Encrypt" : '腾讯云'} · ${item.credentialName || `#${item.credentialId}`}`,
    count: item.count,
  }));
  return [
    { label: '全部', value: null as number | null, count: undefined as number | undefined },
    ...list.map(c => ({ label: c.name, value: c.id, count: c.count })),
  ];
});

// ── Table columns ──────────────────────────────────────────────
const isAllMode = computed(() => selectedCredentialId.value === 'all');
const canApplyCertificate = computed(() =>
  (sslCredentials.value || []).length > 0 || acmeDnsCredentialOptions.value.length > 0,
);

const columns = computed(() => {
  const cols: any[] = [
    { type: 'selection' as const },
    {
      title: '域名',
      key: 'domain',
      width: 220,
      fixed: 'left' as const,
      render: (row: SslCertificate) => {
        const sanCount = typeof row.san === 'number' ? row.san : (Array.isArray(row.san) ? row.san.length : 0);
        return h('div', { class: 'space-y-1' }, [
          h('div', { class: 'flex items-center gap-1.5' }, [
            h('span', { class: 'font-medium text-slate-700' }, row.domain || row.remoteCertId),
            sanCount > 1 ? h(NTag, { size: 'tiny', bordered: false }, () => `+${sanCount - 1} 域名`) : null,
          ]),
          !isManagedDomain(row.domain || '') ? h('span', { class: 'text-xs text-slate-400' }, '未纳入域名管理') : null,
        ]);
      },
    },
  ];

  if (isAllMode.value) {
    cols.push({
      title: '账号',
      key: 'credentialName',
      width: 160,
      render: (row: SslCertificate) => {
        const isAcme = row.provider === 'acme' || row.source === 'letsencrypt';
        // Channel-correct name: ACME certs belong to a DNS credential (used for
        // DNS-01), Tencent certs to a Tencent SSL credential. The old code
        // fell back to the Tencent credential list for both, mislabelling LE
        // rows as "腾讯云xxx".
        const acmeCred = (dnsCredentials.value || []).find(c => c.id === row.credentialId);
        const shownName = isAcme
          ? (acmeCred?.name || row.credentialName || credNameById(row.credentialId) || `#${row.credentialId}`)
          : (row.credentialName || credNameById(row.credentialId) || (row.credentialId ? `#${row.credentialId}` : '-'));
        // Lead with the CHANNEL (腾讯云 / Let's Encrypt) and show the account
        // name after it. A Tencent SSL credential and a DNS credential can
        // share a display name (both "腾讯云Shifuf"), so suffixing the channel
        // made the two rows read as one merged account — the channel is the
        // real discriminator, so it goes first.
        return h('div', { class: 'flex items-center gap-1' }, [
          h(NTag, { size: 'tiny', bordered: false, type: isAcme ? 'success' : 'info' },
            () => isAcme ? "Let's Encrypt" : '腾讯云'),
          h('span', { class: 'text-xs text-slate-500 truncate' }, shownName),
        ]);
      },
    });
  }

  cols.push(
    {
      title: '类型',
      key: 'productName',
      width: 140,
      render: (row: SslCertificate) =>
        h('span', { class: 'text-sm text-slate-500' }, row.productName || row.certType || '-'),
    },
    {
      title: '状态',
      key: 'status',
      width: 100,
      render: (row: SslCertificate) => {
        const cfg = statusConfig[row.status] || statusConfig.applying;
        const tag = h(NTag, { type: cfg.type, size: 'small', bordered: false }, () => cfg.label);
        if (row.statusMsg && (row.status === 'failed' || row.status === 'cancelled')) {
          return h(NTooltip, { trigger: 'hover' }, {
            trigger: () => h('span', { class: 'cursor-help' }, [tag]),
            default: () => row.statusMsg,
          });
        }
        return tag;
      },
    },
    {
      title: '来源',
      key: 'source',
      width: 130,
      render: (row: SslCertificate) => {
        const isAcme = row.provider === 'acme' || row.source === 'letsencrypt';
        const srcTag = h(NTag, { size: 'tiny', bordered: false, type: isAcme ? 'success' : 'default' },
          () => isAcme ? "Let's Encrypt" : '腾讯云');
        const children: any[] = [srcTag];
        // acme certs carry auto-renew state; show a badge + last renewal / error.
        if (isAcme) {
          const renew = row.effectiveAutoRenew
            ? h(NTag, { size: 'tiny', bordered: false, type: 'success' }, () => '续期生效')
            : row.autoRenew !== false && row.globalAutoRenew === false
              ? h(NTag, { size: 'tiny', bordered: false, type: 'warning' }, () => '等待全局开启')
              : h(NTag, { size: 'tiny', bordered: false, type: 'default' }, () => '单独关闭');
          let sub: any = null;
          if (row.renewError) {
            sub = h(NTooltip, { trigger: 'hover' }, {
              trigger: () => h('span', { class: 'text-xs text-red-500 cursor-help' }, '续期失败'),
              default: () => row.renewError,
            });
          } else if (row.lastRenewedAt) {
            sub = h('span', { class: 'text-xs text-slate-400' }, `续期于 ${formatDate(row.lastRenewedAt)}`);
          }
          children.push(h('div', { class: 'flex items-center gap-1 mt-0.5' }, [renew]));
          if (sub) children.push(h('div', { class: 'mt-0.5' }, [sub]));
        }
        return h('div', { class: 'space-y-0.5' }, children);
      },
    },
    {
      title: '部署',
      key: 'deployment',
      width: 150,
      render: (row: SslCertificate) => {
        const event = deploymentFor(row);
        if (!event) {
          // Deployable but never queued — tell the user how it gets deployed.
          return row.status === 'issued'
            ? h('span', { class: 'text-xs text-slate-400' }, '未入队（宝塔插件同步时自动部署）')
            : h('span', { class: 'text-xs text-slate-400' }, '暂无事件');
        }
        const type = event.status === 'success' ? 'success' : event.status === 'failed' ? 'error'
          : event.status === 'running' ? 'info' : event.status === 'skipped' ? 'default' : 'warning';
        const tag = h(NTag, { size: 'tiny', bordered: false, type }, () => deploymentStatusLabel[event.status]);
        // Show WHICH sites the certificate landed on (a wildcard like
        // *.shifuf.com may be deployed to several sites) plus timing, so the
        //判定依据 (target/fingerprint/error) is visible without opening 任务.
        const targets = (event.targetName || '').split(',').map(s => s.trim()).filter(Boolean);
        const lines: any[] = [tag];
        if (targets.length) {
          lines.push(h('div', { class: 'text-xs text-slate-500 mt-0.5 break-all' },
            targets.length === 1 ? targets[0] : `${targets[0]} 等 ${targets.length} 个站点`));
        }
        if (event.status === 'success' && event.completedAt) {
          lines.push(h('div', { class: 'text-xs text-slate-400' }, formatDateTime(event.completedAt)));
        }
        const tooltipText = (() => {
          const parts: string[] = [];
          if (targets.length) parts.push(`目标站点：${targets.join('、')}`);
          if (event.fingerprint) {
            try {
              const fp = JSON.parse(event.fingerprint);
              const entries = Object.entries(fp).filter(([, v]) => v);
              if (entries.length) parts.push('已部署指纹：' + entries.map(([site, v]) => `${site} ${String(v).slice(0, 12)}…`).join('；'));
            } catch { /* fingerprint may be a raw string (legacy) */ }
          }
          if (event.error) parts.push(`说明：${event.error}`);
          parts.push(`判定依据：${deploymentStatusLabel[event.status]}（事件 #${event.id}，尝试 ${event.attempts} 次）`);
          return parts.join('\n');
        })();
        return h(NTooltip, { trigger: 'hover' }, {
          trigger: () => h('div', { class: 'cursor-help space-y-0.5' }, lines),
          default: () => tooltipText,
        });
      },
    },
    {
      title: '有效期',
      key: 'validity',
      width: 220,
      render: (row: SslCertificate) => {
        const expiry = row.status === 'issued' ? expiryDaysText(row.notAfter) : null;
        return h('div', { class: 'space-y-0.5' }, [
          h('span', { class: 'text-sm text-slate-500' }, `${formatDate(row.notBefore)} ~ ${formatDate(row.notAfter)}`),
          expiry ? h(NTag, { size: 'tiny', type: expiry.type, bordered: false }, () => expiry.text) : null,
        ]);
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 300,
      fixed: 'right' as const,
      render: (row: SslCertificate) =>
        h('div', { class: 'flex items-center gap-2 flex-wrap' }, [
          h(NButton, { size: 'tiny', secondary: true, onClick: () => openDetail(row) },
            { icon: () => h(Eye, { size: 13 }), default: () => '详情' }),
          row.status === 'issued'
            ? h(NButton, { size: 'tiny', secondary: true, onClick: () => openCertView(row) },
                { icon: () => h(FileText, { size: 13 }), default: () => '查看' })
            : null,
          row.status === 'issued'
            ? h(NButton, { size: 'tiny', secondary: true, type: 'info', onClick: () => handleDeploy(row) },
                { icon: () => h(Rocket, { size: 13 }), default: () => '部署' })
            : null,
          row.status === 'issued'
            ? h(NButton, { size: 'tiny', secondary: true, type: 'warning', onClick: () => syncCertRowToEdgeOne(row) },
                { icon: () => h(Zap, { size: 13 }), default: () => '同步加速' })
            : null,
          !isManagedDomain(row.domain || '') && (row.domain || '').trim()
            ? h(NButton, { size: 'tiny', secondary: true, onClick: () => openAddZoneForDomain(row.domain) },
                { icon: () => h(Plus, { size: 13 }), default: () => '添加域名' })
            : null,
          row.status === 'validating'
            ? h(NButton, { size: 'tiny', secondary: true, type: 'info', onClick: () => handleComplete(row) },
                { icon: () => h(CheckCircle, { size: 13 }), default: () => '验证' })
            : null,
          row.status === 'issued'
            ? h(NButton, {
                size: 'tiny', type: 'primary',
                onClick: () => handleDownload(row),
              }, {
                icon: () => h(Download, { size: 13 }),
                default: () => '下载',
              })
            : null,
          row.provider === 'acme'
            ? h(NButton, {
                size: 'tiny', secondary: true,
                type: row.autoRenew === false ? 'default' : 'success',
                onClick: () => toggleCertificateAutoRenew(row),
              }, { default: () => row.autoRenew === false ? '开启续期' : '关闭续期' })
            : (row.status !== 'expired' && !row.isUploaded && row.status !== 'revoked'
              ? h(NButton, {
                  size: 'tiny', secondary: true,
                  type: row.autoRenew ? 'success' : 'default',
                  onClick: () => toggleCertificateAutoRenew(row),
                }, { default: () => row.autoRenew ? '关闭自动续费' : '开启自动续费' })
              : null),
          (row.status === 'expired' || (row.status === 'issued' && withinDays(row.notAfter)))
            ? h(NButton, { size: 'tiny', secondary: true, type: 'warning', onClick: () => quickReapply(row) },
                { icon: () => h(RotateCw, { size: 13 }), default: () => '续期' })
            : null,
          h(NButton, { size: 'tiny', quaternary: true, type: 'error', onClick: () => handleDelete(row) },
            { icon: () => h(Trash2, { size: 13 }), default: () => '删除' }),
        ]),
    },
  );

  return cols;
});

// Horizontal scroll width = sum of every column's declared width. naived-ui
// treats scroll-x as the table's minimum width: when it was a hard-coded
// 900/1000 but the columns actually summed to ~1400, the table compressed and
// clipped the trailing 操作 column instead of scrolling. Deriving it from the
// real widths guarantees the columns keep their size and a scrollbar appears.
const tableScrollX = computed(() =>
  columns.value.reduce((sum: number, col: any) => {
    const w = Number(col.width) || Number(col.minWidth) || 0;
    return sum + (w || 48); // selection / width-less columns ≈ 48px
  }, 0),
);
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <section class="panel p-4">
      <div class="toolbar-row">
        <div>
          <h1 class="page-title">SSL 证书管理</h1>
          <p class="page-subtitle">
            腾讯云 DV / Let's Encrypt (acme.sh) 证书申请、自动续期、在线查看、下载与上传
            <span v-if="hasActiveApplying" class="inline-flex items-center gap-1 ml-2 text-blue-500">
              <span class="inline-block w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
              <span class="text-xs">自动刷新中</span>
            </span>
          </p>
        </div>
        <div class="flex-1" />

        <NSelect
          v-if="sslCredentials && sslCredentials.length > 0 && channelTab !== 'letsencrypt'"
          v-model:value="selectedCredentialId"
          :options="credentialOptions"
          placeholder="选择凭证"
          size="small"
          class="!w-52"
        />
        <NButton v-if="channelTab !== 'letsencrypt'" size="small" quaternary @click="openAddCred" title="添加 SSL 凭证">
          <template #icon><KeyRound :size="14" /></template>
        </NButton>
        <NButton v-if="channelTab !== 'letsencrypt'" size="small" quaternary @click="showCredList = !showCredList" title="管理凭证">
          <template #icon><Pencil :size="14" /></template>
        </NButton>
        <NInput
          v-model:value="searchKeyword"
          placeholder="搜索域名..."
          clearable
          size="small"
          class="!w-44"
        >
          <template #prefix><Search :size="14" class="text-slate-500" /></template>
        </NInput>
        <NButton size="small" type="primary" :disabled="!canApplyCertificate" @click="openApply">
          <template #icon><Plus :size="14" /></template>
          申请
        </NButton>
        <NButton v-if="channelTab !== 'letsencrypt'" size="small" secondary :disabled="!selectedCredentialId || selectedCredentialId === 'all'" @click="showUpload = true">
          <template #icon><Upload :size="14" /></template>
          上传
        </NButton>
        <NButton
          v-if="channelTab !== 'letsencrypt'"
          size="small"
          secondary
          :disabled="!selectedCredentialId || selectedCredentialId === 'all'"
          :loading="syncMutation.isPending.value"
          @click="syncMutation.mutate()"
        >
          <template #icon><RefreshCw :size="14" /></template>
          同步
        </NButton>
        <NButton
          v-if="channelTab !== 'letsencrypt'"
          size="small"
          secondary
          :loading="reconcileMutation.isPending.value"
          @click="reconcileMutation.mutate()"
          title="检查腾讯云远端证书并清理失效本地记录"
        >
          检查失效
        </NButton>
        <NDropdown
          v-if="channelTab !== 'letsencrypt'"
          trigger="click"
          :options="cleanExpiredOptions"
          @select="handleCleanExpired"
        >
          <NButton size="small" secondary :loading="cleanExpiredMutation.isPending.value" title="删除腾讯云上已过期/吊销/失败的失效证书">
            清理失效
          </NButton>
        </NDropdown>
        <NButton size="small" secondary @click="openTaskDrawer" title="查看持久化签发任务与自动部署事件">
          <template #icon><ListChecks :size="14" /></template>
          任务
          <span
            v-if="edgeOneDriftCount > 0"
            class="ml-1 inline-flex items-center justify-center rounded-full bg-red-500 px-1.5 text-[10px] font-semibold text-white"
            title="有加速域名绑定的证书已过期/漂移，点击查看「加速绑定」"
          >{{ edgeOneDriftCount }}</span>
        </NButton>
        <NButton
          size="small"
          secondary
          :loading="renewMutation.isPending.value"
          @click="openRenew"
          title="自动续期即将过期的证书"
        >
          <template #icon><RotateCw :size="14" /></template>
          自动续期
        </NButton>
        <div class="flex items-center gap-1.5 pl-1" title="开启后后台每日自动检查，剩余 ≤7 天即续期并清理过期证书">
          <NSwitch :value="autoRenewEnabled" :loading="autoRenewToggling" size="small" @update:value="toggleAutoRenew" />
          <span class="text-xs" :class="autoRenewEnabled ? 'text-emerald-600 font-semibold' : 'text-slate-400'">
            {{ autoRenewEnabled ? '自动续期已开启' : '自动续期未开启' }}
          </span>
        </div>
      </div>

      <!-- Channel tabs: 全部 / 腾讯云 / Let's Encrypt. Tabs only appear for
           channels that have credentials or certificates in the account. -->
      <div class="mt-3 flex flex-wrap items-center gap-2 border-t border-panel-border pt-3">
        <NButton
          v-for="tab in channelTabs"
          :key="tab.key"
          size="small"
          :type="channelTab === tab.key ? 'primary' : 'default'"
          :secondary="channelTab !== tab.key"
          @click="selectChannelTab(tab.key)"
        >
          {{ tab.label }}<span v-if="tab.count !== undefined"> ({{ tab.count }})</span>
        </NButton>
        <div class="flex-1" />
        <span v-if="channelTab === 'tencent'" class="text-xs text-slate-400">仅显示腾讯云签发的证书</span>
        <span v-else-if="channelTab === 'letsencrypt'" class="text-xs text-slate-400">仅显示 Let's Encrypt (acme.sh) 签发的证书</span>
      </div>
    </section>

    <!-- Credential Management -->
    <section v-if="showCredList && sslCredentials && sslCredentials.length > 0" class="panel p-4">
      <p class="mb-3 text-sm font-semibold text-slate-700">凭证管理</p>
      <div class="space-y-2">
        <div
          v-for="cred in sslCredentials"
          :key="cred.id"
          class="flex items-center gap-3 rounded-xl border border-panel-border bg-panel-bg p-3"
          :class="{ 'ring-2 ring-accent/30': selectedCredentialId === cred.id }"
        >
          <div class="min-w-0 flex-1 cursor-pointer" @click="selectedCredentialId = cred.id">
            <div class="flex items-center gap-2">
              <span class="truncate text-sm font-medium text-slate-700">{{ cred.name }}</span>
              <NTag v-if="cred.provider === 'dnspod'" size="tiny" :bordered="false">DNS 共用</NTag>
              <NTag v-else size="tiny" type="info" :bordered="false">SSL 专属</NTag>
            </div>
            <p class="text-xs text-slate-500">ID: {{ cred.id }}</p>
          </div>
          <template v-if="cred.provider === 'tencent_ssl'">
            <NButton text size="tiny" @click="openEditCred(cred)">
              <template #icon><Pencil :size="12" /></template>
            </NButton>
            <NButton text size="tiny" type="error" @click="handleDeleteCred(cred)">
              <template #icon><Trash2 :size="12" /></template>
            </NButton>
          </template>
          <NTag v-else size="tiny" :bordered="false" class="text-xs text-slate-400">在设置中管理</NTag>
        </div>
      </div>
    </section>

    <!-- Error displays -->
    <NAlert v-if="credsError" type="error" :bordered="false" class="mx-0">
      <div class="flex items-center gap-2">
        <AlertTriangle :size="14" />
        <span>凭证加载失败：{{ credsError }}</span>
      </div>
    </NAlert>

    <NAlert v-if="certsErrorMsg" type="error" :bordered="false" class="mx-0">
      <div class="flex items-center gap-2">
        <AlertTriangle :size="14" />
        <span>证书加载失败：{{ certsErrorMsg }}</span>
      </div>
    </NAlert>

    <NAlert v-if="aggregationErrors.length > 0" type="warning" :bordered="false" class="mx-0">
      <p class="text-sm font-medium mb-1">部分账号获取证书失败：</p>
      <p v-for="(e, i) in aggregationErrors" :key="i" class="text-xs text-slate-600">
        {{ e.name }}：{{ e.error }}
      </p>
    </NAlert>

    <!-- Expiring certificate warning -->
    <NAlert v-if="expiringCerts.length > 0" type="warning" :bordered="false" class="mx-0">
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium">{{ expiringCerts.length }} 个证书即将过期或已过期</p>
          <p class="text-xs text-slate-500 mt-1">
            {{ expiringCerts.slice(0, 3).map(c => c.domain).join('、') }}{{ expiringCerts.length > 3 ? '...' : '' }}
          </p>
        </div>
        <NButton size="small" type="warning" :loading="renewMutation.isPending.value" @click="openRenew">
          一键续期
        </NButton>
      </div>
    </NAlert>

    <!-- No credentials -->
    <section v-if="!credsLoading && !credsError && !canApplyCertificate" class="panel p-8">
      <NEmpty description="暂无可用的证书签发凭证">
        <template #extra>
          <p class="mb-3 text-sm text-slate-500">
            可添加含 SecretId / SecretKey 的腾讯云凭证，或在设置中添加支持 DNS-01 的 DNS 凭证来申请 Let's Encrypt 证书。
          </p>
          <NButton size="small" type="primary" @click="openAddCred">
            <template #icon><Plus :size="14" /></template>
            添加 SSL 凭证
          </NButton>
        </template>
      </NEmpty>
    </section>

    <!-- Table -->
    <section class="panel p-4">
      <!-- Filter chips for "all" mode -->
      <div v-if="isAllMode && filterOptions.length > 2" class="mb-3 flex flex-wrap gap-2">
        <NButton
          v-for="opt in filterOptions"
          :key="String(opt.value)"
          size="tiny"
          :type="filterCredentialId === opt.value ? 'primary' : 'default'"
          :secondary="filterCredentialId !== opt.value"
          @click="filterCredentialId = opt.value"
        >
          {{ opt.label }}
        </NButton>
      </div>

      <!-- Status filter chips -->
      <div v-if="certificates.length > 0" class="mb-3 flex flex-wrap items-center gap-2">
        <NButton
          size="tiny"
          :type="statusFilter === null ? 'primary' : 'default'"
          :secondary="statusFilter !== null"
          @click="statusFilter = null"
        >
          全部 ({{ statusTotal }})
        </NButton>
        <template v-for="(cfg, key) in statusConfig" :key="key">
          <NButton
            v-if="statusCounts[key]"
            size="tiny"
            :type="statusFilter === key ? cfg.type : 'default'"
            :secondary="statusFilter !== key"
            @click="statusFilter = statusFilter === key ? null : (key as SslCertificateStatus)"
          >
            {{ cfg.label }} ({{ statusCounts[key] }})
          </NButton>
        </template>
      </div>

      <!-- Issuance source is now controlled by the channel tabs above. -->

      <!-- Sort controls + batch toolbar + export -->
      <div v-if="certificates.length > 0" class="mb-3 flex flex-wrap items-center gap-2">
        <NSelect
          v-model:value="sortBy"
          :options="sortOptions"
          size="tiny"
          class="!w-28"
        />
        <NButton size="tiny" quaternary @click="sortAsc = !sortAsc" :title="sortAsc ? '升序' : '降序'">
          <template #icon><ArrowUpDown :size="13" /></template>
          {{ sortAsc ? '升序' : '降序' }}
        </NButton>
        <NButton size="tiny" quaternary @click="exportCsv" title="导出 CSV">
          <template #icon><FileDown :size="13" /></template>
          导出
        </NButton>
        <template v-if="checkedRowKeys.length > 0">
          <span class="text-xs text-slate-500 ml-2">已选 {{ checkedRowKeys.length }} 项</span>
          <NButton size="tiny" type="primary" secondary :loading="batchDeployMutation.isPending.value" @click="handleBatchDeploy">
            <template #icon><Rocket :size="13" /></template>
            批量部署
          </NButton>
          <NButton size="tiny" type="success" secondary :loading="batchAutoRenewMutation.isPending.value" @click="handleBatchAutoRenew(true)">
            批量开启续期
          </NButton>
          <NButton size="tiny" secondary :loading="batchAutoRenewMutation.isPending.value" @click="handleBatchAutoRenew(false)">
            批量关闭续期
          </NButton>
          <NButton size="tiny" type="error" :loading="batchDeleting" @click="handleBatchDelete">
            <template #icon><Trash2 :size="13" /></template>
            批量删除
          </NButton>
          <NButton size="tiny" quaternary @click="checkedRowKeys = []">取消选择</NButton>
        </template>
      </div>

      <div v-if="isLoading" class="flex justify-center py-20"><NSpin size="large" /></div>
      <NEmpty v-else-if="sortedCertificates.length === 0 && !certsErrorMsg" description="暂无证书数据" class="py-10" />

      <!-- Mobile cards -->
      <div v-else-if="isMobile" class="space-y-3">
        <div v-for="cert in sortedCertificates" :key="cert.remoteCertId" class="panel-muted p-4">
          <div class="mb-2 flex items-center justify-between">
            <span class="font-medium text-slate-700 truncate">{{ cert.domain || cert.remoteCertId }}</span>
            <NTag :type="(statusConfig[cert.status] || statusConfig.applying).type" size="small" :bordered="false">
              {{ (statusConfig[cert.status] || statusConfig.applying).label }}
            </NTag>
          </div>
          <div class="mb-1 flex items-center gap-2 text-xs text-slate-500">
            <span>{{ cert.productName || cert.certType || '-' }}</span>
            <NTag v-if="isAllMode" size="tiny" :bordered="false" :type="(cert.provider === 'acme' || cert.source === 'letsencrypt') ? 'success' : 'info'">
              {{ (cert.provider === 'acme' || cert.source === 'letsencrypt')
                ? `Let's Encrypt · ${(dnsCredentials || []).find(c => c.id === cert.credentialId)?.name || cert.credentialName || ''}`
                : `腾讯云 · ${cert.credentialName || credNameById(cert.credentialId)}` }}
            </NTag>
          </div>
          <div class="flex items-center justify-between text-xs text-slate-500">
            <div>
              <span>{{ formatDate(cert.notBefore) }} ~ {{ formatDate(cert.notAfter) }}</span>
              <NTag
                v-if="cert.status === 'issued' && expiryDaysText(cert.notAfter)"
                :type="expiryDaysText(cert.notAfter)!.type"
                size="tiny"
                :bordered="false"
                class="ml-1"
              >
                {{ expiryDaysText(cert.notAfter)!.text }}
              </NTag>
            </div>
            <div class="flex gap-3">
              <NButton text size="tiny" @click="openDetail(cert)">详情</NButton>
              <NButton v-if="cert.status === 'issued'" text size="tiny" @click="openCertView(cert)">查看</NButton>
              <NButton v-if="cert.status === 'issued'" text size="tiny" @click="handleDeploy(cert)">部署</NButton>
              <NButton v-if="cert.status === 'issued'" text size="tiny" type="primary" @click="handleDownload(cert)">
                <template #icon><Download :size="12" /></template>
                下载
              </NButton>
              <NButton
                v-if="cert.status === 'expired' || (cert.status === 'issued' && withinDays(cert.notAfter))"
                text size="tiny" type="warning"
                @click="quickReapply(cert)"
              >
                续期
              </NButton>
              <NButton text size="tiny" type="error" @click="handleDelete(cert)">删除</NButton>
            </div>
          </div>
        </div>
      </div>

      <!-- Desktop table -->
      <template v-else-if="sortedCertificates.length > 0">
        <NDataTable
          v-model:checked-row-keys="checkedRowKeys"
          :columns="columns"
          :data="sortedCertificates"
          :row-key="(r: SslCertificate) => r.remoteCertId"
          :bordered="false"
          size="small"
          class="table-scrollable"
          :scroll-x="tableScrollX"
          :max-height="560"
        />
      </template>

      <!-- Pagination -->
      <div v-if="totalCount > pageSize" class="mt-4 flex justify-end">
       <NPagination
         v-model:page="page"
         :page-size="pageSize"
         :item-count="totalCount"
          :disabled="certsFetching && !isLoading"
         show-quick-jumper
       />
      </div>
    </section>

    <!-- Add Credential Modal -->
    <NModal v-model:show="showAddCred" preset="dialog" title="添加 SSL 凭证" :mask-closable="false" style="max-width: 480px;">
      <div class="space-y-4 pt-2">
        <NAlert v-if="addCredError" type="error" :bordered="false">{{ addCredError }}</NAlert>
        <NFormItem label="凭证名称" required>
          <NInput v-model:value="addCredName" placeholder="如：我的腾讯云 SSL" />
        </NFormItem>
        <NFormItem label="SecretId" required>
          <NInput v-model:value="addCredSecretId" placeholder="腾讯云 SecretId" />
        </NFormItem>
        <NFormItem label="SecretKey" required>
          <NInput v-model:value="addCredSecretKey" type="password" show-password-on="click" placeholder="腾讯云 SecretKey" />
        </NFormItem>
        <NAlert type="info" :bordered="false">
          <p class="text-sm">前往
            <a href="https://console.cloud.tencent.com/cam/capi" target="_blank" rel="noopener" class="text-accent hover:underline">腾讯云密钥管理</a>
            获取 SecretId 和 SecretKey。建议使用子账号并仅授予 SSL 权限。
          </p>
          <p class="mt-1 text-xs text-slate-500">如果已有腾讯云 DNS（DNSPod）凭证且包含 SecretId/SecretKey，它会自动出现在上方选择器中，无需重复添加。</p>
        </NAlert>
      </div>
      <template #action>
        <NButton @click="showAddCred = false">取消</NButton>
        <NButton
          type="primary"
          :loading="addCredMutation.isPending.value"
          :disabled="!addCredName.trim() || !addCredSecretId.trim() || !addCredSecretKey.trim()"
          @click="addCredMutation.mutate()"
        >
          保存
        </NButton>
      </template>
    </NModal>

    <!-- Edit Credential Modal -->
    <NModal v-model:show="showEditCred" preset="dialog" title="编辑 SSL 凭证" :mask-closable="false" style="max-width: 480px;">
      <div class="space-y-4 pt-2">
        <NAlert v-if="editCredError" type="error" :bordered="false">{{ editCredError }}</NAlert>
        <NFormItem label="凭证名称">
          <NInput v-model:value="editCredName" placeholder="如：我的腾讯云 SSL" />
        </NFormItem>
        <NFormItem label="SecretId">
          <NInput v-model:value="editCredSecretId" placeholder="不修改请留空" />
        </NFormItem>
        <NFormItem label="SecretKey">
          <NInput v-model:value="editCredSecretKey" type="password" show-password-on="click" placeholder="不修改请留空" />
        </NFormItem>
      </div>
      <template #action>
        <NButton @click="showEditCred = false">取消</NButton>
        <NButton
          type="primary"
          :loading="editCredMutation.isPending.value"
          :disabled="!editCredName.trim()"
          @click="editCredMutation.mutate()"
        >
          保存
        </NButton>
      </template>
    </NModal>

    <!-- Apply Modal -->
    <NModal v-model:show="showApply" preset="dialog" :title="applyOldCertId ? '续期证书' : '申请免费证书'" :mask-closable="false" style="max-width: 520px;">
      <div class="space-y-4 pt-2">
        <NAlert v-if="applyOldCertId" type="info" :bordered="false">
          正在续期证书 {{ applyOldCertId }}，将使用腾讯云官方续期流程。
        </NAlert>
        <NFormItem v-if="!applyOldCertId && channelTab === 'all'" label="签发渠道">
          <NSelect v-model:value="applyChannel" :options="channelOptions" />
        </NFormItem>
        <NFormItem v-if="applyChannel === 'tencent' && selectedCredentialId === 'all'" label="腾讯云 SSL 凭证" required>
          <NSelect
            v-model:value="applySslCredId"
            :options="credentialOptions.filter(option => option.value !== 'all')"
            placeholder="选择用于申请证书的腾讯云凭证"
            filterable
          />
        </NFormItem>
        <NFormItem label="域名" required>
          <div class="space-y-2 w-full">
            <div class="flex items-center gap-2">
              <NSelect
                v-if="applyDomainMode === 'managed'"
                v-model:value="applyManagedRoot"
                :options="managedDomainOptions"
                placeholder="选择已管理的主域名"
                filterable
                class="flex-1"
                :loading="managedDomainsLoading"
              />
              <NInput
                v-else
                v-model:value="applyDomain"
                placeholder="输入域名，例如 example.com 或 www.example.com"
                class="flex-1"
              />
              <NButton
                size="small"
                secondary
                @click="applyDomainMode = applyDomainMode === 'managed' ? 'manual' : 'managed'"
                :disabled="managedDomainOptions.length === 0 && applyDomainMode === 'manual'"
              >
                {{ applyDomainMode === 'managed' ? '手动输入' : '选择域名' }}
              </NButton>
            </div>

            <template v-if="applyDomainMode === 'managed'">
              <div class="flex items-center gap-2">
                <NInput v-model:value="applySubdomain" placeholder="子域（可选），如 www 或 api.v1" class="flex-1" />
                <div class="flex items-center gap-2">
                  <NSwitch v-model:value="applyWildcard" :disabled="!!applySubdomain.trim()" />
                  <span class="text-xs text-slate-500">通配符</span>
                </div>
              </div>
              <p v-if="applySubdomain.trim()" class="text-xs text-slate-500">
                最终申请域名：{{ applyFinalDomain }}
              </p>
              <p v-else class="text-xs text-slate-500">
                最终申请域名：{{ applyFinalDomain || '-' }}
              </p>
            </template>

            <template v-else>
              <div class="flex items-center gap-2">
                <NTag v-if="applyManagedHint" size="small" :bordered="false">
                  已管理：{{ applyManagedHint.name }}
                </NTag>
                <NButton
                  v-else-if="applyFinalDomain && zoneManageCredentials.length > 0"
                  size="small"
                  secondary
                  @click="openAddZoneForDomain(applyFinalDomain)"
                >
                  添加到域名管理
                </NButton>
              </div>
            </template>
          </div>
        </NFormItem>
        <NFormItem v-if="applyChannel === 'tencent'" label="验证方式">
          <NSelect v-model:value="applyDvMethod" :options="dvMethodOptions" />
        </NFormItem>

        <template v-if="applyChannel === 'tencent' && applyDvMethod === 'DNS'">
          <NFormItem label="自动添加 DNS 验证记录">
            <div class="flex items-center gap-2">
              <NSwitch v-model:value="applyAutoDns" />
              <span class="text-xs text-slate-500">开启后自动为域名添加 DNS 验证记录（支持 Cloudflare / DNSPod）</span>
            </div>
          </NFormItem>
          <NAlert v-if="!applyAutoDns" type="info" :bordered="false">
            关闭自动添加后，提交申请会进入手动验证步骤：系统将自动打开证书详情，展示需要添加的 DNS 记录，并提供「检测并提交验证」按钮。
          </NAlert>
          <NFormItem v-if="applyAutoDns" label="DNS 凭证">
            <NSelect
              v-model:value="applyDnsCredId"
              :options="dnsCredentialOptions"
              placeholder="不选则自动匹配所有已配置的 DNS 凭证"
              filterable
              clearable
            />
          </NFormItem>
          <p v-if="applyAutoDns && !applyDnsCredId && dnsCredentialOptions.length > 0" class="text-xs text-slate-500 -mt-2">
            未指定凭证时，系统将自动从所有已配置的 DNS 凭证中匹配该域名所在的区域。
          </p>
          <NAlert v-if="applyAutoDns && dnsCredentialOptions.length === 0" type="warning" :bordered="false">
            暂无可用的 DNS 凭证。请先在设置中添加 Cloudflare 或 DNSPod 凭证。
          </NAlert>
        </template>

        <NAlert v-if="applyChannel === 'tencent' && applyDvMethod === 'DNS_AUTO'" type="info" :bordered="false">
          DNS 自动验证要求域名的 NS 记录已指向 DNSPod（腾讯云）。如果域名使用 Cloudflare、阿里云或其他 DNS 服务商解析，请选择「DNS 验证」并开启自动添加记录——只需在下方选择对应的 DNS 凭证即可自动完成验证。
        </NAlert>

        <!-- acme.sh channel fields -->
        <template v-if="applyChannel === 'acme'">
          <NFormItem label="DNS 凭证" required>
            <NSelect
              v-model:value="applyAcmeDnsCredId"
              :options="acmeDnsCredentialOptions"
              placeholder="选择用于 DNS-01 验证的凭证（Cloudflare / DNSPod / 阿里云）"
              filterable
            />
          </NFormItem>
          <NFormItem label="证书颁发机构 (CA)">
            <NSelect v-model:value="applyAcmeCa" :options="acmeCaOptions" />
          </NFormItem>
          <template v-if="applyAcmeCaRequiresEab">
            <NFormItem label="EAB Key ID" required>
              <NInput v-model:value="applyAcmeEabKid" placeholder="ZeroSSL 等 CA 提供的外锚凭据 Key ID" />
            </NFormItem>
            <NFormItem label="EAB HMAC Key" required>
              <NInput v-model:value="applyAcmeEabHmac" type="password" show-password-on="click" placeholder="与 Key ID 配对的 HMAC 密钥" />
            </NFormItem>
            <NAlert type="warning" :bordered="false">
              该 CA 需要外部账户绑定（EAB）。请在 CA 控制台生成 Key ID 与 HMAC 密钥后填入，留空将无法完成账户注册。
            </NAlert>
          </template>
          <NFormItem label="密钥类型">
            <NSelect v-model:value="applyAcmeKeyLength" :options="acmeKeyLengthOptions" />
          </NFormItem>
          <NAlert v-if="acmeDnsCredentialOptions.length === 0" type="warning" :bordered="false">
            暂无可用于 DNS 验证的凭证。请先在设置中添加 Cloudflare、DNSPod 或阿里云凭证。
          </NAlert>
          <NAlert type="info" :bordered="false">
            由 acme.sh 通过所选 CA 签发，全程自动完成 DNS 验证（加记录 → 验证 → 清理），签发后默认开启自动续期。主域名和所有 SAN 必须由同一个 DNS 凭证管理；Cloudflare / DNSPod 会在提交时校验管理范围。DNS 传播通常需要 1-3 分钟。支持通配符域名（如 *.example.com）。
          </NAlert>
        </template>
      </div>
      <template #action>
        <NButton @click="showApply = false">取消</NButton>
        <NButton
          type="primary"
          :loading="applyMutation.isPending.value || acmeMutation.isPending.value"
          :disabled="!applyFinalDomain || (applyChannel === 'acme' ? !applyAcmeDnsCredId : !applyEffectiveCredId)"
          @click="submitApply()"
        >
          提交申请
        </NButton>
      </template>
    </NModal>

    <AddZoneDialog
      v-model:show="showAddZone"
      :credentials="zoneManageCredentials"
      :initial-credential-id="addZoneInitialCredId"
      :initial-domains-text="addZoneInitialText"
    />

    <!-- Upload Modal -->
    <NModal v-model:show="showUpload" preset="dialog" title="上传第三方证书" :mask-closable="false" style="max-width: 560px;">
      <div class="space-y-4 pt-2">
        <NFormItem label="证书公钥 (PEM)" required>
          <NInput
            v-model:value="uploadPublicKey"
            type="textarea"
            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
            :rows="5"
          />
        </NFormItem>
        <NFormItem label="证书私钥 (PEM)" required>
          <NInput
            v-model:value="uploadPrivateKey"
            type="textarea"
            placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
            :rows="5"
          />
        </NFormItem>
        <NFormItem label="备注名称">
          <NInput v-model:value="uploadAlias" placeholder="可选，方便识别" />
        </NFormItem>
      </div>
      <template #action>
        <NButton @click="showUpload = false">取消</NButton>
        <NButton
          type="primary"
          :loading="uploadMutation.isPending.value"
          :disabled="!uploadPublicKey.trim() || !uploadPrivateKey.trim()"
          @click="uploadMutation.mutate()"
        >
          上传
        </NButton>
      </template>
    </NModal>

    <!-- Renew Modal -->
    <NModal v-model:show="showRenewModal" preset="dialog" title="自动续期" :mask-closable="false" style="max-width: 480px;">
      <div class="space-y-4 pt-2">
        <NAlert type="info" :bordered="false">
          自动检查所有账号下即将过期（或已过期）的证书，为相同域名重新申请免费 DV 证书。
        </NAlert>
        <NFormItem label="提前续期天数">
          <NSelect
            v-model:value="renewDays"
            :options="[
              { label: '7 天内过期', value: 7 },
              { label: '15 天内过期', value: 15 },
              { label: '30 天内过期（推荐）', value: 30 },
              { label: '60 天内过期', value: 60 },
            ]"
          />
        </NFormItem>
        <NFormItem label="DNS 凭证">
          <NSelect
            v-model:value="renewDnsCredId"
            :options="dnsCredentialOptions"
            placeholder="不选则自动匹配所有已配置的 DNS 凭证"
            clearable
            filterable
          />
        </NFormItem>
        <p class="text-xs text-slate-500">
          {{ renewDnsCredId
            ? '将通过所选 DNS 凭证自动添加验证记录。'
            : '未指定凭证时，系统将自动遍历所有已配置的 DNS 凭证（Cloudflare / DNSPod 等），匹配域名所在区域并添加验证记录。'
          }}
        </p>
      </div>
      <template #action>
        <NButton @click="showRenewModal = false">取消</NButton>
        <NButton
          type="primary"
          :loading="renewMutation.isPending.value"
          @click="renewMutation.mutate()"
        >
          开始续期
        </NButton>
      </template>
    </NModal>

    <!-- Renew Result Modal -->
    <NModal v-model:show="showRenewResult" preset="dialog" title="续期结果" style="max-width: 560px;">
      <div v-if="renewResultData" class="space-y-4 pt-2">
        <!-- Summary -->
        <div class="flex gap-3 text-sm">
          <NTag v-if="renewResultData.renewed.length > 0" type="success" :bordered="false" size="small">
            {{ renewResultData.renewed.length }} 个已续期
          </NTag>
          <NTag v-if="renewResultData.failed.length > 0" type="error" :bordered="false" size="small">
            {{ renewResultData.failed.length }} 个失败
          </NTag>
          <NTag v-if="renewResultData.skipped.length > 0" type="warning" :bordered="false" size="small">
            {{ renewResultData.skipped.length }} 个跳过
          </NTag>
        </div>

        <!-- Renewed list -->
        <div v-if="renewResultData.renewed.length > 0">
          <p class="text-sm font-semibold text-slate-700 mb-2">续期成功</p>
          <div v-for="(item, i) in renewResultData.renewed" :key="'r' + i" class="panel-muted p-3 mb-2 text-sm">
            <div class="flex items-center justify-between">
              <span class="font-medium text-slate-700">{{ item.domain }}</span>
              <NTag v-if="item.dnsRecordAdded" type="success" size="tiny" :bordered="false">DNS 已添加</NTag>
              <NTag v-else type="warning" size="tiny" :bordered="false">需手动验证</NTag>
            </div>
            <p class="text-xs text-slate-500 mt-1">凭证: {{ item.credential }} · 新证书 ID: {{ item.newCertId }}</p>
            <template v-if="(item as any).dnsErrors?.length">
              <p v-for="(de, j) in (item as any).dnsErrors" :key="j" class="text-xs text-orange-600 mt-0.5">
                DNS 错误：{{ de.error || de.key }}
              </p>
            </template>
          </div>
        </div>

        <!-- Failed list -->
        <div v-if="renewResultData.failed.length > 0">
          <p class="text-sm font-semibold text-slate-700 mb-2">续期失败</p>
          <div v-for="(item, i) in renewResultData.failed" :key="'f' + i" class="rounded-xl border border-red-200 bg-red-50 p-3 mb-2 text-sm">
            <div class="font-medium text-slate-700">{{ item.domain }}</div>
            <p class="text-xs text-slate-500 mt-1">凭证: {{ item.credential }}</p>
            <p class="text-xs text-red-600 mt-1">{{ item.error }}</p>
          </div>
        </div>

        <!-- Skipped list -->
        <div v-if="renewResultData.skipped.length > 0">
          <p class="text-sm font-semibold text-slate-700 mb-2">已跳过</p>
          <div v-for="(item, i) in renewResultData.skipped" :key="'s' + i" class="panel-muted p-3 mb-2 text-sm">
            <div class="font-medium text-slate-700">{{ item.domain }}</div>
            <p class="text-xs text-slate-500 mt-1">凭证: {{ item.credential }} · {{ item.reason }}</p>
          </div>
        </div>
      </div>
      <template #action>
        <NButton @click="showRenewResult = false">关闭</NButton>
      </template>
    </NModal>

    <!-- Detail Drawer -->
    <NDrawer v-model:show="showTaskDrawer" :width="isMobile ? '100%' : 760" placement="right">
      <NDrawerContent closable>
        <template #header>
          <div class="flex w-full items-center justify-between gap-3 pr-2">
            <span>SSL 自动化任务</span>
            <div class="flex gap-2">
            <NButton size="small" secondary @click="handleDownloadTaskLogs"><template #icon><FileDown :size="14" /></template>下载日志</NButton>
            <NButton size="small" secondary @click="openNotificationSettings">通知设置</NButton>
            </div>
          </div>
        </template>
        <NTabs v-model:value="taskDrawerTab" type="line" animated>
          <NTabPane name="acme" tab="签发任务">
            <div v-if="acmeJobsFetching && !(acmeJobs || []).length" class="flex justify-center py-12"><NSpin /></div>
            <NEmpty v-else-if="!(acmeJobs || []).length" description="暂无 ACME 签发任务" class="py-12" />
            <div v-else class="space-y-3">
              <div v-for="job in acmeJobs" :key="job.id" class="rounded-xl border border-panel-border p-3">
                <div class="flex items-start gap-3">
                  <div class="min-w-0 flex-1">
                    <div class="flex flex-wrap items-center gap-2">
                      <span class="font-medium text-slate-700">{{ job.domain }}</span>
                      <NTag size="tiny" :bordered="false" :type="job.status === 'success' ? 'success' : job.status === 'failed' ? 'error' : job.status === 'running' ? 'info' : job.status === 'cancelled' ? 'default' : 'warning'">
                        {{ jobStatusLabel[job.status] }}
                      </NTag>
                      <span class="text-xs text-slate-400">尝试 {{ job.attempts }}/3</span>
                    </div>
                    <p class="mt-1 text-xs text-slate-500">{{ job.operation === 'renew' ? '续期' : '签发' }} · 创建于 {{ formatDateTime(job.createdAt) }}</p>
                    <p v-if="job.error" class="mt-1 break-all text-xs text-red-500">{{ job.error }}</p>
                  </div>
                  <div class="flex gap-2">
                    <NButton v-if="job.status === 'failed' || job.status === 'cancelled'" size="tiny" secondary type="warning" @click="taskActionMutation.mutate({ id: job.id, action: 'retry' })">重试</NButton>
                    <NButton v-if="job.status === 'queued' || job.status === 'failed'" size="tiny" secondary @click="taskActionMutation.mutate({ id: job.id, action: 'cancel' })">取消</NButton>
                  </div>
                </div>
              </div>
            </div>
          </NTabPane>
          <NTabPane name="deployment" tab="部署事件">
            <div class="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <NSelect v-model:value="deploymentStatusFilter" clearable placeholder="按状态筛选" :options="[
                { label: '待部署', value: 'queued' }, { label: '部署中', value: 'running' },
                { label: '已部署', value: 'success' }, { label: '部署失败', value: 'failed' },
                { label: '已跳过', value: 'skipped' },
              ]" />
              <NSelect v-model:value="deploymentSourceFilter" clearable placeholder="按来源筛选" :options="[
                { label: '腾讯云', value: 'tencent' }, { label: `Let's Encrypt`, value: 'letsencrypt' },
              ]" />
              <NInput v-model:value="deploymentDomainFilter" clearable placeholder="按域名筛选" />
            </div>
            <div v-if="deploymentEventsFetching && !(deploymentEvents || []).length" class="flex justify-center py-12"><NSpin /></div>
            <NEmpty v-else-if="!(deploymentEvents || []).length" description="暂无证书部署事件" class="py-12" />
            <div v-else class="space-y-3">
              <div v-for="event in deploymentEvents" :key="event.id" class="rounded-xl border border-panel-border p-3">
                <div class="flex items-start gap-3">
                  <div class="min-w-0 flex-1">
                    <div class="flex flex-wrap items-center gap-2">
                      <span class="font-medium text-slate-700">{{ event.domain }}</span>
                      <NTag size="tiny" :bordered="false">{{ event.source === 'letsencrypt' ? "Let's Encrypt" : '腾讯云' }}</NTag>
                      <NTag size="tiny" :bordered="false" :type="event.status === 'success' ? 'success' : event.status === 'failed' ? 'error' : event.status === 'running' ? 'info' : event.status === 'skipped' ? 'default' : 'warning'">
                        {{ deploymentStatusLabel[event.status] }}
                      </NTag>
                      <span class="text-xs text-slate-400">尝试 {{ event.attempts }}/5</span>
                    </div>
                    <p class="mt-1 text-xs text-slate-500">
                      目标：{{ event.targetName || '待匹配' }} · 更新于 {{ formatDateTime(event.updatedAt) }}
                      <span v-if="event.nextAttemptAt"> · 下次重试 {{ formatDateTime(event.nextAttemptAt) }}</span>
                    </p>
                    <p v-if="event.error" class="mt-1 break-all text-xs text-red-500">{{ event.error }}</p>
                  </div>
                  <NButton
                    v-if="event.status === 'failed' || event.status === 'skipped' || event.status === 'success'"
                    size="tiny"
                    secondary
                    :type="event.status === 'success' ? 'default' : 'warning'"
                    :loading="deploymentRetryMutation.isPending.value && deploymentRetryMutation.variables.value === event.id"
                    @click="deploymentRetryMutation.mutate(event.id)"
                  >
                    {{ event.status === 'success' ? '重新部署' : '立即重试' }}
                  </NButton>
                </div>
              </div>
            </div>
          </NTabPane>
          <NTabPane name="logs" tab="执行日志与统计">
            <div class="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div class="rounded-xl border border-panel-border p-3"><p class="text-xs text-slate-500">成功</p><p class="mt-1 text-xl font-semibold text-green-600">{{ taskStats?.byStatus?.success || 0 }}</p></div>
              <div class="rounded-xl border border-panel-border p-3"><p class="text-xs text-slate-500">失败</p><p class="mt-1 text-xl font-semibold text-red-600">{{ taskStats?.byStatus?.failed || 0 }}</p></div>
              <div class="rounded-xl border border-panel-border p-3"><p class="text-xs text-slate-500">腾讯云</p><p class="mt-1 text-xl font-semibold text-slate-700">{{ taskStats?.bySource?.tencent || 0 }}</p></div>
              <div class="rounded-xl border border-panel-border p-3"><p class="text-xs text-slate-500">Let's Encrypt</p><p class="mt-1 text-xl font-semibold text-slate-700">{{ (taskStats?.bySource?.letsencrypt || 0) + (taskStats?.bySource?.acme || 0) }}</p></div>
            </div>
            <div v-if="taskStats?.failureReasons?.length" class="mb-4 rounded-xl border border-panel-border p-3">
              <p class="mb-2 text-sm font-semibold text-slate-700">失败原因统计</p>
              <div v-for="item in taskStats.failureReasons" :key="item.reason" class="flex items-start justify-between gap-3 border-t border-panel-border py-2 first:border-0">
                <span class="break-all text-xs text-slate-600">{{ item.reason }}</span><NTag size="tiny" type="error" :bordered="false">{{ item.count }}</NTag>
              </div>
            </div>
            <div v-if="taskLogsFetching && !(taskLogs || []).length" class="flex justify-center py-12"><NSpin /></div>
            <NEmpty v-else-if="!(taskLogs || []).length" description="暂无任务执行日志" class="py-12" />
            <div v-else class="space-y-2">
              <div v-for="log in taskLogs" :key="log.id" class="rounded-xl border border-panel-border p-3">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-medium text-slate-700">{{ log.domain || '-' }}</span>
                  <NTag size="tiny" :bordered="false">{{ log.taskType }}</NTag>
                  <NTag size="tiny" :bordered="false" :type="log.status === 'success' ? 'success' : log.status === 'failed' ? 'error' : log.status === 'running' ? 'info' : 'default'">{{ log.status }}</NTag>
                  <span class="ml-auto text-xs text-slate-400">{{ formatDateTime(log.createdAt) }}</span>
                </div>
                <p v-if="log.targetName" class="mt-1 text-xs text-slate-500">目标：{{ log.targetName }}</p>
                <p v-if="log.message" class="mt-1 break-all text-xs" :class="log.status === 'failed' ? 'text-red-500' : 'text-slate-500'">{{ log.message }}</p>
              </div>
            </div>
          </NTabPane>
          <NTabPane name="sites" tab="站点部署">
            <div v-if="siteDeploymentsFetching && !(siteDeployments || []).length" class="flex justify-center py-12"><NSpin /></div>
            <NEmpty v-else-if="!(siteDeployments || []).length" description="暂无站点部署记录" class="py-12" />
            <div v-else class="space-y-3">
              <div v-for="site in siteDeployments" :key="site.site" class="rounded-xl border border-panel-border p-3">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-medium text-slate-700">{{ site.site }}</span>
                  <NTag size="tiny" :bordered="false" :type="site.latestStatus === 'success' ? 'success' : site.latestStatus === 'failed' ? 'error' : site.latestStatus === 'running' ? 'info' : site.latestStatus === 'skipped' ? 'default' : 'warning'">
                    {{ deploymentStatusLabel[site.latestStatus as SslDeploymentEvent['status']] || site.latestStatus }}
                  </NTag>
                  <span class="text-xs text-slate-400">{{ site.latestDomain }}</span>
                  <span class="ml-auto text-xs text-slate-400">{{ formatDateTime(site.latestAt) }}</span>
                </div>
                <p v-if="site.latestFingerprint" class="mt-1 break-all text-xs text-slate-500">
                  指纹：{{ site.latestFingerprint.slice(0, 24) }}…
                </p>
                <p v-if="site.latestError" class="mt-1 break-all text-xs text-red-500">{{ site.latestError }}</p>
                <div v-if="site.history.length > 1" class="mt-2 space-y-1 border-t border-panel-border pt-2">
                  <p class="text-xs font-medium text-slate-500">最近部署历史</p>
                  <div v-for="h in site.history" :key="h.eventId" class="flex items-center gap-2 text-xs text-slate-500">
                    <NTag size="tiny" :bordered="false" :type="h.status === 'success' ? 'success' : h.status === 'failed' ? 'error' : h.status === 'skipped' ? 'default' : 'warning'" style="min-width:48px;text-align:center;">
                      {{ deploymentStatusLabel[h.status as SslDeploymentEvent['status']] || h.status }}
                    </NTag>
                    <span class="truncate">{{ h.domain }}</span>
                    <span class="ml-auto shrink-0 text-slate-400">{{ formatDateTime(h.at) }}</span>
                  </div>
                </div>
              </div>
            </div>
          </NTabPane>
          <NTabPane name="edgeone" tab="加速绑定">
            <div class="mb-3 flex items-center gap-2">
              <NButton size="small" type="warning" secondary :loading="syncEdgeOneMutation.isPending.value" @click="syncEdgeOneMutation.mutate({})">
                全部同步到 CDN
              </NButton>
              <NButton size="small" quaternary :loading="syncEdgeOneMutation.isPending.value" @click="syncEdgeOneMutation.mutate({ dryRun: true })">
                预览
              </NButton>
              <span class="text-xs text-slate-400">将面板证书绑定到匹配的加速域名（EdgeOne / Cloudflare / ESA），消除 CDN 侧证书过期</span>
            </div>
            <div v-if="edgeOneBindingsFetching && !(edgeOneBindings || []).length" class="flex justify-center py-12"><NSpin /></div>
            <NEmpty v-else-if="!(edgeOneBindings || []).length" description="暂无加速证书绑定记录（启用域名加速或部署证书后自动生成）" class="py-12" />
            <div v-else class="space-y-3">
              <div v-for="b in edgeOneBindings" :key="b.id" class="rounded-xl border border-panel-border p-3">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-medium text-slate-700">{{ b.domainName }}</span>
                  <NTag size="tiny" :bordered="false" type="info">
                    {{ b.provider === 'cloudflare' ? 'Cloudflare' : b.provider === 'aliyun_esa' ? '阿里云 ESA' : 'EdgeOne' }}
                  </NTag>
                  <NTag size="tiny" :bordered="false" :type="b.status === 'synced' ? 'success' : b.status === 'failed' ? 'error' : 'warning'">
                    {{ b.status === 'synced' ? '已绑定' : b.status === 'failed' ? '失败' : b.status }}
                  </NTag>
                  <NTag v-if="b.upToDate === false" size="tiny" :bordered="false" type="warning">有更新证书</NTag>
                  <NTag v-if="b.upToDate === true" size="tiny" :bordered="false" type="success">已是最新</NTag>
                  <span class="ml-auto text-xs text-slate-400">{{ formatDateTime(b.syncedAt || b.updatedAt) }}</span>
                </div>
                <p class="mt-1 text-xs text-slate-500">
                  来源：{{ b.source === 'acme' ? "Let's Encrypt" : '腾讯云' }} · 证书 ID：{{ b.certRemoteId }}
                  <span v-if="b.edgeCertId"> · 边缘证书：{{ b.edgeCertId }}</span>
                </p>
                <p v-if="b.notAfter" class="text-xs text-slate-400">到期：{{ formatDateTime(b.notAfter) }}</p>
                <p v-if="b.lastError" class="mt-1 break-all text-xs text-red-500">{{ b.lastError }}</p>
                <div class="mt-2 flex gap-2">
                  <NButton size="tiny" secondary :loading="syncEdgeOneMutation.isPending.value" @click="syncEdgeOneMutation.mutate({ certId: b.certRemoteId })">
                    重新同步
                  </NButton>
                </div>
              </div>
            </div>
          </NTabPane>
        </NTabs>
      </NDrawerContent>
    </NDrawer>

    <NModal v-model:show="showNotificationSettings" preset="card" title="SSL 失败通知与任务清理" :style="{ width: isMobile ? '94vw' : '620px' }">
      <div v-if="notificationLoading" class="flex justify-center py-12"><NSpin /></div>
      <div v-else class="space-y-4">
        <NAlert type="info" :bordered="false">仅在签发最终失败、续期失败或部署连续失败 5 次时发送，避免重试过程重复告警。SMTP 参数复用“设置 → 域名到期提醒”中的邮件配置。</NAlert>
        <div class="flex items-center justify-between rounded-xl border border-panel-border p-3"><div><p class="text-sm font-medium text-slate-700">启用 SSL 失败通知</p><p class="text-xs text-slate-500">所有通道的总开关</p></div><NSwitch v-model:value="notificationForm.enabled" /></div>
        <div class="rounded-xl border border-panel-border p-3">
          <div class="mb-3 flex items-center justify-between"><span class="text-sm font-medium text-slate-700">邮件通知</span><NSwitch v-model:value="notificationForm.emailEnabled" /></div>
          <NInput v-model:value="notificationForm.emailTo" placeholder="收件邮箱，多个可用逗号分隔" />
        </div>
        <div class="rounded-xl border border-panel-border p-3">
          <div class="mb-3 flex items-center justify-between"><span class="text-sm font-medium text-slate-700">Webhook</span><NSwitch v-model:value="notificationForm.webhookEnabled" /></div>
          <NInput v-model:value="notificationForm.webhookUrl" type="password" show-password-on="click" placeholder="https://example.com/hooks/ssl" />
          <p class="mt-2 text-xs text-slate-500">出于 SSRF 防护，仅允许解析到公网地址的 HTTPS URL。</p>
          <div class="mt-3 flex items-center justify-between border-t border-panel-border pt-3">
            <div>
              <span class="text-sm font-medium text-slate-700">推送成功事件</span>
              <p class="text-xs text-slate-500">签发/续期/部署成功时也向此 Webhook 发送事件（默认只推失败）</p>
            </div>
            <NSwitch v-model:value="notificationForm.notifySuccessWebhook" :disabled="!notificationForm.webhookEnabled" />
          </div>
        </div>
        <div class="rounded-xl border border-panel-border p-3">
          <div class="mb-3 flex items-center justify-between"><span class="text-sm font-medium text-slate-700">企业微信机器人</span><NSwitch v-model:value="notificationForm.wecomEnabled" /></div>
          <NInput v-model:value="notificationForm.wecomWebhookUrl" type="password" show-password-on="click" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
        </div>
        <NFormItem label="成功任务与执行日志保留天数">
          <NInputNumber v-model:value="notificationForm.retentionDays" :min="1" :max="365" class="w-full" />
        </NFormItem>
      </div>
      <template #action>
        <div class="flex justify-end gap-2">
          <NButton :loading="checkExpiryMutation.isPending.value" @click="checkExpiryMutation.mutate()" title="立即检查证书到期情况并向已启用通道推送 30/7/1 天提醒">检测并推送到期提醒</NButton>
          <NButton :loading="testNotificationMutation.isPending.value" @click="testNotificationMutation.mutate()">测试通知</NButton>
          <NButton @click="showNotificationSettings = false">取消</NButton>
          <NButton type="primary" :loading="saveNotificationMutation.isPending.value" @click="saveNotificationMutation.mutate()">保存</NButton>
        </div>
      </template>
    </NModal>

    <NDrawer v-model:show="showDetail" :width="isMobile ? '100%' : 560" placement="right">
      <NDrawerContent title="证书详情" closable>
        <div v-if="detailLoading" class="flex justify-center py-20"><NSpin size="large" /></div>
        <template v-else-if="detailData">
          <NDescriptions label-placement="left" :column="1" bordered size="small">
            <NDescriptionsItem label="证书 ID">{{ detailData.remoteCertId }}</NDescriptionsItem>
            <NDescriptionsItem label="域名">{{ detailData.domain }}</NDescriptionsItem>
            <NDescriptionsItem label="SAN">
              <span v-if="Array.isArray(detailData.san)">{{ detailData.san.join(', ') }}</span>
              <span v-else>{{ detailData.san || '-' }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="产品">{{ detailData.productName || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="状态">
              <div class="flex items-center gap-2">
                <NTag
                  :type="(statusConfig[detailData.status] || statusConfig.applying).type"
                  size="small"
                  :bordered="false"
                >
                  {{ (statusConfig[detailData.status] || statusConfig.applying).label }}
                </NTag>
                <span
                  v-if="detailData.status === 'applying' || detailData.status === 'validating'"
                  class="inline-block w-2 h-2 rounded-full bg-blue-500 animate-pulse"
                  title="自动刷新中"
                />
              </div>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="detailData.statusMsg" label="状态信息">{{ detailData.statusMsg }}</NDescriptionsItem>
            <NDescriptionsItem label="颁发者">{{ detailData.issuer || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="生效时间">{{ formatDate(detailData.notBefore) }}</NDescriptionsItem>
            <NDescriptionsItem label="过期时间">
              {{ formatDate(detailData.notAfter) }}
              <NTag
                v-if="detailData.status === 'issued' && expiryDaysText(detailData.notAfter)"
                :type="expiryDaysText(detailData.notAfter)!.type"
                size="tiny"
                :bordered="false"
                class="ml-2"
              >
                {{ expiryDaysText(detailData.notAfter)!.text }}
              </NTag>
            </NDescriptionsItem>
          </NDescriptions>

          <!-- ── Verification section: ALWAYS show for applying/validating ── -->
          <template v-if="detailData.status === 'applying' || detailData.status === 'validating'">
            <div class="mt-5 rounded-xl border border-blue-200 bg-blue-50/50 p-4">
              <h3 class="text-sm font-semibold text-slate-700 mb-2">域名验证</h3>

              <!-- No dvAuths yet: waiting -->
              <template v-if="!detailData.dvAuths || detailData.dvAuths.length === 0">
                <div class="flex items-center gap-3 py-4 text-sm text-slate-500">
                  <NSpin size="small" />
                  <span>验证信息生成中，通常几秒内完成，页面每 10 秒自动刷新…</span>
                </div>
              </template>

              <!-- dvAuths available: show records -->
              <template v-else>
                <p class="text-xs text-slate-500 mb-3">
                  请按下方记录完成域名所有权验证。可以点击「自动添加 DNS 记录」一键添加，也可以手动在 DNS 服务商处添加。
                </p>

                <div v-for="(dv, i) in detailData.dvAuths" :key="i" class="rounded-lg border border-slate-200 bg-white mb-2 p-3 text-sm">
                  <div class="grid grid-cols-[auto_1fr_auto] gap-x-3 gap-y-1.5 items-start">
                    <span class="text-slate-400 text-xs leading-5">域名</span>
                    <span class="break-all text-slate-700 leading-5">{{ dv.domain }}</span>
                    <span />

                    <span class="text-slate-400 text-xs leading-5">类型</span>
                    <span class="text-slate-700 leading-5">
                      <NTag size="tiny" :bordered="false" :type="dv.type?.toUpperCase().includes('CNAME') ? 'info' : 'warning'">
                        {{ dv.type?.toUpperCase().includes('CNAME') ? 'CNAME' : 'TXT' }}
                      </NTag>
                    </span>
                    <span />

                    <span class="text-slate-400 text-xs leading-5">主机记录</span>
                    <code class="break-all text-xs bg-slate-100 rounded px-1.5 py-0.5 text-slate-700 select-all leading-5">{{ dv.key }}</code>
                    <NButton text size="tiny" @click="copyToClipboard(dv.key)" title="复制主机记录" class="shrink-0">
                      <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </NButton>

                    <span class="text-slate-400 text-xs leading-5">记录值</span>
                    <code class="break-all text-xs bg-slate-100 rounded px-1.5 py-0.5 text-slate-700 select-all leading-5">{{ dv.value }}</code>
                    <NButton text size="tiny" @click="copyToClipboard(dv.value)" title="复制记录值" class="shrink-0">
                      <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </NButton>
                  </div>
                </div>

                <!-- File verification info (if available) -->
                <template v-if="detailData.dvAuthDetail?.path">
                  <div class="mt-3 rounded-lg border border-slate-200 bg-white p-3 text-sm">
                    <p class="text-xs font-medium text-slate-600 mb-2">文件验证方式（备选）</p>
                    <div class="grid grid-cols-[auto_1fr_auto] gap-x-3 gap-y-1.5 items-start">
                      <span class="text-slate-400 text-xs leading-5">验证路径</span>
                      <code class="break-all text-xs bg-slate-100 rounded px-1.5 py-0.5 text-slate-700 select-all leading-5">{{ detailData.dvAuthDetail.path }}</code>
                      <NButton text size="tiny" @click="copyToClipboard(detailData.dvAuthDetail!.path)" title="复制路径" class="shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                      </NButton>

                      <span class="text-slate-400 text-xs leading-5">文件内容</span>
                      <code class="break-all text-xs bg-slate-100 rounded px-1.5 py-0.5 text-slate-700 select-all leading-5">{{ detailData.dvAuthDetail.value }}</code>
                      <NButton text size="tiny" @click="copyToClipboard(detailData.dvAuthDetail!.value)" title="复制内容" class="shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                      </NButton>
                    </div>
                    <p class="text-xs text-slate-400 mt-2">
                      在域名根目录下创建上述路径文件，写入对应内容，确保可通过 http://{{ detailData.domain }}{{ detailData.dvAuthDetail.path }} 访问。
                    </p>
                  </div>
                </template>

                <!-- Guidance hint -->
                <p class="text-xs text-slate-400 mt-3">
                  DNS 记录添加后 CA 验证通常需要 1~15 分钟。页面每 10 秒自动刷新状态，签发后会自动提示。
                </p>
              </template>
            </div>

            <!-- Action buttons for verification -->
            <div class="mt-4 flex flex-wrap gap-3">
              <NButton
                v-if="detailData.dvAuths?.length && detailHasDnsCreds"
                type="primary"
                size="small"
                :loading="autoDnsLoading"
                @click="autoDnsForDetail"
              >
                自动添加 DNS 记录
              </NButton>
              <NButton
                type="info"
                size="small"
                @click="checkAndCompleteDetail"
              >
                <template #icon><CheckCircle :size="14" /></template>
                检测并提交验证
              </NButton>
              <NButton size="small" secondary @click="refreshDetail">
                <template #icon><RefreshCw :size="14" /></template>
                刷新详情
              </NButton>
            </div>
          </template>

          <!-- ── For non-verification states: show dvAuths as reference if present ── -->
          <template v-else-if="detailData.dvAuths && detailData.dvAuths.length > 0">
            <h3 class="mt-6 mb-3 text-sm font-semibold text-slate-700">域名验证记录（历史）</h3>
            <div v-for="(dv, i) in detailData.dvAuths" :key="i" class="panel-muted mb-2 p-3 text-sm">
              <div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                <span class="text-slate-400 text-xs">类型</span>
                <span class="text-slate-600 text-xs">{{ dv.type }}</span>
                <span class="text-slate-400 text-xs">主机记录</span>
                <span class="break-all text-slate-600 text-xs">{{ dv.key }}</span>
                <span class="text-slate-400 text-xs">记录值</span>
                <span class="break-all text-slate-600 text-xs">{{ dv.value }}</span>
              </div>
            </div>
          </template>

          <!-- Actions for non-verification states -->
          <div v-if="detailData.status !== 'applying' && detailData.status !== 'validating'" class="mt-6 flex flex-wrap gap-3">
            <NButton size="small" secondary @click="refreshDetail">
              <template #icon><RefreshCw :size="14" /></template>
              刷新详情
            </NButton>
            <NButton
              v-if="detailData.status === 'issued'"
              type="primary"
              size="small"
              @click="handleDownload(detailData)"
            >
              <template #icon><Download :size="14" /></template>
              下载证书
            </NButton>
            <NButton
              v-if="detailData.status === 'issued'"
              size="small"
              secondary
              @click="openCertView(detailData)"
            >
              <template #icon><FileText :size="14" /></template>
              在线查看
            </NButton>
            <NButton
              v-if="detailData.status === 'issued'"
              size="small"
              secondary
              type="info"
              :loading="deployMutation.isPending.value"
              @click="handleDeploy(detailData)"
            >
              <template #icon><Rocket :size="14" /></template>
              部署
            </NButton>
            <NButton
              v-if="detailData.status === 'expired' || (detailData.status === 'issued' && withinDays(detailData.notAfter))"
              type="warning"
              size="small"
              @click="quickReapply(detailData)"
            >
              <template #icon><RotateCw :size="14" /></template>
              续期此证书
            </NButton>
            <NButton
              v-if="detailData.dvAuths?.length && detailHasDnsCreds && (detailData.status === 'issued' || detailData.status === 'expired')"
              size="small"
              secondary
              :loading="cleanupDnsLoading"
              @click="cleanupDnsForDetail"
            >
              <template #icon><Trash2 :size="14" /></template>
              清理验证记录
            </NButton>
          </div>

          <!-- Deployed resources -->
          <template v-if="detailData.deployedResources && detailData.deployedResources.length > 0">
            <h3 class="mt-6 mb-3 text-sm font-semibold text-slate-700">部署资源</h3>
            <div v-for="(res, i) in detailData.deployedResources" :key="i" class="panel-muted mb-2 p-3 text-sm">
              <div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                <template v-for="(val, key) in res" :key="key">
                  <span class="text-slate-400 text-xs">{{ key }}</span>
                  <span class="break-all text-slate-600 text-xs">{{ val }}</span>
                </template>
              </div>
            </div>
          </template>
        </template>
      </NDrawerContent>
    </NDrawer>

    <!-- Online Certificate Viewer — full public PEM + parsed metadata -->
    <NModal v-model:show="showCertView" preset="card" style="max-width: 760px;" :title="`证书内容 · ${certViewData?.domain || ''}`">
      <div v-if="certViewLoading" class="flex justify-center py-16"><NSpin size="large" /></div>
      <template v-else-if="certViewData">
        <NDescriptions :column="2" label-placement="left" size="small" bordered class="mb-4">
          <NDescriptionsItem label="公用名 (CN)">{{ certViewData.meta.subjectCN || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="颁发者">{{ certViewData.meta.issuer || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="生效时间">{{ formatDateTime(certViewData.meta.notBefore) }}</NDescriptionsItem>
          <NDescriptionsItem label="到期时间">{{ formatDateTime(certViewData.meta.notAfter) }}</NDescriptionsItem>
          <NDescriptionsItem label="签名算法">{{ certViewData.meta.signatureAlgorithm || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="序列号">
            <span class="break-all text-xs">{{ certViewData.meta.serialNumber || '-' }}</span>
          </NDescriptionsItem>
          <NDescriptionsItem label="SHA-256 指纹" :span="2">
            <span class="break-all text-xs">{{ certViewData.meta.fingerprintSha256 || '-' }}</span>
          </NDescriptionsItem>
          <NDescriptionsItem label="SAN 域名" :span="2">
            <div class="flex flex-wrap gap-1">
              <NTag v-for="n in (certViewData.meta.san || [])" :key="n" size="tiny" :bordered="false">{{ n }}</NTag>
              <span v-if="!certViewData.meta.san?.length" class="text-xs text-slate-400">无</span>
            </div>
          </NDescriptionsItem>
        </NDescriptions>
        <div class="mb-2 flex items-center justify-between">
          <span class="text-sm font-semibold text-slate-700">证书内容（PEM）</span>
          <NButton size="tiny" secondary @click="copyCertPem">
            <template #icon><Copy :size="12" /></template>
            复制
          </NButton>
        </div>
        <pre class="max-h-96 overflow-auto rounded-lg border border-panel-border bg-slate-50 p-3 text-xs leading-relaxed break-all whitespace-pre-wrap">{{ certViewData.publicKey }}</pre>
        <p class="mt-2 text-xs text-slate-400">仅显示公钥证书（包含完整证书链）；私钥不会在此展示。</p>
      </template>
      <template #footer>
        <NButton @click="showCertView = false">关闭</NButton>
        <NButton type="primary" @click="downloadViewedCert">下载 ZIP</NButton>
      </template>
    </NModal>
  </div>
</template>
