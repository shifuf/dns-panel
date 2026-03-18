<script setup lang="ts">
import { ref, computed, watch, h, onUnmounted } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import {
  NButton, NTag, NDataTable, NModal, NFormItem, NInput, NSelect, NAlert,
  NEmpty, NSpin, NPagination, NDrawer, NDrawerContent, NDescriptions,
  NDescriptionsItem, NSwitch, NTooltip, useMessage, useDialog,
} from 'naive-ui';
import { RefreshCw, Search, Plus, Upload, Download, Trash2, Eye, CheckCircle, KeyRound, Pencil, AlertTriangle, RotateCw, ArrowUpDown, FileDown } from 'lucide-vue-next';
import {
  getSslCredentials, createSslCredential, updateSslCredential, deleteSslCredential as deleteSslCred,
  getSslCertificates, getSslCertificateDetail, applySslCertificate,
  completeSslCertificate, downloadSslCertificate, uploadSslCertificate,
  deleteSslCertificate, syncSslCertificates, renewExpiredCertificates,
  autoDnsSslCertificate, cleanupDnsSslCertificate,
} from '@/services/ssl';
import { getDnsCredentials } from '@/services/dnsCredentials';
import { getDomains } from '@/services/domains';
import AddZoneDialog from '@/components/Dashboard/AddZoneDialog.vue';
import type { SslCredential, RenewResult } from '@/services/ssl';
import { useResponsive } from '@/composables/useResponsive';
import type { SslCertificate, SslCertificateDetail, SslCertificateStatus } from '@/types/ssl';
import type { Domain } from '@/types';

const message = useMessage();
const dialog = useDialog();
const queryClient = useQueryClient();
const { isMobile } = useResponsive();

// ── Credential selection ───────────────────────────────────────
const SSL_CRED_STORAGE_KEY = 'ssl_selected_credential';
const savedCredId = localStorage.getItem(SSL_CRED_STORAGE_KEY);
const selectedCredentialId = ref<number | 'all' | null>(
  savedCredId === 'all' ? 'all' : savedCredId ? parseInt(savedCredId, 10) || null : null,
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
  const opts: Array<{ label: string; value: number | 'all' }> = [];
  const list = sslCredentials.value || [];
  if (list.length > 1) {
    opts.push({ label: '全部账号', value: 'all' });
  }
  for (const c of list) {
    const suffix = c.provider === 'dnspod' ? '（DNS 共用）' : '';
    opts.push({ label: `${c.name}${suffix}`, value: c.id });
  }
  return opts;
});

watch(sslCredentials, (list) => {
  if (!list || !list.length) return;
  if (selectedCredentialId.value === 'all') return;
  if (selectedCredentialId.value && list.some(c => c.id === selectedCredentialId.value)) return;
  selectedCredentialId.value = list.length > 1 ? 'all' : list[0].id;
}, { immediate: true });

function credNameById(id?: number) {
  if (!id) return '';
  const c = (sslCredentials.value || []).find(x => x.id === id);
  return c ? c.name : `#${id}`;
}

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
const pageSize = ref(20);
const searchKeyword = ref('');
const filterCredentialId = ref<number | null>(null);
const hasActiveApplying = ref(false);


const {
  data: certsResponse,
  isLoading,
  error: certsError,
} = useQuery({
  queryKey: computed(() => [
    'ssl-certificates',
    selectedCredentialId.value,
    page.value,
    pageSize.value,
    searchKeyword.value,
    filterCredentialId.value,
  ]),
  queryFn: async () => {
    if (!selectedCredentialId.value) return { data: [], pagination: { total: 0, page: 1, limit: 20, pages: 0 }, errors: undefined };
    const res = await getSslCertificates(selectedCredentialId.value, {
      page: page.value,
      limit: pageSize.value,
      search: searchKeyword.value || undefined,
      filterCredentialId: filterCredentialId.value || undefined,
    });
    return {
      data: res.data || [],
      pagination: res.pagination || { total: 0, page: 1, limit: 20, pages: 0 },
      errors: res.errors,
    };
  },
  enabled: computed(() => !!selectedCredentialId.value),
  refetchInterval: computed(() => hasActiveApplying.value ? 15000 : false),
});

const certificates = computed(() => certsResponse.value?.data || []);
const totalCount = computed(() => certsResponse.value?.pagination?.total || 0);
const aggregationErrors = computed(() => certsResponse.value?.errors || []);
const certsErrorMsg = computed(() => certsError.value ? String(certsError.value) : '');
watch(certificates, (list) => {
  hasActiveApplying.value = list.some(c => c.status === 'applying' || c.status === 'validating');
}, { immediate: true });

// ── Expiring/expired certificate detection ─────────────────────
const expiringCerts = computed(() => {
  const now = new Date();
  const threshold = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  return certificates.value.filter(c => {
    if (!c.notAfter || c.status !== 'issued') return false;
    return new Date(c.notAfter) <= threshold;
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
  try {
    return new Date(v).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' });
  } catch { return v; }
}

function expiryDaysText(notAfter?: string): { text: string; type: 'success' | 'warning' | 'error' | 'default' } | null {
  if (!notAfter) return null;
  try {
    const diff = Math.floor((new Date(notAfter).getTime() - Date.now()) / 86400000);
    if (diff < 0) return { text: `已过期 ${Math.abs(diff)} 天`, type: 'error' };
    if (diff <= 7) return { text: `剩余 ${diff} 天`, type: 'error' };
    if (diff <= 30) return { text: `剩余 ${diff} 天`, type: 'warning' };
    return { text: `剩余 ${diff} 天`, type: 'success' };
  } catch { return null; }
}

// ── Status filter ───────────────────────────────────────────────
const statusFilter = ref<SslCertificateStatus | null>(null);

watch([selectedCredentialId, searchKeyword, filterCredentialId, statusFilter], () => { page.value = 1; });

const statusCounts = computed(() => {
  const counts: Record<string, number> = {};
  for (const c of certificates.value) {
    counts[c.status] = (counts[c.status] || 0) + 1;
  }
  return counts;
});

const filteredCertificates = computed(() => {
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
      cmp = (a.notAfter || '9999').localeCompare(b.notAfter || '9999');
    } else if (sortBy.value === 'status') {
      cmp = (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99);
    } else if (sortBy.value === 'remoteCreatedAt') {
      cmp = (a.remoteCreatedAt || '').localeCompare(b.remoteCreatedAt || '');
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
const _settingApplyDnsCredId = ref(false);

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
  if (selectedCredentialId.value === 'all') return null;
  return selectedCredentialId.value;
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

// ── Quick re-apply for expired/expiring certs ──────────────────
function quickReapply(cert: SslCertificate) {
  const credId = getCredIdForCert(cert);
  if (!credId) {
    message.error('无法确定凭证，请在单一账号下操作');
    return;
  }
  selectedCredentialId.value = credId;
  applyDomain.value = cert.domain || '';
  applyDomainMode.value = 'manual';
  applyManagedRoot.value = null;
  applySubdomain.value = '';
  applyWildcard.value = cert.domain?.startsWith('*.') || false;
  applyDvMethod.value = 'DNS';
  applyAutoDns.value = true;
  applyDnsCredTouched.value = false;
  setApplyDnsCredId(null);
  // Pass old cert ID for Tencent renewal flow (only for issued certs, not expired)
  applyOldCertId.value = cert.status === 'issued' ? cert.remoteCertId : null;
  showApply.value = true;
}

function openApply() {
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

// ── Filter chips for "all" mode ────────────────────────────────
const filterOptions = computed(() => {
  const list = sslCredentials.value || [];
  return [
    { label: '全部', value: null as number | null },
    ...list.map(c => ({ label: c.name, value: c.id })),
  ];
});

// ── Table columns ──────────────────────────────────────────────
const isAllMode = computed(() => selectedCredentialId.value === 'all');

const columns = computed(() => {
  const cols: any[] = [
    { type: 'selection' as const },
    {
      title: '域名',
      key: 'domain',
      minWidth: 180,
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
      width: 120,
      render: (row: SslCertificate) =>
        h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => row.credentialName || credNameById(row.credentialId) || '-'),
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
        h('div', { class: 'flex items-center gap-2' }, [
          h(NButton, { size: 'tiny', secondary: true, onClick: () => openDetail(row) },
            { icon: () => h(Eye, { size: 13 }), default: () => '详情' }),
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
          (row.status === 'expired' || (row.status === 'issued' && row.notAfter && new Date(row.notAfter).getTime() - Date.now() < 30 * 86400000))
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
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <section class="panel p-4">
      <div class="toolbar-row">
        <div>
          <h1 class="page-title">SSL 证书管理</h1>
          <p class="page-subtitle">
            腾讯云免费 DV 证书申请、查看、下载与上传
            <span v-if="hasActiveApplying" class="inline-flex items-center gap-1 ml-2 text-blue-500">
              <span class="inline-block w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
              <span class="text-xs">自动刷新中</span>
            </span>
          </p>
        </div>
        <div class="flex-1" />

        <NSelect
          v-if="credentialOptions.length > 0"
          v-model:value="selectedCredentialId"
          :options="credentialOptions"
          placeholder="选择凭证"
          size="small"
          class="!w-52"
        />
        <NButton size="small" quaternary @click="openAddCred" title="添加 SSL 凭证">
          <template #icon><KeyRound :size="14" /></template>
        </NButton>
        <NButton size="small" quaternary @click="showCredList = !showCredList" title="管理凭证">
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
        <NButton size="small" type="primary" :disabled="!selectedCredentialId || selectedCredentialId === 'all'" @click="openApply">
          <template #icon><Plus :size="14" /></template>
          申请
        </NButton>
        <NButton size="small" secondary :disabled="!selectedCredentialId || selectedCredentialId === 'all'" @click="showUpload = true">
          <template #icon><Upload :size="14" /></template>
          上传
        </NButton>
        <NButton
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
          size="small"
          secondary
          :loading="renewMutation.isPending.value"
          @click="openRenew"
          title="自动续期即将过期的证书"
        >
          <template #icon><RotateCw :size="14" /></template>
          自动续期
        </NButton>
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
    <section v-if="!credsLoading && !credsError && (!sslCredentials || sslCredentials.length === 0)" class="panel p-8">
      <NEmpty description="暂无可用的腾讯云凭证">
        <template #extra>
          <p class="mb-3 text-sm text-slate-500">
            需要含有 SecretId / SecretKey 的腾讯云凭证。
            已有的腾讯云 DNS 凭证会自动出现，也可以单独添加。
          </p>
          <NButton size="small" type="primary" @click="openAddCred">
            <template #icon><Plus :size="14" /></template>
            添加 SSL 凭证
          </NButton>
        </template>
      </NEmpty>
    </section>

    <!-- Table -->
    <section v-else-if="(sslCredentials && sslCredentials.length > 0) || credsError" class="panel p-4">
      <!-- Filter chips for "all" mode -->
      <div v-if="isAllMode && (sslCredentials?.length ?? 0) > 1" class="mb-3 flex flex-wrap gap-2">
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
          全部 ({{ certificates.length }})
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
            <NTag v-if="isAllMode && cert.credentialName" size="tiny" :bordered="false" type="info">{{ cert.credentialName }}</NTag>
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
              <NButton v-if="cert.status === 'issued'" text size="tiny" type="primary" @click="handleDownload(cert)">
                <template #icon><Download :size="12" /></template>
                下载
              </NButton>
              <NButton
                v-if="cert.status === 'expired' || (cert.status === 'issued' && cert.notAfter && new Date(cert.notAfter).getTime() - Date.now() < 30 * 86400000)"
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
          :scroll-x="isAllMode ? 1000 : 900"
          :max-height="560"
        />
      </template>

      <!-- Pagination -->
      <div v-if="totalCount > pageSize" class="mt-4 flex justify-end">
        <NPagination
          v-model:page="page"
          :page-size="pageSize"
          :item-count="totalCount"
          :page-sizes="[20, 50, 100]"
          show-size-picker
          @update:page-size="(s: number) => { pageSize = s; page = 1; }"
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
    <NModal v-model:show="showApply" preset="dialog" :title="applyOldCertId ? '续期证书' : '申请免费 DV 证书'" :mask-closable="false" style="max-width: 520px;">
      <div class="space-y-4 pt-2">
        <NAlert v-if="applyOldCertId" type="info" :bordered="false">
          正在续期证书 {{ applyOldCertId }}，将使用腾讯云官方续期流程。
        </NAlert>
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
        <NFormItem label="验证方式">
          <NSelect v-model:value="applyDvMethod" :options="dvMethodOptions" />
        </NFormItem>

        <template v-if="applyDvMethod === 'DNS'">
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

        <NAlert v-if="applyDvMethod === 'DNS_AUTO'" type="info" :bordered="false">
          DNS 自动验证要求域名的 NS 记录已指向 DNSPod（腾讯云）。如果域名使用 Cloudflare、阿里云或其他 DNS 服务商解析，请选择「DNS 验证」并开启自动添加记录——只需在下方选择对应的 DNS 凭证即可自动完成验证。
        </NAlert>
      </div>
      <template #action>
        <NButton @click="showApply = false">取消</NButton>
        <NButton
          type="primary"
          :loading="applyMutation.isPending.value"
          :disabled="!applyFinalDomain"
          @click="applyMutation.mutate()"
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
              v-if="detailData.status === 'expired' || (detailData.status === 'issued' && detailData.notAfter && new Date(detailData.notAfter).getTime() - Date.now() < 30 * 86400000)"
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
  </div>
</template>
