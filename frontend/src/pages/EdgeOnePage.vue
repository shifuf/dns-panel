<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { NAlert, NButton, NEmpty, NInput, NInputNumber, NModal, NSelect, NSpin, NTag, useDialog, useMessage } from 'naive-ui';
import { Link2, Pause, Play, Plus, RefreshCw, Search, SearchCheck, ShieldCheck, Trash2, Wand2 } from 'lucide-vue-next';
import DnsCredentialManagement from '@/components/Settings/DnsCredentialManagement.vue';
import { getDnsCredentials } from '@/services/dnsCredentials';
import {
  autoConfigureAccelerationCname, autoVerifyAccelerationSiteDns, bindAccelerationCertificate,
  createAccelerationSite, deleteAccelerationDomain, deleteAccelerationSite,
  finalizeAccelerationDomain,
  getAccelerationDomainStatus, identifyAccelerationSite, listAccelerationCertificates, listAccelerationDomains, listAccelerationSites,
  updateAccelerationDomainStatus, updateAccelerationSiteStatus, verifyAccelerationSite,
  type AccelerationCertificate, type AccelerationDnsCheck, type AccelerationDomain, type AccelerationDnsRecord, type AccelerationDnsConflict, type AccelerationVerificationInfo, type AccelerationSite,
} from '@/services/accelerations';
import { applySslCertificate, getSslCertificates, getSslCredentials, type SslCredential } from '@/services/ssl';
import type { DnsCredential } from '@/types/dns';
import type { SslCertificate } from '@/types/ssl';
import { formatDateSafe } from '@/utils/formatters';
import { isValidDomain, isValidIPv4, isValidIPv6 } from '@/utils/validators';

const provider = 'edgeone';
const message = useMessage();
const dialog = useDialog();
const credentials = ref<DnsCredential[]>([]);
const dnsCredentials = ref<DnsCredential[]>([]);
const credentialId = ref<number | null>(null);
const dnsCredentialId = ref<number | null>(null);
const sslCredentials = ref<SslCredential[]>([]);
const sites = ref<AccelerationSite[]>([]);
const siteId = ref('');
const domains = ref<AccelerationDomain[]>([]);
const certificates = ref<AccelerationCertificate[]>([]);
const sslManagedCertificates = ref<SslCertificate[]>([]);
const verification = ref<AccelerationVerificationInfo | null>(null);
const verificationCode = ref('');
const siteKeyword = ref('');
const domainKeyword = ref('');
const statusMap = ref<Record<string, string>>({});
const dnsCheckMap = ref<Record<string, AccelerationDnsCheck>>({});
const loadingCredentials = ref(false);
const loadingDnsCredentials = ref(false);
const loadingSslCredentials = ref(false);
const loadingSites = ref(false);
const loadingDomains = ref(false);
const loadingCertificates = ref(false);
const loadingSslManagedCertificates = ref(false);
const verifying = ref(false);
const refreshingVerification = ref(false);
const autoSiteDnsLoading = ref(false);
const autoDomainDnsTarget = ref<string | null>(null);
const siteActionTarget = ref<string | null>(null);
const siteActionType = ref<'toggle' | 'delete' | null>(null);
const domainActionTarget = ref<string | null>(null);
const domainActionType = ref<'toggle' | 'delete' | 'inspect' | null>(null);
const showSiteModal = ref(false);
const showDomainModal = ref(false);
const showCertBindModal = ref(false);
const savingSite = ref(false);
const savingDomain = ref(false);
const applyingSslCertificate = ref(false);
const bindingCert = ref(false);
const bindHostLocked = ref(false);
const bindSslCredentialId = ref<number | null>(null);
const editingDomain = ref<string | null>(null);
const connectionNotice = ref<{ type: 'success' | 'warning' | 'info'; text: string } | null>(null);
const siteForm = ref({ zoneName: '', area: 'global', type: 'partial', planId: '' });
const domainForm = ref({
  subDomain: '',
  originType: 'IP_DOMAIN',
  originValue: '',
  backupOriginValue: '',
  hostHeaderMode: 'acceleration',
  customHostHeader: '',
  originProtocol: 'FOLLOW',
  httpOriginPort: 80,
  httpsOriginPort: 443,
  ipv6Status: 'follow',
});
const certBindForm = ref({ hosts: '', certId: '' });

const showNextStepModal = ref(false);
const nextStepLoading = ref(false);
const nextStepData = ref<{
  domain?: AccelerationDomain;
  dnsRecordsAdded: AccelerationDnsRecord[];
  dnsConflicts: AccelerationDnsConflict[];
  dnsErrors: Array<{ key?: string; error: string }>;
  dnsCheck?: AccelerationDnsCheck;
  hostRecord: string;
  cnameTarget: string;
  message: string;
} | null>(null);

const site = computed(() => sites.value.find((item) => String(item.siteId || item.zoneId || '') === String(siteId.value)) || null);
const credentialOptions = computed(() => credentials.value.map((item) => ({ label: `${item.name} · ${item.providerName || item.provider}`, value: item.id })));
const dnsCredentialOptions = computed(() =>
  dnsCredentials.value
    .filter((item) => ['cloudflare', 'dnspod', 'dnspod_token'].includes(String(item.provider || '').toLowerCase()))
    .map((item) => ({ label: `${item.name} · ${item.providerName || item.provider}`, value: item.id })),
);
const filteredSites = computed(() => {
  const keyword = siteKeyword.value.trim().toLowerCase();
  if (!keyword) return sites.value;
  return sites.value.filter((item) => {
    const zoneName = String(item.zoneName || item.siteName || '').toLowerCase();
    const id = String(item.siteId || item.zoneId || '').toLowerCase();
    return zoneName.includes(keyword) || id.includes(keyword);
  });
});
const filteredDomains = computed(() => {
  const keyword = domainKeyword.value.trim().toLowerCase();
  if (!keyword) return domains.value;
  return domains.value.filter((item) => {
    const domainName = String(item.domainName || '').toLowerCase();
    const origin = String(item.originValue || '').toLowerCase();
    const cname = String(item.cnameTarget || '').toLowerCase();
    return domainName.includes(keyword) || origin.includes(keyword) || cname.includes(keyword);
  });
});

function asErrorText(err: any): string {
  return typeof err === 'string' ? err : (err?.message || String(err));
}

function isSiteActionLoading(target: AccelerationSite | null | undefined, action: 'toggle' | 'delete') {
  const siteKey = String(target?.siteId || target?.zoneId || '').trim();
  return !!siteKey && siteActionTarget.value === siteKey && siteActionType.value === action;
}

function isSiteActionBusy(target: AccelerationSite | null | undefined) {
  const siteKey = String(target?.siteId || target?.zoneId || '').trim();
  return !!siteKey && siteActionTarget.value === siteKey;
}

function isDomainActionLoading(target: AccelerationDomain | null | undefined, action: 'toggle' | 'delete' | 'inspect') {
  const domainKey = String(target?.domainName || '').trim();
  return !!domainKey && domainActionTarget.value === domainKey && domainActionType.value === action;
}

function isDomainActionBusy(target: AccelerationDomain | null | undefined) {
  const domainKey = String(target?.domainName || '').trim();
  return !!domainKey && domainActionTarget.value === domainKey;
}

function parseList(raw: string): string[] {
  return Array.from(new Set(
    String(raw || '')
      .split(/[;,\n]/)
      .map((item) => item.trim())
      .filter(Boolean),
  ));
}

function normalizeHostValue(value: string): string {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function normalizeDomainValue(value: string): string {
  return normalizeHostValue(value).replace(/^\.+/, '').replace(/\.+$/, '');
}

function resolveAccelerationDomain(subDomain: string, zoneName?: string | null): string {
  const zone = normalizeDomainValue(String(zoneName || ''));
  const raw = normalizeDomainValue(subDomain);
  if (!raw || raw === '@') return zone;
  if (!zone) return raw;
  if (raw === zone || raw.endsWith(`.${zone}`)) return raw;
  if (!raw.includes('.')) return `${raw}.${zone}`;
  return raw;
}

function extractSubDomain(domainName?: string | null, zoneName?: string | null): string {
  const fullDomain = normalizeDomainValue(String(domainName || ''));
  const zone = normalizeDomainValue(String(zoneName || ''));
  if (!fullDomain) return '';
  if (!zone) return fullDomain;
  if (fullDomain === zone) return '@';
  const suffix = `.${zone}`;
  if (fullDomain.endsWith(suffix)) return fullDomain.slice(0, -suffix.length) || '@';
  return fullDomain;
}

function isValidOriginTarget(value: string): boolean {
  const target = normalizeDomainValue(value);
  return !!target && (isValidIPv4(target) || isValidIPv6(target) || isValidDomain(target));
}

function isValidHostHeaderValue(value: string): boolean {
  const target = normalizeDomainValue(value);
  return !!target && isValidDomain(target);
}

function normalizeCertificateId(value: string): string {
  return String(value || '').trim().toLowerCase();
}

function parseSanValues(value: string | string[] | undefined): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeHostValue(String(item || ''))).filter(Boolean);
  }
  return parseList(String(value || '')).map((item) => normalizeHostValue(item)).filter(Boolean);
}

function wildcardMatches(pattern: string, host: string): boolean {
  const normalizedPattern = normalizeHostValue(pattern);
  const normalizedHost = normalizeDomainValue(host);
  if (!normalizedPattern || !normalizedHost) return false;
  if (normalizedPattern === normalizedHost) return true;
  if (!normalizedPattern.startsWith('*.')) return false;
  const suffix = normalizedPattern.slice(1);
  if (!normalizedHost.endsWith(suffix)) return false;
  const patternLabels = normalizedPattern.slice(2).split('.').filter(Boolean);
  const hostLabels = normalizedHost.split('.').filter(Boolean);
  return hostLabels.length === patternLabels.length + 1;
}

function certificateMatchesHost(cert: SslCertificate, host: string): boolean {
  const normalizedHost = normalizeDomainValue(host);
  if (!normalizedHost) return false;
  const candidates = [cert.domain, ...parseSanValues(cert.san)].map((item) => normalizeHostValue(item)).filter(Boolean);
  return candidates.some((pattern) => wildcardMatches(pattern, normalizedHost));
}

const currentAccelerationDomain = computed(() => resolveAccelerationDomain(domainForm.value.subDomain, site.value?.zoneName));
const currentHostHeader = computed(() =>
  domainForm.value.hostHeaderMode === 'custom'
    ? normalizeDomainValue(domainForm.value.customHostHeader)
    : currentAccelerationDomain.value,
);
const bindHosts = computed(() => parseList(certBindForm.value.hosts).map((item) => normalizeDomainValue(item)).filter(Boolean));

type BoundCertificateView = AccelerationCertificate & {
  source: 'ssl' | 'edgeone';
  sourceLabel: string;
  credentialId?: number;
  credentialName?: string;
  missingInSsl?: boolean;
};

function normalizeCertificateHosts(item?: AccelerationCertificate | null): string[] {
  if (!item) return [];
  const hosts = Array.isArray(item.hosts) && item.hosts.length ? item.hosts : parseList(String(item.host || ''));
  return hosts.map((host) => normalizeDomainValue(host)).filter(Boolean);
}

function describeCertificate(item?: AccelerationCertificate | null, options: { includeHosts?: boolean } = {}): string {
  if (!item) return '';
  const parts: string[] = [];
  if (options.includeHosts) {
    const hosts = normalizeCertificateHosts(item);
    if (hosts.length) parts.push(hosts.join(', '));
  }
  if (item.certId || item.certificateId) parts.push(String(item.certId || item.certificateId || ''));
  if (item.signAlgo) parts.push(String(item.signAlgo));
  if (item.issuer) parts.push(String(item.issuer));
  if (item.expireTime) parts.push(`到期 ${formatDateSafe(item.expireTime)}`);
  return parts.join(' · ');
}

function buildCertificateKey(item?: AccelerationCertificate | null): string {
  const certId = normalizeCertificateId(String(item?.certId || item?.certificateId || ''));
  const hosts = normalizeCertificateHosts(item);
  const host = normalizeDomainValue(String(item?.host || ''));
  return certId ? `id:${certId}` : `host:${hosts.join(',') || host || '-'}`;
}

function findManagedSslCertificateById(certId?: string | null): SslCertificate | null {
  const normalized = normalizeCertificateId(String(certId || ''));
  if (!normalized) return null;
  return sslManagedCertificates.value.find((item) => normalizeCertificateId(item.remoteCertId) === normalized) || null;
}

function buildBoundCertificateFromSsl(cert: SslCertificate, host: string): BoundCertificateView {
  return {
    hosts: [host],
    host,
    certificateId: cert.remoteCertId,
    certId: cert.remoteCertId,
    certType: cert.certType || 'sslcert',
    status: cert.status || 'issued',
    issuer: cert.issuer || null,
    subject: cert.domain || null,
    signAlgo: null,
    effectiveTime: cert.notBefore,
    expireTime: cert.notAfter,
    source: 'ssl',
    sourceLabel: cert.credentialName ? `SSL 证书库 · ${cert.credentialName}` : 'SSL 证书库',
    credentialId: cert.credentialId,
    credentialName: cert.credentialName,
    missingInSsl: false,
  };
}

function buildBoundCertificateFromEdgeOne(item: AccelerationCertificate, host: string, sourceLabel: string): BoundCertificateView {
  const hosts = Array.from(new Set([host, ...normalizeCertificateHosts(item)])).filter(Boolean);
  return {
    ...item,
    hosts,
    host: hosts[0] || host,
    certificateId: item.certificateId || item.certId,
    certId: item.certId || item.certificateId,
    source: 'edgeone',
    sourceLabel,
    missingInSsl: true,
  };
}

function createDomainBoundCertificate(item?: AccelerationDomain | null): AccelerationCertificate | null {
  if (!item) return null;
  const host = normalizeDomainValue(item.domainName);
  if (!host) return null;
  const certificateId = String(item.certificateId || item.certificateIds?.[0] || '').trim();
  if (!item.certificateBound && !certificateId && !item.certificateExpireTime && !item.certificateSignAlgo && !item.certificateIssuer && !item.certificateStatus) {
    return null;
  }
  return {
    hosts: [host],
    host,
    certificateId: certificateId || undefined,
    certId: certificateId || undefined,
    certType: item.certificateMode || 'sslcert',
    status: item.certificateStatus || (item.certificateBound ? 'bound' : 'unknown'),
    issuer: item.certificateIssuer || null,
    signAlgo: item.certificateSignAlgo || null,
    effectiveTime: item.certificateEffectiveTime,
    expireTime: item.certificateExpireTime,
  };
}

function getBoundCertificateByHost(host?: string | null): BoundCertificateView | null {
  const normalized = normalizeDomainValue(String(host || ''));
  if (!normalized) return null;
  const edgeOneCert = certificates.value.find((item) => normalizeCertificateHosts(item).includes(normalized));
  const domainCert = createDomainBoundCertificate(
    domains.value.find((item) => normalizeDomainValue(item.domainName) === normalized) || null,
  );
  const current = edgeOneCert || domainCert;
  if (!current) return null;
  const sslCert = findManagedSslCertificateById(current.certId || current.certificateId);
  if (sslCert) {
    return buildBoundCertificateFromSsl(sslCert, normalized);
  }
  const sourceLabel = edgeOneCert
    ? 'EdgeOne 当前绑定，SSL 证书库未找到'
    : 'EdgeOne 域名信息返回，SSL 证书库未找到';
  return buildBoundCertificateFromEdgeOne(current, normalized, sourceLabel);
}

function describeBoundCertificate(host?: string | null): string {
  return describeCertificate(getBoundCertificateByHost(host), { includeHosts: false });
}

function describeBoundCertificateSource(host?: string | null): string {
  return String(getBoundCertificateByHost(host)?.sourceLabel || '').trim();
}

const managedSslCertificateChoices = computed(() =>
  sslManagedCertificates.value
    .filter((item) => ['issued', 'upload'].includes(String(item.status || '').toLowerCase()))
    .map((item) => ({
      cert: item,
      matched: !bindHosts.value.length || bindHosts.value.some((host) => certificateMatchesHost(item, host)),
    }))
    .sort((a, b) => {
      if (a.matched !== b.matched) return Number(b.matched) - Number(a.matched);
      return String(b.cert.notAfter || '').localeCompare(String(a.cert.notAfter || ''));
    }),
);
const managedSslCertificateOptions = computed(() =>
  managedSslCertificateChoices.value.map(({ cert, matched }) => ({
    label: `${cert.domain} · ${cert.remoteCertId}${matched ? ' · 匹配当前域名' : ''}${cert.issuer ? ` · ${cert.issuer}` : ''}${cert.notAfter ? ` · 到期 ${formatDateSafe(cert.notAfter)}` : ''}${cert.credentialName ? ` · ${cert.credentialName}` : ''}`,
    value: cert.remoteCertId,
  })),
);
const matchedManagedSslCertificateCount = computed(() =>
  managedSslCertificateChoices.value.filter((item) => item.matched).length,
);
const selectedManagedSslCertificate = computed(() => findManagedSslCertificateById(certBindForm.value.certId));
const selectedManagedSslPending = computed(() => {
  const status = String(selectedManagedSslCertificate.value?.status || '').toLowerCase();
  return !!selectedManagedSslCertificate.value && !['issued', 'upload'].includes(status);
});
const bindTargetHost = computed(() => bindHosts.value.length === 1 ? bindHosts.value[0] : '');
const sslCredentialOptions = computed(() =>
  sslCredentials.value.map((item) => ({
    label: `${item.name} · ${item.provider}`,
    value: item.id,
  })),
);
const currentBoundCertificates = computed(() => {
  const items: BoundCertificateView[] = [];
  const seen = new Set<string>();
  for (const host of bindHosts.value) {
    const cert = getBoundCertificateByHost(host);
    if (!cert) continue;
    const key = buildCertificateKey(cert);
    if (seen.has(key)) continue;
    seen.add(key);
    items.push(cert);
  }
  return items;
});
const isCurrentBindingAlreadyApplied = computed(() => {
  const selectedCertId = normalizeCertificateId(certBindForm.value.certId);
  if (!selectedCertId || !bindHosts.value.length) return false;
  return bindHosts.value.every((host) => {
    const cert = getBoundCertificateByHost(host);
    return normalizeCertificateId(String(cert?.certId || cert?.certificateId || '')) === selectedCertId;
  });
});
const canApplySslForBind = computed(() => !!bindTargetHost.value && !!bindSslCredentialId.value);
const bindSubmitLabel = computed(() => {
  if (isCurrentBindingAlreadyApplied.value) return '已绑定';
  if (selectedManagedSslPending.value) return '等待签发';
  return '提交绑定';
});
const canSubmitBind = computed(() => {
  if (isCurrentBindingAlreadyApplied.value) return false;
  if (!bindHosts.value.length || !certBindForm.value.certId.trim()) return false;
  if (selectedManagedSslPending.value) return false;
  return true;
});

function describeDnsCheck(check?: AccelerationDnsCheck): string {
  if (!check) return '';
  const publicResult = check.publicResolution;
  if (publicResult?.checked) {
    if (publicResult.isResolved) {
      return `公网解析已指向 ${publicResult.currentValue || check.expectedValue || '-'}`;
    }
    if (publicResult.currentValue) {
      return `公网当前指向 ${publicResult.currentValue}，期望 ${check.expectedValue || '-'}`;
    }
    if (publicResult.error) {
      return `公网解析检查异常：${publicResult.error}`;
    }
    return `公网尚未解析到期望 CNAME（期望 ${check.expectedValue || '-'}）`;
  }
  if (publicResult?.error) {
    return `公网解析检查失败：${publicResult.error}`;
  }
  return '';
}

function siteType(item: AccelerationSite): 'success' | 'warning' | 'error' | 'default' {
  if (item.paused) return 'warning';
  const status = String(item.status || '').toLowerCase();
  if (item.verified || status === 'active' || status === 'online') return 'success';
  if (status.includes('error') || status.includes('fail') || status.includes('offline')) return 'error';
  return 'default';
}

function resolveDomainUiState(item: AccelerationDomain): { tagType: 'success' | 'warning' | 'error' | 'default'; text: string } {
  const ui = String(item.uiState || '').toLowerCase();
  if (ui === 'paused' || item.paused) return { tagType: 'warning', text: '已暂停' };
  if (ui === 'active') return { tagType: 'success', text: '生效中' };
  if (ui === 'deploying') return { tagType: 'warning', text: '部署中' };
  if (ui === 'cname_pending') return { tagType: 'error', text: '异常请添加 CNAME' };
  if (ui === 'error') return { tagType: 'error', text: '异常' };
  const status = String(item.domainStatus || '').toLowerCase();
  if (status === 'active' || status === 'online') return { tagType: 'success', text: '生效中' };
  if (['pending', 'deploying', 'processing', 'configuring'].includes(status)) return { tagType: 'warning', text: '部署中' };
  if (!item.verified) return { tagType: 'error', text: '异常请添加 CNAME' };
  return { tagType: 'default', text: item.domainStatus || '未知' };
}

async function loadDnsCredentials() {
  loadingDnsCredentials.value = true;
  try {
    const res = await getDnsCredentials('dns');
    dnsCredentials.value = res.data?.credentials || [];
    if (dnsCredentialId.value && !dnsCredentials.value.some((item) => item.id === dnsCredentialId.value)) {
      dnsCredentialId.value = null;
    }
  } catch (err: any) {
    message.error(`加载 DNS 凭证失败：${asErrorText(err)}`);
  } finally {
    loadingDnsCredentials.value = false;
  }
}

async function loadSslCredentials() {
  loadingSslCredentials.value = true;
  try {
    const res = await getSslCredentials();
    sslCredentials.value = res.data || [];
    if (bindSslCredentialId.value && !sslCredentials.value.some((item) => item.id === bindSslCredentialId.value)) {
      bindSslCredentialId.value = null;
    }
    if (!bindSslCredentialId.value && sslCredentials.value.length === 1) {
      bindSslCredentialId.value = sslCredentials.value[0].id;
    }
  } catch (err: any) {
    sslCredentials.value = [];
    message.warning(`加载 SSL 账户失败：${asErrorText(err)}`);
  } finally {
    loadingSslCredentials.value = false;
  }
}

async function loadCredentials(keep = true, silent = false) {
  loadingCredentials.value = true;
  try {
    const res = await getDnsCredentials('acceleration');
    credentials.value = (res.data?.credentials || []).filter((item) => String(item.provider || '').toLowerCase() === provider);
    if (!credentials.value.length) {
      credentialId.value = null;
      sites.value = [];
      siteId.value = '';
      domains.value = [];
      certificates.value = [];
      return;
    }
    if (!keep || !credentials.value.some((item) => item.id === credentialId.value)) credentialId.value = credentials.value[0].id;
  } catch (err: any) {
    if (!silent) message.error(asErrorText(err));
    throw err;
  } finally {
    loadingCredentials.value = false;
  }
}

async function loadSites(prefer?: string, options: { silent?: boolean; skipLoadingFlag?: boolean } = {}) {
  if (!credentialId.value) {
    sites.value = [];
    siteId.value = '';
    domains.value = [];
    certificates.value = [];
    return;
  }
  const trackLoading = !options.skipLoadingFlag;
  if (trackLoading) loadingSites.value = true;
  try {
    const res = await listAccelerationSites({ credentialId: credentialId.value, provider });
    sites.value = res.data?.sites || [];
    const nextSiteId = (prefer && sites.value.some((item) => item.siteId === prefer)) ? prefer : (sites.value[0]?.siteId || '');
    const changed = nextSiteId !== siteId.value;
    siteId.value = nextSiteId;
    if (!siteId.value) {
      domains.value = [];
      certificates.value = [];
      return;
    }
    if (!changed) {
      await Promise.all([
        loadDomains({ silent: true, skipLoadingFlag: options.skipLoadingFlag }),
        loadCertificates({ silent: true, skipLoadingFlag: options.skipLoadingFlag }),
        loadManagedSslCertificates([], { silent: true }),
      ]);
    }
  } catch (err: any) {
    sites.value = [];
    siteId.value = '';
    domains.value = [];
    certificates.value = [];
    if (!options.silent) message.error(asErrorText(err));
    throw err;
  } finally {
    if (trackLoading) loadingSites.value = false;
  }
}

async function loadDomains(options: { silent?: boolean; skipLoadingFlag?: boolean } = {}) {
  if (!credentialId.value || !site.value?.siteId) { domains.value = []; return; }
  const trackLoading = !options.skipLoadingFlag;
  if (trackLoading) loadingDomains.value = true;
  try {
    const res = await listAccelerationDomains({ credentialId: credentialId.value, provider, siteId: site.value.siteId });
    domains.value = res.data?.domains || [];
  } catch (err: any) {
    domains.value = [];
    if (!options.silent) message.error(asErrorText(err));
    throw err;
  } finally {
    if (trackLoading) loadingDomains.value = false;
  }
}

async function loadCertificates(options: { silent?: boolean; skipLoadingFlag?: boolean } = {}) {
  if (!credentialId.value || !site.value?.siteId) { certificates.value = []; return; }
  const trackLoading = !options.skipLoadingFlag;
  if (trackLoading) loadingCertificates.value = true;
  try {
    const res = await listAccelerationCertificates({ credentialId: credentialId.value, provider, siteId: site.value.siteId });
    certificates.value = res.data?.certificates || res.data?.items || [];
  } catch (err: any) {
    certificates.value = [];
    if (!options.silent) message.error(asErrorText(err));
    throw err;
  } finally {
    if (trackLoading) loadingCertificates.value = false;
  }
}

async function loadManagedSslCertificates(preferredHosts: string[] = bindHosts.value, options: { silent?: boolean } = {}) {
  loadingSslManagedCertificates.value = true;
  try {
    const keywords = Array.from(new Set([
      normalizeDomainValue(preferredHosts[0] || ''),
      normalizeDomainValue(site.value?.zoneName || ''),
    ].filter(Boolean)));
    const merged = new Map<string, SslCertificate>();
    const load = async (search?: string) => {
      const res = await getSslCertificates('all', search ? { page: 1, limit: 100, search } : { page: 1, limit: 100 });
      for (const item of res.data || []) {
        if (item?.remoteCertId && !merged.has(item.remoteCertId)) {
          merged.set(item.remoteCertId, item);
        }
      }
    };
    if (!keywords.length) {
      await load();
    } else {
      for (const keyword of keywords) {
        await load(keyword);
      }
      if (!merged.size) {
        await load();
      }
    }
    sslManagedCertificates.value = Array.from(merged.values());
    if (showCertBindModal.value && !certBindForm.value.certId.trim()) {
      const preferred = sslManagedCertificates.value.find((item) =>
        ['issued', 'upload'].includes(String(item.status || '').toLowerCase())
        && (!preferredHosts.length || preferredHosts.some((host) => certificateMatchesHost(item, host))),
      );
      if (preferred?.remoteCertId) {
        certBindForm.value.certId = preferred.remoteCertId;
        if (!bindSslCredentialId.value && typeof preferred.credentialId === 'number') {
          bindSslCredentialId.value = preferred.credentialId;
        }
      }
    }
  } catch (err: any) {
    sslManagedCertificates.value = [];
    if (!options.silent) {
      message.warning(`加载 SSL 证书失败：${asErrorText(err)}`);
    }
  } finally {
    loadingSslManagedCertificates.value = false;
  }
}

async function refreshAll() {
  await Promise.all([
    loadCredentials(false, true),
    loadDnsCredentials(),
    loadSslCredentials(),
  ]);
  if (credentialId.value) {
    await loadSites(undefined, { silent: false });
  }
}

async function handleCredentialChanged() {
  await loadCredentials(false, true);
  await loadDnsCredentials();
  await loadSslCredentials();
  if (!credentialId.value) {
    connectionNotice.value = { type: 'info', text: '请先添加 EdgeOne 账户。' };
    return;
  }
  try {
    await loadSites(undefined, { silent: true });
    connectionNotice.value = { type: 'success', text: '账户已保存，且已成功连接 EdgeOne。' };
  } catch (err: any) {
    connectionNotice.value = { type: 'warning', text: `账户已保存，但连接 EdgeOne 失败：${asErrorText(err)}` };
    message.warning(connectionNotice.value.text);
  }
}

async function refreshVerification() {
  if (!credentialId.value || !site.value?.zoneName) return;
  refreshingVerification.value = true;
  try {
    const res = await identifyAccelerationSite({ credentialId: credentialId.value, provider, zoneName: site.value.zoneName });
    verification.value = res.data?.verification || null;
    verificationCode.value = verification.value?.verificationCode || '';
    message.success('验证信息已刷新');
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    refreshingVerification.value = false;
  }
}

async function autoVerifyDns() {
  if (!credentialId.value || !site.value?.zoneName) return;
  autoSiteDnsLoading.value = true;
  try {
    const res = await autoVerifyAccelerationSiteDns({
      credentialId: credentialId.value,
      provider,
      zoneName: site.value.zoneName,
      siteId: site.value.siteId,
      dnsCredentialId: dnsCredentialId.value || undefined,
      autoMatchDns: !dnsCredentialId.value,
      autoVerify: true,
    });
    verification.value = res.data?.verification || verification.value;
    verificationCode.value = verification.value?.verificationCode || verificationCode.value;
    await loadSites(site.value.siteId, { silent: true });
    const added = res.data?.dnsRecordsAdded?.length || 0;
    const skipped = res.data?.dnsRecordsSkipped?.length || 0;
    if (added > 0 || skipped > 0) {
      const parts = [];
      if (added > 0) parts.push(`新增 ${added} 条 TXT`);
      if (skipped > 0) parts.push(`跳过 ${skipped} 条已存在 TXT`);
      message.success(`${parts.join('，')}${res.data?.verifySubmitted ? '，并已提交归属验证' : ''}`);
    } else if (res.data?.dnsErrors?.length) {
      message.warning(res.data.dnsErrors.map((item) => item.error).join('；'));
    } else {
      message.info('当前没有可自动写入的验证记录');
    }
    if (res.data?.verifyError) {
      message.warning(`已写入 TXT，但自动验证失败：${res.data.verifyError}`);
    }
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    autoSiteDnsLoading.value = false;
  }
}

async function doVerify() {
  if (!credentialId.value || !site.value?.zoneName) return;
  verifying.value = true;
  try {
    await verifyAccelerationSite({
      credentialId: credentialId.value,
      provider,
      zoneName: site.value.zoneName,
      siteId: site.value.siteId,
      verificationCode: verificationCode.value.trim() || verification.value?.verificationCode || verification.value?.recordValue || undefined,
    });
    await loadSites(site.value.siteId, { silent: true });
    message.success('验证请求已提交');
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    verifying.value = false;
  }
}

function openCreateSite() {
  siteForm.value = { zoneName: '', area: 'global', type: 'partial', planId: '' };
  showSiteModal.value = true;
}

async function saveSite() {
  if (!credentialId.value) { message.error('请先选择 EdgeOne 账户'); return; }
  if (!siteForm.value.zoneName.trim()) { message.error('请输入站点域名'); return; }
  savingSite.value = true;
  try {
    const res = await createAccelerationSite({ credentialId: credentialId.value, provider, ...siteForm.value, zoneName: siteForm.value.zoneName.trim(), planId: siteForm.value.planId.trim() || undefined });
    const created: any = res.data?.site || {};
    verification.value = created.verification || null;
    verificationCode.value = created.verification?.verificationCode || '';
    showSiteModal.value = false;
    await loadSites(created.siteId || '');
    message.success('站点已创建');
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    savingSite.value = false;
  }
}

function openCreateDomain(item?: AccelerationDomain) {
  editingDomain.value = item?.domainName || null;
  domainForm.value = {
    subDomain: extractSubDomain(item?.domainName, site.value?.zoneName),
    originType: item?.originType || 'IP_DOMAIN',
    originValue: item?.originValue || '',
    backupOriginValue: item?.backupOriginValue || '',
    hostHeaderMode: item?.hostHeader && normalizeDomainValue(item.hostHeader) !== normalizeDomainValue(item.domainName || '')
      ? 'custom'
      : 'acceleration',
    customHostHeader: item?.hostHeader && normalizeDomainValue(item.hostHeader) !== normalizeDomainValue(item.domainName || '')
      ? item.hostHeader
      : '',
    originProtocol: item?.originProtocol || 'FOLLOW',
    httpOriginPort: item?.httpOriginPort || 80,
    httpsOriginPort: item?.httpsOriginPort || 443,
    ipv6Status: item?.ipv6Status || 'follow',
  };
  showDomainModal.value = true;
}

async function saveDomain() {
  if (!credentialId.value || !site.value?.siteId) { message.error('请先选择站点'); return; }
  const domainName = currentAccelerationDomain.value;
  const originValue = normalizeDomainValue(domainForm.value.originValue);
  const backupOriginValue = normalizeDomainValue(domainForm.value.backupOriginValue);
  const hostHeader = domainForm.value.hostHeaderMode === 'custom'
    ? normalizeDomainValue(domainForm.value.customHostHeader)
    : domainName;
  if (!domainName || !isValidDomain(domainName)) { message.error('请输入合法的加速域名'); return; }
  if (!originValue) { message.error('请输入回源地址'); return; }
  if (!isValidOriginTarget(originValue)) { message.error('请输入合法的 IP 或域名'); return; }
  if (backupOriginValue && !isValidOriginTarget(backupOriginValue)) { message.error('备用源站必须是合法的 IP 或域名'); return; }
  if (domainForm.value.hostHeaderMode === 'custom' && !hostHeader) { message.error('请输入回源 HOST 头'); return; }
  if (!hostHeader || !isValidHostHeaderValue(hostHeader)) { message.error('请输入合法的回源 HOST 头'); return; }
  savingDomain.value = true;
  try {
    const payload = {
      credentialId: credentialId.value,
      provider,
      siteId: site.value.siteId,
      ...domainForm.value,
      domainName,
      originValue,
      backupOriginValue: backupOriginValue || undefined,
      hostHeader,
      httpOriginPort: Number(domainForm.value.httpOriginPort || 80),
      httpsOriginPort: Number(domainForm.value.httpsOriginPort || 443),
      dnsCredentialId: dnsCredentialId.value || undefined,
      autoMatchDns: !dnsCredentialId.value,
    };
    const res = await finalizeAccelerationDomain(domainName, payload);
    const item = res.data?.domain;
    if (item?.verifyRecordName || item?.verifyRecordValue) {
      verification.value = {
        recordName: item.verifyRecordName,
        recordType: item.verifyRecordType,
        recordValue: item.verifyRecordValue,
        verificationCode: item.verificationCode,
      };
    }
    showDomainModal.value = false;
    await loadDomains({ silent: true, skipLoadingFlag: true });
    message.success(editingDomain.value ? '域名已更新' : '域名已创建');

    const cnameTarget = String(item?.cnameTarget || '').trim();
    nextStepData.value = {
      domain: item,
      dnsRecordsAdded: res.data?.dnsRecordsAdded || [],
      dnsConflicts: res.data?.dnsConflicts || [],
      dnsErrors: res.data?.dnsErrors || [],
      dnsCheck: res.data?.dnsCheck,
      hostRecord: domainName,
      cnameTarget,
      message: res.message || '',
    };
    showNextStepModal.value = true;
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    savingDomain.value = false;
  }
}

async function retryCnameFromNextStep() {
  const data = nextStepData.value;
  if (!data?.domain || !site.value?.siteId || !credentialId.value) return;
  nextStepLoading.value = true;
  try {
    const res = await autoConfigureAccelerationCname({
      credentialId: credentialId.value,
      provider,
      siteId: site.value.siteId,
      domainName: data.domain.domainName,
      dnsCredentialId: dnsCredentialId.value || undefined,
      autoMatchDns: !dnsCredentialId.value,
    });
    nextStepData.value = {
      ...data,
      dnsRecordsAdded: res.data?.dnsRecordsAdded || [],
      dnsConflicts: res.data?.dnsConflicts || [],
      dnsErrors: res.data?.dnsErrors || [],
      dnsCheck: res.data?.dnsCheck || data.dnsCheck,
      message: res.message || data.message,
    };
    await loadDomains({ silent: true, skipLoadingFlag: true });
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    nextStepLoading.value = false;
  }
}

async function autoConfigureCname(item: AccelerationDomain) {
  if (!credentialId.value || !site.value?.siteId) return;
  autoDomainDnsTarget.value = item.domainName;
  try {
    const res = await autoConfigureAccelerationCname({
      credentialId: credentialId.value,
      provider,
      siteId: site.value.siteId,
      domainName: item.domainName,
      dnsCredentialId: dnsCredentialId.value || undefined,
      autoMatchDns: !dnsCredentialId.value,
    });
    if (res.data?.dnsCheck) {
      dnsCheckMap.value = { ...dnsCheckMap.value, [item.domainName]: res.data.dnsCheck };
    }
    const added = res.data?.dnsRecordsAdded?.length || 0;
    if (added > 0) {
      message.success(`已自动处理 ${item.domainName} 的 CNAME 记录`);
    } else if (res.data?.dnsConflicts?.length) {
      message.warning(`检测到 ${res.data.dnsConflicts.length} 条 DNS 冲突，未自动写入`);
    } else if (res.data?.dnsErrors?.length) {
      message.warning(res.data.dnsErrors.map((entry) => entry.error).join('；'));
    } else {
      message.info('当前没有可自动写入的 CNAME 记录');
    }
    await loadDomains({ silent: true, skipLoadingFlag: true });
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    autoDomainDnsTarget.value = null;
  }
}

async function toggleSite(item: AccelerationSite) {
  if (!credentialId.value) return;
  const target = String(item.siteId || item.zoneId || '').trim();
  if (!target || siteActionTarget.value === target) return;
  siteActionTarget.value = target;
  siteActionType.value = 'toggle';
  try {
    await updateAccelerationSiteStatus({ credentialId: credentialId.value, provider, siteId: item.siteId, zoneName: item.zoneName, enabled: !!item.paused });
    await loadSites(item.siteId, { silent: true, skipLoadingFlag: true });
  } catch (err: any) { message.error(asErrorText(err)); }
  finally {
    if (siteActionTarget.value === target) {
      siteActionTarget.value = null;
      siteActionType.value = null;
    }
  }
}

async function toggleDomain(item: AccelerationDomain) {
  if (!credentialId.value || !site.value?.siteId) return;
  const target = String(item.domainName || '').trim();
  if (!target || domainActionTarget.value === target) return;
  domainActionTarget.value = target;
  domainActionType.value = 'toggle';
  try {
    await updateAccelerationDomainStatus(item.domainName, { credentialId: credentialId.value, provider, siteId: site.value.siteId, enabled: !!item.paused });
    await loadDomains({ silent: true, skipLoadingFlag: true });
  } catch (err: any) { message.error(asErrorText(err)); }
  finally {
    if (domainActionTarget.value === target) {
      domainActionTarget.value = null;
      domainActionType.value = null;
    }
  }
}

function removeSite(item: AccelerationSite) {
  if (!credentialId.value) return;
  dialog.warning({ title: '删除站点', content: `确定删除 ${item.zoneName || item.siteId} 吗？`, positiveText: '删除', negativeText: '取消', onPositiveClick: async () => {
    const target = String(item.siteId || item.zoneId || '').trim();
    if (!target || siteActionTarget.value === target) return;
    siteActionTarget.value = target;
    siteActionType.value = 'delete';
    try { await deleteAccelerationSite({ credentialId: credentialId.value!, provider, siteId: item.siteId, zoneName: item.zoneName }); await loadSites(undefined, { silent: true, skipLoadingFlag: true }); message.success('站点已删除'); } catch (err: any) { message.error(asErrorText(err)); }
    finally {
      if (siteActionTarget.value === target) {
        siteActionTarget.value = null;
        siteActionType.value = null;
      }
    }
  } });
}

function removeDomain(item: AccelerationDomain) {
  if (!credentialId.value || !site.value?.siteId) return;
  dialog.warning({ title: '删除域名', content: `确定删除 ${item.domainName} 吗？`, positiveText: '删除', negativeText: '取消', onPositiveClick: async () => {
    const target = String(item.domainName || '').trim();
    if (!target || domainActionTarget.value === target) return;
    domainActionTarget.value = target;
    domainActionType.value = 'delete';
    try { await deleteAccelerationDomain({ credentialId: credentialId.value!, provider, siteId: site.value!.siteId, domainName: item.domainName }); await loadDomains({ silent: true, skipLoadingFlag: true }); message.success('域名已删除'); } catch (err: any) { message.error(asErrorText(err)); }
    finally {
      if (domainActionTarget.value === target) {
        domainActionTarget.value = null;
        domainActionType.value = null;
      }
    }
  } });
}

async function inspect(item: AccelerationDomain) {
  if (!credentialId.value || !site.value?.siteId) return;
  const target = String(item.domainName || '').trim();
  if (!target || domainActionTarget.value === target) return;
  domainActionTarget.value = target;
  domainActionType.value = 'inspect';
  try {
    const res = await getAccelerationDomainStatus({
      credentialId: credentialId.value,
      provider,
      siteId: site.value.siteId,
      domainName: item.domainName,
      dnsCredentialId: dnsCredentialId.value || undefined,
      autoMatchDns: !dnsCredentialId.value,
    });
    statusMap.value = { ...statusMap.value, [item.domainName]: `${res.data?.status || 'unknown'}${res.data?.message ? ` · ${res.data?.message}` : ''}` };
    if (res.data?.dnsCheck) {
      dnsCheckMap.value = { ...dnsCheckMap.value, [item.domainName]: res.data.dnsCheck };
    }
  } catch (err: any) { message.error(asErrorText(err)); }
  finally {
    if (domainActionTarget.value === target) {
      domainActionTarget.value = null;
      domainActionType.value = null;
    }
  }
}

function openBindCertificate(item?: AccelerationCertificate | AccelerationDomain) {
  const isDomainTarget = !!(item && 'domainName' in item);
  const host = item && 'domainName' in item ? item.domainName : (item?.host || item?.hosts?.join(', '));
  const boundCertificate = isDomainTarget ? getBoundCertificateByHost(host) : null;
  certBindForm.value = {
    hosts: host || filteredDomains.value.map((domain) => domain.domainName).join(', '),
    certId: boundCertificate?.certId
      || boundCertificate?.certificateId
      || ('certificateId' in (item || {}) ? ((item as AccelerationCertificate).certificateId || (item as AccelerationCertificate).certId || '') : ''),
  };
  bindHostLocked.value = isDomainTarget && !!host;
  sslManagedCertificates.value = [];
  showCertBindModal.value = true;
  void Promise.all([
    loadSslCredentials(),
    loadManagedSslCertificates(parseList(certBindForm.value.hosts)),
  ]);
}

async function applySslForBind() {
  const host = bindTargetHost.value;
  if (!host) { message.error('请从单个加速域名进入后再申请证书'); return; }
  if (!bindSslCredentialId.value) { message.error('请选择 SSL 账户'); return; }
  applyingSslCertificate.value = true;
  try {
    const currentBound = getBoundCertificateByHost(host);
    const currentSslCertId = currentBound?.source === 'ssl'
      ? String(currentBound.certId || currentBound.certificateId || '').trim()
      : '';
    const res = await applySslCertificate({
      credentialId: bindSslCredentialId.value,
      domain: host,
      dvAuthMethod: 'DNS',
      dnsCredentialId: dnsCredentialId.value || undefined,
      autoDnsRecord: true,
      autoMatchDns: !dnsCredentialId.value,
      oldCertificateId: currentSslCertId || undefined,
    });
    const certId = String(res.data?.CertificateId || '').trim();
    if (certId) {
      certBindForm.value.certId = certId;
    }
    await loadManagedSslCertificates([host]);
    const added = Number(res.data?.dnsRecordsAdded?.length || 0);
    const failed = Number(res.data?.dnsErrors?.length || 0);
    if (failed > 0) {
      message.warning(`SSL 证书已申请：${certId || '-'}，自动解析成功 ${added} 条，失败 ${failed} 条；请到 SSL 证书页或稍后刷新后确认签发状态。`);
    } else {
      message.success(`SSL 证书已申请：${certId || '-'}，并已调用 SSL 接口自动解析；待证书签发后即可提交绑定。`);
    }
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    applyingSslCertificate.value = false;
  }
}

async function bindCertificate() {
  if (!credentialId.value || !site.value?.siteId) { message.error('请先选择站点'); return; }
  const hosts = parseList(certBindForm.value.hosts);
  if (!hosts.length) { message.error('请至少填写一个域名'); return; }
  if (!certBindForm.value.certId.trim()) { message.error('请选择或填写托管证书 ID'); return; }
  if (isCurrentBindingAlreadyApplied.value) { message.info('当前域名已绑定该证书'); return; }
  if (selectedManagedSslPending.value) { message.warning('当前 SSL 证书还未签发完成，请稍后刷新后再绑定'); return; }
  bindingCert.value = true;
  try {
    const res = await bindAccelerationCertificate({
      credentialId: credentialId.value,
      provider,
      siteId: site.value.siteId,
      hosts,
      certType: 'managed',
      certId: certBindForm.value.certId.trim(),
    });
    showCertBindModal.value = false;
    await Promise.all([
      loadDomains({ silent: true, skipLoadingFlag: true }),
      loadCertificates({ silent: true, skipLoadingFlag: true }),
    ]);
    const boundItems = res.data?.certificates || res.data?.items || [];
    const boundCert = boundItems.find((item) =>
      normalizeCertificateId(String(item.certId || item.certificateId || '')) === normalizeCertificateId(certBindForm.value.certId),
    ) || boundItems[0];
    const summary = describeCertificate(boundCert);
    message.success(summary ? `证书已绑定：${summary}` : '证书已绑定');
  } catch (err: any) {
    message.error(asErrorText(err));
  } finally {
    bindingCert.value = false;
  }
}

watch(credentialId, async (value, prev) => {
  if (value !== prev) {
    verification.value = null;
    verificationCode.value = '';
    connectionNotice.value = null;
    if (value) {
      try {
        await loadSites(undefined, { silent: true });
      } catch {
        // explicit flows surface the actual error
      }
    }
  }
});

watch(selectedManagedSslCertificate, (value) => {
  if (!value?.credentialId) return;
  if (!bindSslCredentialId.value || !sslCredentials.value.some((item) => item.id === bindSslCredentialId.value)) {
    bindSslCredentialId.value = value.credentialId;
  }
});

watch(siteId, async (value, prev) => {
  if (value && value !== prev) {
    verification.value = null;
    verificationCode.value = '';
    statusMap.value = {};
    dnsCheckMap.value = {};
    sslManagedCertificates.value = [];
    bindHostLocked.value = false;
    await Promise.all([
      loadDomains({ silent: true }),
      loadCertificates({ silent: true }),
      loadManagedSslCertificates([], { silent: true }),
    ]);
  }
  if (!value) {
    domains.value = [];
    certificates.value = [];
    statusMap.value = {};
    dnsCheckMap.value = {};
    sslManagedCertificates.value = [];
    bindHostLocked.value = false;
  }
});

onMounted(async () => {
  await Promise.all([
    loadCredentials(true, true),
    loadDnsCredentials(),
    loadSslCredentials(),
  ]);
  if (credentialId.value) {
    try {
      await loadSites(undefined, { silent: true });
    } catch (err: any) {
      connectionNotice.value = { type: 'warning', text: `当前 EdgeOne 凭证连接失败：${asErrorText(err)}` };
    }
  }
});
</script>

<template>
  <div class="space-y-6">
    <section class="bento-card p-6">
      <div class="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <div class="mb-2 inline-flex items-center gap-2 rounded-full bg-blue-50 px-3 py-1 text-xs font-medium text-blue-600">
            <ShieldCheck :size="14" /> Acceleration Plugin
          </div>
          <h1 class="text-2xl font-semibold text-slate-700">EdgeOne 加速插件</h1>
          <p class="mt-1 text-sm text-slate-500">支持站点、加速域名、自动 DNS 验证，以及通过 SSL 证书库进行真实证书申请与绑定。</p>
        </div>
        <div class="flex flex-col gap-3 xl:items-end">
          <div class="flex flex-col gap-3 lg:flex-row">
            <NSelect v-model:value="credentialId" :options="credentialOptions" :loading="loadingCredentials" placeholder="选择 EdgeOne 账户" class="min-w-[260px]" />
            <NSelect v-model:value="dnsCredentialId" clearable :options="dnsCredentialOptions" :loading="loadingDnsCredentials" placeholder="自动 DNS 账户（可选）" class="min-w-[260px]" />
            <NButton :loading="loadingCredentials || loadingDnsCredentials || loadingSslCredentials || loadingSites || loadingDomains || loadingCertificates" @click="refreshAll">
              <template #icon><RefreshCw :size="14" /></template>刷新
            </NButton>
          </div>
          <p class="text-xs text-slate-500">自动写入 DNS 当前支持 Cloudflare / DNSPod；不选择时会自动匹配已有 DNS 凭证。</p>
        </div>
      </div>
      <NAlert v-if="connectionNotice" class="mt-4" :type="connectionNotice.type" :bordered="false">{{ connectionNotice.text }}</NAlert>
      <NAlert v-else-if="!dnsCredentialOptions.length" class="mt-4" type="info" :bordered="false">未检测到可自动写 TXT / CNAME 的 Cloudflare / DNSPod 凭证，仍可继续手动模式。</NAlert>
    </section>

    <div class="grid gap-6 xl:grid-cols-[380px,1fr]">
      <div class="space-y-6">
        <div class="bento-card p-4">
          <DnsCredentialManagement embedded category="acceleration" title="EdgeOne 账户管理" description="添加、编辑、验证 EdgeOne SecretId / SecretKey 与默认 PlanId" @changed="handleCredentialChanged" />
        </div>

        <div class="bento-card p-4">
          <div class="mb-4 flex flex-col gap-3">
            <div class="flex items-center justify-between">
              <div><h3 class="text-base font-semibold text-slate-700">站点</h3><p class="text-xs text-slate-500">创建、选择并管理 EdgeOne 站点</p></div>
              <div class="flex gap-2">
                <NButton size="small" @click="loadSites(siteId, { silent: false })"><template #icon><RefreshCw :size="14" /></template></NButton>
                <NButton size="small" type="primary" :disabled="!credentialId" @click="openCreateSite"><template #icon><Plus :size="14" /></template>新增</NButton>
              </div>
            </div>
            <NInput v-model:value="siteKeyword" clearable placeholder="搜索站点 / ZoneId">
              <template #prefix><Search :size="14" /></template>
            </NInput>
          </div>
          <div v-if="loadingSites" class="flex justify-center py-8"><NSpin /></div>
          <NAlert v-else-if="!credentialId" type="info" :bordered="false">请先添加 EdgeOne 账户。</NAlert>
          <NEmpty v-else-if="filteredSites.length === 0" :description="siteKeyword ? '没有匹配的站点' : '暂无站点'" />
          <div v-else class="space-y-3">
            <button v-for="item in filteredSites" :key="item.siteId" type="button" class="w-full rounded-xl border p-4 text-left" :class="siteId === item.siteId ? 'border-blue-400 bg-blue-50/70' : 'border-panel-border bg-panel-bg'" @click="siteId = item.siteId">
              <div class="flex items-start justify-between gap-3">
                <div class="min-w-0">
                  <p class="truncate text-sm font-semibold text-slate-700">{{ item.zoneName || item.siteName || item.siteId }}</p>
                  <p class="mt-1 text-xs text-slate-500">{{ item.type || '-' }} · {{ item.area || '-' }} · {{ formatDateSafe(item.createdAt) }}</p>
                </div>
                <NTag :type="siteType(item)" :bordered="false">{{ item.paused ? '已暂停' : (item.status || 'unknown') }}</NTag>
              </div>
            </button>
          </div>
        </div>
      </div>

      <div class="space-y-6">
        <div class="bento-card p-4">
          <div class="mb-4 flex flex-wrap gap-2 justify-between">
            <div><h3 class="text-base font-semibold text-slate-700">站点验证</h3><p class="text-xs text-slate-500">获取 TXT 验证记录，支持自动写入 DNS 后提交验证</p></div>
            <div class="flex flex-wrap gap-2">
              <NButton size="small" :disabled="!site || refreshingVerification || isSiteActionBusy(site)" :loading="refreshingVerification" @click="refreshVerification"><template #icon><SearchCheck :size="14" /></template>获取验证信息</NButton>
              <NButton size="small" type="primary" :disabled="!site || isSiteActionBusy(site)" :loading="autoSiteDnsLoading" @click="autoVerifyDns"><template #icon><Wand2 :size="14" /></template>自动添加 TXT</NButton>
              <NButton size="small" type="primary" :disabled="!site || isSiteActionBusy(site)" :loading="verifying" @click="doVerify"><template #icon><ShieldCheck :size="14" /></template>验证</NButton>
              <NButton size="small" :disabled="!site || (isSiteActionBusy(site) && !isSiteActionLoading(site, 'toggle'))" :loading="site ? isSiteActionLoading(site, 'toggle') : false" @click="site && toggleSite(site)"><template #icon><component :is="site?.paused ? Play : Pause" :size="14" /></template>{{ site?.paused ? '启用站点' : '暂停站点' }}</NButton>
              <NButton size="small" type="error" :disabled="!site || (isSiteActionBusy(site) && !isSiteActionLoading(site, 'delete'))" :loading="site ? isSiteActionLoading(site, 'delete') : false" @click="site && removeSite(site)"><template #icon><Trash2 :size="14" /></template>删除站点</NButton>
            </div>
          </div>
          <NEmpty v-if="!site" description="请选择站点" />
          <template v-else>
            <div class="grid gap-3 md:grid-cols-4">
              <div class="rounded-xl border border-panel-border bg-panel-bg p-4"><p class="text-xs text-slate-400">站点域名</p><p class="mt-2 font-semibold text-slate-700">{{ site.zoneName || site.siteName }}</p></div>
              <div class="rounded-xl border border-panel-border bg-panel-bg p-4"><p class="text-xs text-slate-400">状态</p><div class="mt-2"><NTag :type="siteType(site)" :bordered="false">{{ site.status || 'unknown' }}</NTag></div></div>
              <div class="rounded-xl border border-panel-border bg-panel-bg p-4"><p class="text-xs text-slate-400">验证</p><div class="mt-2"><NTag :type="site.verified ? 'success' : 'warning'" :bordered="false">{{ site.verified ? '已验证' : (site.verifyStatus || '未验证') }}</NTag></div></div>
              <div class="rounded-xl border border-panel-border bg-panel-bg p-4"><p class="text-xs text-slate-400">站点 ID</p><p class="mt-2 break-all font-mono text-xs text-slate-600">{{ site.siteId }}</p></div>
            </div>
            <div class="mt-4 rounded-xl border border-panel-border bg-panel-bg p-4">
              <template v-if="verification?.recordName || verification?.recordValue">
                <div class="grid gap-3 md:grid-cols-3 text-sm">
                  <div><p class="text-xs text-slate-400">类型</p><p class="mt-1 font-mono">{{ verification?.recordType || 'TXT' }}</p></div>
                  <div><p class="text-xs text-slate-400">主机记录</p><p class="mt-1 break-all font-mono">{{ verification?.recordName }}</p></div>
                  <div><p class="text-xs text-slate-400">记录值</p><p class="mt-1 break-all font-mono">{{ verification?.recordValue }}</p></div>
                </div>
              </template>
              <NAlert v-else type="info" :bordered="false">点击“获取验证信息”查看需要添加的 TXT 记录，或直接用“自动添加 TXT”。</NAlert>
              <div class="mt-4"><p class="mb-1 text-xs text-slate-400">验证码（可留空，默认使用返回值）</p><NInput v-model:value="verificationCode" placeholder="VerifyOwnership 所需验证码" /></div>
            </div>
          </template>
        </div>

        <div class="bento-card p-4">
          <div class="mb-4 flex flex-col gap-3">
            <div class="flex flex-wrap gap-2 justify-between">
              <div><h3 class="text-base font-semibold text-slate-700">加速域名</h3><p class="text-xs text-slate-500">源站、CNAME、状态与自动 DNS 配置</p></div>
              <div class="flex flex-wrap gap-2">
                <NButton size="small" :disabled="!site" @click="loadDomains({ silent: false })"><template #icon><RefreshCw :size="14" /></template>刷新</NButton>
                <NButton size="small" type="primary" :disabled="!site" @click="openCreateDomain()"><template #icon><Plus :size="14" /></template>新增域名</NButton>
              </div>
            </div>
            <NInput v-model:value="domainKeyword" clearable placeholder="搜索域名 / 源站 / CNAME">
              <template #prefix><Search :size="14" /></template>
            </NInput>
          </div>
          <div v-if="loadingDomains" class="flex justify-center py-8"><NSpin /></div>
          <NEmpty v-else-if="!site" description="请选择站点后查看域名" />
          <NEmpty v-else-if="filteredDomains.length === 0" :description="domainKeyword ? '没有匹配的加速域名' : '暂无加速域名'" />
          <div v-else class="space-y-3">
            <div v-for="item in filteredDomains" :key="item.domainName" class="rounded-xl border border-panel-border bg-panel-bg p-4">
              <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <p class="truncate text-sm font-semibold text-slate-700">{{ item.domainName }}</p>
                    <NTag :type="resolveDomainUiState(item).tagType" :bordered="false">{{ resolveDomainUiState(item).text }}</NTag>
                    <NTag
                      :type="getBoundCertificateByHost(item.domainName) ? (getBoundCertificateByHost(item.domainName)?.missingInSsl ? 'warning' : 'success') : 'default'"
                      :bordered="false"
                      class="cursor-pointer"
                      @click="openBindCertificate(item)"
                    >
                      {{ getBoundCertificateByHost(item.domainName) ? (getBoundCertificateByHost(item.domainName)?.missingInSsl ? 'HTTPS 待同步' : 'HTTPS 已部署') : 'HTTPS 未配置' }}
                    </NTag>
                  </div>
                  <div class="mt-2 grid gap-2 text-xs text-slate-500 md:grid-cols-2 xl:grid-cols-4">
                    <div>源站：<span class="font-mono text-slate-700">{{ item.originValue || '-' }}</span></div>
                    <div>CNAME：<span class="font-mono text-slate-700">{{ item.cnameTarget || '-' }}</span></div>
                    <div>端口：<span class="font-mono text-slate-700">{{ item.httpOriginPort || 80 }}/{{ item.httpsOriginPort || 443 }}</span></div>
                    <div>创建：<span class="text-slate-700">{{ formatDateSafe(item.createdAt) }}</span></div>
                  </div>
                  <p v-if="describeBoundCertificate(item.domainName)" class="mt-2 text-xs text-emerald-600">证书：{{ describeBoundCertificate(item.domainName) }}</p>
                  <p v-if="describeBoundCertificateSource(item.domainName)" class="mt-1 text-xs text-slate-500">来源：{{ describeBoundCertificateSource(item.domainName) }}</p>
                  <p v-if="item.verifyRecordName || item.verifyRecordValue" class="mt-2 text-xs text-slate-500">验证记录：{{ item.verifyRecordType || 'TXT' }} · {{ item.verifyRecordName || '-' }} → {{ item.verifyRecordValue || '-' }}</p>
                  <p v-if="statusMap[item.domainName]" class="mt-2 text-xs text-slate-500">{{ statusMap[item.domainName] }}</p>
                  <p v-if="describeDnsCheck(dnsCheckMap[item.domainName])" class="mt-1 text-xs text-slate-500">{{ describeDnsCheck(dnsCheckMap[item.domainName]) }}</p>
                  <p v-if="dnsCheckMap[item.domainName]?.configured" class="mt-1 text-xs text-emerald-600">DNS 平台记录已存在：{{ dnsCheckMap[item.domainName]?.currentValue || dnsCheckMap[item.domainName]?.expectedValue || '-' }}</p>
                  <p v-if="dnsCheckMap[item.domainName]?.conflicts?.length" class="mt-1 text-xs text-amber-600">检测到 {{ dnsCheckMap[item.domainName]?.conflicts?.length }} 条 DNS 冲突：{{ dnsCheckMap[item.domainName]?.conflicts?.[0]?.reason }}</p>
                  <p v-if="dnsCheckMap[item.domainName]?.errors?.length" class="mt-1 text-xs text-slate-500">{{ dnsCheckMap[item.domainName]?.errors?.[0]?.error }}</p>
                </div>
                <div class="flex flex-wrap gap-2">
                  <NButton size="small" :loading="autoDomainDnsTarget === item.domainName" :disabled="isDomainActionBusy(item)" @click="autoConfigureCname(item)"><template #icon><Link2 :size="14" /></template>自动 CNAME</NButton>
                  <NButton size="small" :loading="isDomainActionLoading(item, 'inspect')" :disabled="isDomainActionBusy(item) && !isDomainActionLoading(item, 'inspect')" @click="inspect(item)">查状态</NButton>
                  <NButton size="small" :disabled="isDomainActionBusy(item)" @click="openBindCertificate(item)">绑证书</NButton>
                  <NButton size="small" :disabled="isDomainActionBusy(item)" @click="openCreateDomain(item)">编辑</NButton>
                  <NButton size="small" :loading="isDomainActionLoading(item, 'toggle')" :disabled="isDomainActionBusy(item) && !isDomainActionLoading(item, 'toggle')" @click="toggleDomain(item)"><template #icon><component :is="item.paused ? Play : Pause" :size="14" /></template>{{ item.paused ? '启用' : '暂停' }}</NButton>
                  <NButton size="small" type="error" :loading="isDomainActionLoading(item, 'delete')" :disabled="isDomainActionBusy(item) && !isDomainActionLoading(item, 'delete')" @click="removeDomain(item)"><template #icon><Trash2 :size="14" /></template>删除</NButton>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <NModal :show="showSiteModal" preset="card" title="创建站点" :style="{ width: '560px' }" @update:show="(v: boolean) => { showSiteModal = v; }">
      <div class="space-y-4">
        <div><label class="mb-1 block text-sm text-slate-500">站点域名</label><NInput v-model:value="siteForm.zoneName" placeholder="example.com" /></div>
        <div class="grid gap-4 md:grid-cols-2">
          <div><label class="mb-1 block text-sm text-slate-500">接入方式</label><NSelect v-model:value="siteForm.type" :options="[{ label: 'partial', value: 'partial' }, { label: 'full', value: 'full' }]" /></div>
          <div><label class="mb-1 block text-sm text-slate-500">区域</label><NSelect v-model:value="siteForm.area" :options="[{ label: 'global', value: 'global' }, { label: 'china', value: 'china' }]" /></div>
        </div>
        <div><label class="mb-1 block text-sm text-slate-500">套餐 ID（可选）</label><NInput v-model:value="siteForm.planId" placeholder="plan-xxxxxx" /></div>
        <div class="flex justify-end gap-3"><NButton @click="showSiteModal = false">取消</NButton><NButton type="primary" :loading="savingSite" @click="saveSite">创建</NButton></div>
      </div>
    </NModal>

    <NModal :show="showDomainModal" preset="card" :title="editingDomain ? '编辑域名' : '新增域名'" :style="{ width: '680px' }" @update:show="(v: boolean) => { showDomainModal = v; }">
      <div class="space-y-4">
        <div class="grid gap-4 md:grid-cols-[1fr,220px]">
          <div>
            <label class="mb-1 block text-sm text-slate-500">加速域名</label>
            <NInput v-model:value="domainForm.subDomain" :disabled="!!editingDomain" placeholder="www / api / @ / 完整域名" />
          </div>
          <div>
            <label class="mb-1 block text-sm text-slate-500">站点后缀</label>
            <div class="rounded-xl border border-panel-border bg-panel-bg px-3 py-2 text-sm text-slate-700">{{ site?.zoneName ? `.${site.zoneName}` : '-' }}</div>
          </div>
        </div>
        <p class="text-xs text-slate-500">完整域名：<span class="font-mono text-slate-700">{{ currentAccelerationDomain || '-' }}</span>。留空或输入 <span class="font-mono">@</span> 表示根域名；输入包含 <span class="font-mono">.</span> 时按完整域名处理。</p>
        <div class="grid gap-4 md:grid-cols-2">
          <div><label class="mb-1 block text-sm text-slate-500">源站类型</label><NSelect v-model:value="domainForm.originType" :options="[{ label: 'IP_DOMAIN', value: 'IP_DOMAIN' }, { label: 'COS', value: 'COS' }, { label: 'AWS_S3', value: 'AWS_S3' }]" /></div>
          <div><label class="mb-1 block text-sm text-slate-500">回源配置</label><NInput v-model:value="domainForm.originValue" placeholder="请输入合法的 IP 或域名" /></div>
        </div>
        <div class="grid gap-4 md:grid-cols-2">
          <div><label class="mb-1 block text-sm text-slate-500">备用源站</label><NInput v-model:value="domainForm.backupOriginValue" placeholder="可选，备用 IP 或域名" /></div>
          <div><label class="mb-1 block text-sm text-slate-500">IPv6 访问</label><NSelect v-model:value="domainForm.ipv6Status" :options="[{ label: '遵循站点配置', value: 'follow' }, { label: '关闭', value: 'close' }]" /></div>
        </div>
        <div class="grid gap-4 md:grid-cols-3">
          <div><label class="mb-1 block text-sm text-slate-500">回源协议</label><NSelect v-model:value="domainForm.originProtocol" :options="[{ label: '协议跟随', value: 'FOLLOW' }, { label: 'HTTP', value: 'HTTP' }, { label: 'HTTPS', value: 'HTTPS' }]" /></div>
          <div>
            <label class="mb-1 block text-sm text-slate-500">HTTP</label>
            <NInputNumber
              :value="domainForm.httpOriginPort"
              :min="1"
              :max="65535"
              :show-button="false"
              @update:value="(value: number | null) => { domainForm.httpOriginPort = value || 80; }"
            />
          </div>
          <div>
            <label class="mb-1 block text-sm text-slate-500">HTTPS</label>
            <NInputNumber
              :value="domainForm.httpsOriginPort"
              :min="1"
              :max="65535"
              :show-button="false"
              @update:value="(value: number | null) => { domainForm.httpsOriginPort = value || 443; }"
            />
          </div>
        </div>
        <div class="grid gap-4 md:grid-cols-[220px,1fr]">
          <div><label class="mb-1 block text-sm text-slate-500">回源 HOST 头</label><NSelect v-model:value="domainForm.hostHeaderMode" :options="[{ label: '使用加速域名', value: 'acceleration' }, { label: '自定义', value: 'custom' }]" /></div>
          <div><label class="mb-1 block text-sm text-slate-500">当前 HOST 头</label><div class="rounded-xl border border-panel-border bg-panel-bg px-3 py-2 text-sm text-slate-700">{{ currentHostHeader || '-' }}</div></div>
        </div>
        <div v-if="domainForm.hostHeaderMode === 'custom'"><label class="mb-1 block text-sm text-slate-500">自定义 HOST 头</label><NInput v-model:value="domainForm.customHostHeader" placeholder="origin.example.com" /></div>
        <NAlert type="info" :bordered="false">创建成功后会展示 EdgeOne 返回的 CNAME，可直接用“自动 CNAME”写入到已配置的 Cloudflare / DNSPod。</NAlert>
        <div class="flex justify-end gap-3"><NButton @click="showDomainModal = false">取消</NButton><NButton type="primary" :loading="savingDomain" @click="saveDomain">{{ editingDomain ? '保存' : '创建' }}</NButton></div>
      </div>
    </NModal>

    <NModal :show="showCertBindModal" preset="card" title="绑定证书" :style="{ width: '820px' }" @update:show="(v: boolean) => { showCertBindModal = v; }">
      <div class="space-y-4">
        <div>
          <label class="mb-1 block text-sm text-slate-500">绑定域名</label>
          <NInput v-model:value="certBindForm.hosts" :disabled="bindHostLocked" placeholder="www.example.com, api.example.com" />
          <p v-if="bindHostLocked" class="mt-1 text-xs text-slate-500">当前从单个加速域名进入，绑定域名已锁定。</p>
        </div>
        <NAlert v-if="currentBoundCertificates.length" :type="currentBoundCertificates.some((item) => item.missingInSsl) ? 'warning' : 'success'" :bordered="false">
          <div class="space-y-1 text-sm">
            <p v-for="item in currentBoundCertificates" :key="buildCertificateKey(item)">
              已绑定：{{ describeCertificate(item, { includeHosts: true }) }} · 来源：{{ item.sourceLabel }}
            </p>
          </div>
        </NAlert>
        <div class="grid gap-4 md:grid-cols-2">
          <div class="space-y-3 rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
            <div class="flex items-start justify-between gap-3">
              <div>
                <label class="block text-sm text-slate-500">SSL 账户</label>
                <p class="mt-1 text-xs text-slate-500">申请动作直接调用 SSL 证书页的真实接口，不再走 EdgeOne 自己的申请逻辑。</p>
              </div>
              <NButton size="small" secondary :loading="loadingSslCredentials" @click="loadSslCredentials">刷新账户</NButton>
            </div>
            <NSelect
              v-model:value="bindSslCredentialId"
              :options="sslCredentialOptions"
              :loading="loadingSslCredentials"
              clearable
              placeholder="选择用于申请证书的 SSL 账户"
            />
            <div class="flex justify-end">
              <NButton size="small" type="primary" secondary :loading="applyingSslCertificate" :disabled="!canApplySslForBind" @click="applySslForBind">申请并自动解析</NButton>
            </div>
          </div>
          <div class="space-y-3 rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
            <div class="flex items-start justify-between gap-3">
              <div>
                <label class="block text-sm text-slate-500">从 SSL 证书列表选择</label>
                <p class="mt-1 text-xs text-slate-500">当前匹配到 {{ matchedManagedSslCertificateCount }} 张证书；未命中时可直接手动填写 CertId。</p>
              </div>
              <NButton size="small" secondary :loading="loadingSslManagedCertificates" @click="loadManagedSslCertificates()">刷新匹配</NButton>
            </div>
            <NSelect
              :value="certBindForm.certId || null"
              :options="managedSslCertificateOptions"
              :loading="loadingSslManagedCertificates"
              clearable
              filterable
              placeholder="优先显示与当前绑定域名匹配的 SSL 证书"
              @update:value="(value: string | null) => { certBindForm.certId = String(value || ''); }"
            />
          </div>
        </div>
        <NAlert v-if="!bindTargetHost" type="info" :bordered="false">申请 SSL 证书仅支持单个加速域名，请从具体域名的“绑证书”进入。</NAlert>
        <NAlert v-else-if="!sslCredentialOptions.length" type="warning" :bordered="false">当前没有可用的 SSL 账户，无法在这里发起真实证书申请；你仍可手动填写已有 CertId 进行绑定。</NAlert>
        <NAlert v-if="selectedManagedSslCertificate" :type="selectedManagedSslPending ? 'warning' : 'success'" :bordered="false">
          当前证书：{{ selectedManagedSslCertificate.domain }} · {{ selectedManagedSslCertificate.remoteCertId }} · {{ selectedManagedSslCertificate.issuer || '-' }} · 状态 {{ selectedManagedSslCertificate.status }} · 到期 {{ formatDateSafe(selectedManagedSslCertificate.notAfter) }}
        </NAlert>
        <NAlert v-else-if="certBindForm.certId.trim() && !loadingSslManagedCertificates" type="warning" :bordered="false">当前 CertId 未在 SSL 证书库中找到。若加速域名显示已绑证书但这里找不到，说明它来自 EdgeOne 当前绑定信息，不是本系统 SSL 证书页里的真实证书记录。</NAlert>
        <div class="rounded-2xl border border-slate-200 p-4">
          <label class="mb-1 block text-sm text-slate-500">托管证书 ID</label>
          <NInput v-model:value="certBindForm.certId" placeholder="cert-xxxxxx" />
          <p class="mt-1 text-xs text-slate-500">当上面的 SSL 列表没有命中时，可以在这里直接填写已有的真实 CertId。</p>
        </div>
        <NAlert type="info" :bordered="false">这里的申请会直接复用 SSL 证书功能并尝试自动解析；证书状态变为已签发后，再把真实 CertId 绑定到 EdgeOne。</NAlert>
        <div class="flex justify-end gap-3"><NButton @click="showCertBindModal = false">取消</NButton><NButton type="primary" :loading="bindingCert" :disabled="!canSubmitBind" @click="bindCertificate">{{ bindSubmitLabel }}</NButton></div>
      </div>
    </NModal>

    <NModal :show="showNextStepModal" preset="card" title="下一步：验证 CNAME 记录" :style="{ width: '640px' }" @update:show="(v: boolean) => { showNextStepModal = v; }">
      <div v-if="nextStepData" class="space-y-4">
        <div class="grid grid-cols-3 gap-3">
          <div class="rounded-xl border border-panel-border bg-panel-bg p-4">
            <p class="text-xs text-slate-400">主机记录</p>
            <p class="mt-2 break-all font-mono text-sm text-slate-700">{{ nextStepData.hostRecord || '-' }}</p>
          </div>
          <div class="rounded-xl border border-panel-border bg-panel-bg p-4">
            <p class="text-xs text-slate-400">记录类型</p>
            <p class="mt-2 font-mono text-sm text-slate-700">CNAME</p>
          </div>
          <div class="rounded-xl border border-panel-border bg-panel-bg p-4">
            <p class="text-xs text-slate-400">记录值</p>
            <p class="mt-2 break-all font-mono text-sm text-slate-700">{{ nextStepData.cnameTarget || '等待 EdgeOne 分配' }}</p>
          </div>
        </div>
        <NAlert v-if="nextStepData.dnsRecordsAdded.length > 0" type="success" :bordered="false">
          已自动添加 CNAME（{{ nextStepData.dnsRecordsAdded[0].provider || '-' }} / {{ nextStepData.dnsRecordsAdded[0].zone || '-' }}）。{{ nextStepData.dnsRecordsAdded[0].existing ? '原记录已存在，无需重写。' : '新记录已下发。' }}
        </NAlert>
        <NAlert v-else-if="nextStepData.dnsConflicts.length > 0" type="warning" :bordered="false">
          检测到 {{ nextStepData.dnsConflicts.length }} 条 DNS 冲突（{{ nextStepData.dnsConflicts[0]?.reason || '-' }}），未自动写入，请手动处理后再重试。
        </NAlert>
        <NAlert v-else-if="nextStepData.dnsErrors.length > 0" type="error" :bordered="false">
          自动写入失败：{{ nextStepData.dnsErrors.map((item) => item.error).join('；') }}
        </NAlert>
        <NAlert v-else-if="nextStepData.dnsCheck?.configured" type="success" :bordered="false">
          DNS 已指向 {{ nextStepData.dnsCheck?.currentValue || nextStepData.cnameTarget || '-' }}。
        </NAlert>
        <NAlert v-else type="info" :bordered="false">
          未自动写入 CNAME。{{ nextStepData.message || '请手动添加或点下方"手动添加 CNAME"重试。' }}
        </NAlert>
        <NAlert v-if="verification?.recordName || verification?.recordValue" type="warning" :bordered="false">
          站点仍有未完成的归属验证：{{ verification?.recordType || 'TXT' }} · {{ verification?.recordName || '-' }} → {{ verification?.recordValue || '-' }}
        </NAlert>
        <div class="flex justify-end gap-3">
          <NButton @click="showNextStepModal = false">关闭</NButton>
          <NButton
            v-if="!nextStepData.dnsCheck?.configured"
            type="primary"
            :loading="nextStepLoading"
            @click="retryCnameFromNextStep"
          >手动添加 CNAME</NButton>
        </div>
      </div>
    </NModal>
  </div>
</template>
