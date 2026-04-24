<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NModal, NFormItem, NInput, NInputNumber, NSelect, NSwitch, NCheckbox, NButton, NCollapse, NCollapseItem, NTag, NAlert, useMessage } from 'naive-ui';
import { useProviderStore } from '@/stores/provider';
import { validateDNSContent, isValidDomain, isValidIPv4, isValidIPv6 } from '@/utils/validators';
import { TTL_OPTIONS, DNS_RECORD_TYPES } from '@/utils/constants';
import type { DnsLine } from '@/types/dns';
import type { DNSRecord, DNSRecordAcceleration } from '@/types';
import { getAccelerationDomainStatus, listAccelerationCertificates, createAccelerationCertificate, bindAccelerationCertificate, type AccelerationDomain, type AccelerationCertificate } from '@/services/accelerations';
import { getSslCertificates } from '@/services/ssl';

type OriginFormData = {
  originType: string;
  originValue: string;
  backupOriginValue: string;
  hostHeaderMode: 'acceleration' | 'custom';
  customHostHeader: string;
  originProtocol: string;
  httpOriginPort: number;
  httpsOriginPort: number;
  ipv6Status: string;
};

type RestoreFormData = {
  type: string;
  value: string;
  ttl?: number;
};

type AccelerationSubmitPayload = {
  enabled: boolean;
  origin?: OriginFormData;
  restoreRecord?: RestoreFormData;
};

type SubmitPayload = {
  recordId?: string;
  type: string;
  name: string;
  content: string;
  ttl?: number;
  proxied?: boolean;
  priority?: number;
  weight?: number;
  line?: string;
  remark?: string;
  acceleration?: AccelerationSubmitPayload;
  dnsChanged?: boolean;
};

const props = defineProps<{
  show: boolean;
  mode?: 'create' | 'edit';
  initialRecord?: DNSRecord | null;
  lines?: DnsLine[];
  minTtl?: number;
  loading?: boolean;
  zoneId?: string;
  zoneName?: string;
  accelerationState?: DNSRecordAcceleration | null;
  defaultOpenAcceleration?: boolean;
  needsRestoreInput?: boolean;
}>();

const emit = defineEmits<{
  'update:show': [val: boolean];
  submit: [params: SubmitPayload];
}>();

const providerStore = useProviderStore();
const message = useMessage();
const caps = computed(() => providerStore.currentCapabilities);
const isCloudflare = computed(() => providerStore.selectedProvider === 'cloudflare');

const mode = computed(() => props.mode || 'create');
const isEdit = computed(() => mode.value === 'edit');

function buildDefaultForm() {
  return {
    type: 'A',
    name: '',
    content: '',
    ttl: 1,
    proxied: false,
    priority: 10,
    weight: 0,
    line: '',
    remark: '',
  };
}

function buildDefaultOriginForm(name: string, content: string): OriginFormData {
  const fullDomain = resolveFullDomainLocal(name);
  const originType = detectOriginType(content);
  return {
    originType,
    originValue: content || '',
    backupOriginValue: '',
    hostHeaderMode: 'custom',
    customHostHeader: fullDomain || '',
    originProtocol: 'FOLLOW',
    httpOriginPort: 80,
    httpsOriginPort: 443,
    ipv6Status: 'follow',
  };
}

function detectOriginType(value: string): string {
  if (!value) return 'IP_DOMAIN';
  const trimmed = value.trim().toLowerCase();
  if (trimmed.endsWith('.myqcloud.com') || trimmed.endsWith('.cos.') || trimmed.includes('.cos.')) return 'COS';
  if (trimmed.endsWith('.amazonaws.com') || trimmed.includes('.s3.')) return 'AWS_S3';
  return 'IP_DOMAIN';
}

function resolveFullDomainLocal(name: string): string {
  const normalized = normalizeHost(name);
  const zone = normalizeHost(props.zoneName || '');
  if (!normalized || normalized === '@') return zone;
  if (!zone) return normalized;
  if (normalized === zone || normalized.endsWith(`.${zone}`)) return normalized;
  if (!normalized.includes('.')) return `${normalized}.${zone}`;
  return normalized;
}

function buildDefaultRestoreForm(): RestoreFormData {
  return { type: 'A', value: '', ttl: 600 };
}

const form = ref(buildDefaultForm());
const validationError = ref('');
const activeCollapseNames = ref<string[]>([]);
const accelerationEnabled = ref(false);
const accelerationTouched = ref(false);
const originForm = ref<OriginFormData>(buildDefaultOriginForm('', ''));
const originTouched = ref(false);
const restoreForm = ref<RestoreFormData>(buildDefaultRestoreForm());

const accelerationStatusLoading = ref(false);
const accelerationDomainStatus = ref<AccelerationDomain | null>(null);
const accelerationCnameTarget = ref<string>('');
const httpsConfiguring = ref(false);
const httpsCertStatus = ref<'unconfigured' | 'deploying' | 'deployed' | 'error'>('unconfigured');
const httpsExistingCerts = ref<AccelerationCertificate[]>([]);
const httpsSslMatched = ref<any[]>([]);
const httpsApplying = ref(false);

function normalizeHost(value?: string | null) {
  return String(value || '').trim().replace(/\.+$/, '').toLowerCase();
}

function resolveFullDomain(name: string): string {
  const normalized = normalizeHost(name);
  const zone = normalizeHost(props.zoneName || '');
  if (!normalized || normalized === '@') return zone;
  if (!zone) return normalized;
  if (normalized === zone || normalized.endsWith(`.${zone}`)) return normalized;
  if (!normalized.includes('.')) return `${normalized}.${zone}`;
  return normalized;
}

function readyAccelerationForInit() {
  const snapshot = props.accelerationState?.originalRecord || null;
  const current = props.initialRecord;
  const originSeed = snapshot?.value || current?.content || '';
  originForm.value = buildDefaultOriginForm(current?.name || '', originSeed);
  restoreForm.value = {
    type: snapshot?.type || 'A',
    value: snapshot?.value || '',
    ttl: snapshot?.ttl || 600,
  };
  accelerationEnabled.value = !!props.accelerationState?.enabled;
  accelerationTouched.value = false;
  originTouched.value = false;
}

watch(() => props.show, (open) => {
  if (!open) return;
  validationError.value = '';
  if (isEdit.value && props.initialRecord) {
    const r = props.initialRecord;
    form.value = {
      type: String(r.type || 'A'),
      name: String(r.name || ''),
      content: String(r.content || ''),
      ttl: Number(r.ttl || 1),
      proxied: !!r.proxied,
      priority: Number(r.priority || 10),
      weight: Number(r.weight || 0),
      line: String(r.line || ''),
      remark: String(r.remark || ''),
    };
  } else {
    form.value = buildDefaultForm();
  }
  readyAccelerationForInit();
  const forcedOpen = !!props.defaultOpenAcceleration || !!props.needsRestoreInput;
  activeCollapseNames.value = forcedOpen ? ['acceleration'] : [];
}, { immediate: true });

watch(() => props.accelerationState, () => {
  if (!props.show) return;
  if (accelerationTouched.value) return;
  readyAccelerationForInit();
});

watch(() => props.needsRestoreInput, (value) => {
  if (!value) return;
  accelerationEnabled.value = false;
  accelerationTouched.value = true;
  if (!activeCollapseNames.value.includes('acceleration')) {
    activeCollapseNames.value = [...activeCollapseNames.value, 'acceleration'];
  }
});

watch(() => form.value.content, (content) => {
  if (!accelerationEnabled.value) return;
  if (originTouched.value) return;
  originForm.value.originValue = content || '';
});

const recordTypeOptions = computed(() => {
  const types = caps.value?.recordTypes || [...DNS_RECORD_TYPES];
  let allTypes = [...types];
  if (caps.value?.supportsUrlForward) {
    allTypes = [...allTypes, 'REDIRECT_URL', 'FORWARD_URL'];
  }
  return [...new Set(allTypes)].map((t) => ({ label: t, value: t }));
});

const ttlOptions = computed(() => {
  const min = props.minTtl || 1;
  return TTL_OPTIONS.filter((o) => o.value >= min || o.value === 1).map((o) => ({ label: o.label, value: o.value }));
});

const lineOptions = computed(() => (props.lines || []).map((l) => ({ label: l.name, value: l.code })));
const showPriority = computed(() => ['MX', 'SRV'].includes(form.value.type));
const typeCanAccelerate = computed(() => ['A', 'AAAA', 'CNAME'].includes(form.value.type));
const nameIsZoneApex = computed(() => {
  const n = normalizeHost(form.value.name);
  const z = normalizeHost(props.zoneName);
  return !n || n === '@' || n === z;
});
const canAccelerate = computed(() => typeCanAccelerate.value && !nameIsZoneApex.value);
const hasOriginalSnapshot = computed(() => {
  const snapshot = props.accelerationState?.originalRecord;
  if (!snapshot) return false;
  return !!(snapshot.type && snapshot.value);
});
const needsRestoreForm = computed(() =>
  canAccelerate.value
  && !accelerationEnabled.value
  && (!!props.accelerationState?.enabled || !!props.needsRestoreInput)
  && !hasOriginalSnapshot.value
);

const currentFullDomain = computed(() => resolveFullDomain(form.value.name));
const currentHostHeader = computed(() =>
  originForm.value.hostHeaderMode === 'custom'
    ? normalizeHost(originForm.value.customHostHeader)
    : currentFullDomain.value
);

const accelerationStatusLabel = computed(() => {
  const ui = props.accelerationState?.uiState;
  if (ui === 'active') return { text: '生效中', type: 'success' as const };
  if (ui === 'deploying') return { text: '部署中', type: 'warning' as const };
  if (ui === 'cname_pending') return { text: '异常请添加 CNAME', type: 'error' as const };
  if (ui === 'paused') return { text: '已暂停', type: 'warning' as const };
  if (ui === 'error') return { text: '异常', type: 'error' as const };
  if (props.accelerationState?.enabled) return { text: '已加速', type: 'success' as const };
  return { text: '未加速', type: 'default' as const };
});

function isValidOriginTarget(value: string) {
  const v = normalizeHost(value);
  return !!v && (isValidIPv4(v) || isValidIPv6(v) || isValidDomain(v));
}

function dnsFieldsDirty(): boolean {
  if (!isEdit.value) return true;
  const r = props.initialRecord;
  if (!r) return true;
  return (
    form.value.type !== r.type
    || String(form.value.name) !== String(r.name || '')
    || String(form.value.content) !== String(r.content || '')
    || Number(form.value.ttl) !== Number(r.ttl || 0)
    || !!form.value.proxied !== !!r.proxied
    || Number(form.value.priority || 0) !== Number(r.priority || 0)
    || Number(form.value.weight || 0) !== Number(r.weight || 0)
    || String(form.value.line || '') !== String(r.line || '')
    || String(form.value.remark || '') !== String(r.remark || '')
  );
}

function accelerationPayload(): AccelerationSubmitPayload | undefined {
  if (!canAccelerate.value) return undefined;
  const wasEnabled = !!props.accelerationState?.enabled;
  const originDirty = accelerationEnabled.value && originTouched.value;
  if (!accelerationTouched.value && !originDirty) return undefined;
  if (accelerationEnabled.value === wasEnabled && !originDirty) return undefined;
  if (accelerationEnabled.value) {
    return {
      enabled: true,
      origin: originDirty ? { ...originForm.value } : undefined,
    };
  }
  if (needsRestoreForm.value) {
    return {
      enabled: false,
      restoreRecord: { ...restoreForm.value },
    };
  }
  return { enabled: false };
}

function handleSubmit() {
  validationError.value = '';
  if (!form.value.name.trim()) { validationError.value = '请输入记录名称'; return; }
  if (!form.value.content.trim()) { validationError.value = '请输入记录值'; return; }
  const contentErr = validateDNSContent(form.value.type, form.value.content);
  if (contentErr) { validationError.value = contentErr; return; }

  const acceleration = accelerationPayload();
  if (acceleration?.enabled) {
    if (!acceleration.origin?.originValue || !isValidOriginTarget(acceleration.origin.originValue)) {
      validationError.value = '请填写合法的回源 IP 或域名';
      return;
    }
    const hostHeader = acceleration.origin.hostHeaderMode === 'custom'
      ? normalizeHost(acceleration.origin.customHostHeader)
      : currentFullDomain.value;
    if (!hostHeader || !isValidDomain(hostHeader)) {
      validationError.value = '请填写合法的回源 HOST 头';
      return;
    }
  }
  if (acceleration && !acceleration.enabled && acceleration.restoreRecord) {
    const rr = acceleration.restoreRecord;
    if (!rr.type || !rr.value) {
      validationError.value = '请填写恢复记录的类型与值';
      return;
    }
    const contentError = validateDNSContent(rr.type, rr.value);
    if (contentError) {
      validationError.value = `恢复值：${contentError}`;
      return;
    }
  }

  const params: SubmitPayload = {
    recordId: isEdit.value ? props.initialRecord?.id : undefined,
    type: form.value.type,
    name: form.value.name,
    content: form.value.content,
    ttl: form.value.ttl,
    dnsChanged: dnsFieldsDirty(),
  };
  if (isCloudflare.value && ['A', 'AAAA', 'CNAME'].includes(form.value.type)) {
    params.proxied = form.value.proxied;
  }
  if (showPriority.value) params.priority = form.value.priority;
  if (caps.value?.supportsWeight) params.weight = form.value.weight;
  if (caps.value?.supportsLine && form.value.line) params.line = form.value.line;
  if (caps.value?.supportsRemark && form.value.remark) params.remark = form.value.remark;
  if (acceleration) params.acceleration = acceleration;
  emit('submit', params);
}

function onAccelerationSwitch(value: boolean) {
  accelerationEnabled.value = value;
  accelerationTouched.value = true;
  if (value && !originForm.value.originValue) {
    originForm.value.originValue = form.value.content || '';
  }
}

function onOriginTouch() {
  if (accelerationEnabled.value) originTouched.value = true;
}

async function checkAccelerationStatus() {
  const accel = props.accelerationState;
  if (!accel?.enabled || !accel.credentialId || !accel.siteId || !accel.domainName) return;
  accelerationStatusLoading.value = true;
  try {
    const res = await getAccelerationDomainStatus({
      credentialId: accel.credentialId,
      provider: accel.provider || 'edgeone',
      siteId: accel.siteId,
      domainName: accel.domainName,
      dnsCredentialId: props.zoneId ? undefined : undefined,
      autoMatchDns: true,
    });
    accelerationDomainStatus.value = res.data?.domain || null;
    accelerationCnameTarget.value = res.data?.domain?.cnameTarget || accel.target || '';
    if (res.data?.domain?.certificateStatus === 'deployed' || res.data?.domain?.certificateBound) {
      httpsCertStatus.value = 'deployed';
    } else if (res.data?.domain?.certificateStatus === 'deploying' || res.data?.domain?.certificateMode === 'apply') {
      httpsCertStatus.value = 'deploying';
    }
  } catch {
    accelerationDomainStatus.value = null;
  } finally {
    accelerationStatusLoading.value = false;
  }
}

async function loadHttpsCertificates() {
  const accel = props.accelerationState;
  const domainName = currentFullDomain.value;
  httpsConfiguring.value = true;
  try {
    const promises: Promise<any>[] = [
      getSslCertificates('all', { search: domainName, limit: 10 }),
    ];
    if (accel?.credentialId && accel?.siteId) {
      promises.push(
        listAccelerationCertificates({
          credentialId: accel.credentialId,
          provider: accel.provider || 'edgeone',
          siteId: accel.siteId,
          hosts: [domainName],
        }).catch(() => null)
      );
    }
    const [sslRes, accelCertsRes] = await Promise.allSettled(promises);
    if (accelCertsRes && accelCertsRes.status === 'fulfilled' && accelCertsRes.value) {
      httpsExistingCerts.value = accelCertsRes.value.data?.certificates || accelCertsRes.value.data?.items || [];
    }
    if (sslRes.status === 'fulfilled') {
      const allCerts = sslRes.value.data || [];
      httpsSslMatched.value = allCerts.filter((c: any) => {
        const certDomains: string[] = [];
        if (c.domain) certDomains.push(c.domain);
        if (Array.isArray(c.san)) certDomains.push(...c.san);
        else if (typeof c.san === 'string') certDomains.push(c.san);
        if (Array.isArray(c.domains)) certDomains.push(...c.domains);
        if (c.subject) certDomains.push(c.subject);
        const wildcardBase = domainName.split('.').slice(1).join('.');
        return certDomains.some((d: string) => {
          const normalized = d.trim().toLowerCase();
          return normalized === domainName.toLowerCase()
            || normalized === `*.${wildcardBase}`
            || normalized === `*.${domainName.toLowerCase()}`;
        });
      });
      if (httpsSslMatched.value.length > 0) {
        httpsCertStatus.value = 'deployed';
      }
    }
  } finally {
    httpsConfiguring.value = false;
  }
}

async function applyHttpsCertificate() {
  const accel = props.accelerationState;
  if (!accel?.credentialId || !accel?.siteId) {
    message.warning('请先开启加速后再申请证书');
    return;
  }
  httpsApplying.value = true;
  try {
    const domainName = accel.domainName || currentFullDomain.value;
    await createAccelerationCertificate({
      credentialId: accel.credentialId,
      provider: accel.provider || 'edgeone',
      siteId: accel.siteId,
      domainName,
    });
    httpsCertStatus.value = 'deploying';
  } catch {
    httpsCertStatus.value = 'error';
  } finally {
    httpsApplying.value = false;
  }
}

async function deployExistingSslCert(cert: any) {
  const accel = props.accelerationState;
  if (!accel?.credentialId || !accel?.siteId) {
    message.warning('请先开启加速后再部署证书');
    return;
  }
  httpsApplying.value = true;
  try {
    await bindAccelerationCertificate({
      credentialId: accel.credentialId,
      provider: accel.provider || 'edgeone',
      siteId: accel.siteId,
      hosts: [accel.domainName || currentFullDomain.value],
      certType: cert.certType || 'default',
      certId: cert.remoteCertId || cert.certId || cert.certificateId || cert.id,
    });
    httpsCertStatus.value = 'deployed';
  } catch {
    httpsCertStatus.value = 'error';
  } finally {
    httpsApplying.value = false;
  }
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    :title="isEdit ? '编辑 DNS 记录' : '添加 DNS 记录'"
    :style="{ width: 'min(96vw, 600px)' }"
    @update:show="emit('update:show', $event)"
  >
    <form @submit.prevent="handleSubmit">
      <div class="space-y-3">
        <div class="grid grid-cols-2 gap-3">
          <NFormItem label="类型" :show-feedback="false">
            <NSelect v-model:value="form.type" :options="recordTypeOptions" :disabled="isEdit" size="small" />
          </NFormItem>
          <NFormItem label="名称" :show-feedback="false">
            <NInput v-model:value="form.name" placeholder="@ 或子域名" size="small" />
          </NFormItem>
        </div>

        <NFormItem label="记录值" :show-feedback="false">
          <NInput v-model:value="form.content" placeholder="记录值" size="small" />
        </NFormItem>

        <div class="grid grid-cols-2 gap-3">
          <NFormItem label="TTL" :show-feedback="false">
            <NSelect v-model:value="form.ttl" :options="ttlOptions" size="small" />
          </NFormItem>

          <NFormItem v-if="showPriority" label="优先级" :show-feedback="false">
            <NInputNumber v-model:value="form.priority" :show-button="false" size="small" />
          </NFormItem>

          <NFormItem v-if="caps?.supportsWeight" label="权重" :show-feedback="false">
            <NInputNumber v-model:value="form.weight" :show-button="false" size="small" />
          </NFormItem>
        </div>

        <NFormItem v-if="isCloudflare && ['A', 'AAAA', 'CNAME'].includes(form.type)" label="代理" :show-feedback="false">
          <NSwitch v-model:value="form.proxied" />
        </NFormItem>

        <NFormItem v-if="caps?.supportsLine && lineOptions.length > 0" label="线路" :show-feedback="false">
          <NSelect v-model:value="form.line" :options="lineOptions" clearable size="small" />
        </NFormItem>

        <NCollapse v-if="caps?.supportsRemark || canAccelerate" v-model:expanded-names="activeCollapseNames" arrow-placement="right">
          <NCollapseItem v-if="caps?.supportsRemark" name="remark" title="备注">
            <NInput v-model:value="form.remark" placeholder="备注信息" size="small" />
          </NCollapseItem>

          <NCollapseItem v-if="canAccelerate" name="acceleration" title="加速管理">
            <template #header-extra>
              <NTag size="small" :type="accelerationStatusLabel.type" :bordered="false">
                {{ accelerationStatusLabel.text }}
              </NTag>
            </template>
            <div class="space-y-3">
              <div v-if="isEdit && accelerationState?.enabled" class="rounded-lg border border-panel-border bg-panel-bg p-3 space-y-2">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <NTag size="small" :type="accelerationStatusLabel.type" :bordered="false">
                      {{ accelerationStatusLabel.text }}
                    </NTag>
                    <span class="text-xs text-slate-500">EdgeOne 加速</span>
                  </div>
                  <NSwitch :value="accelerationEnabled" @update:value="onAccelerationSwitch" />
                </div>
                <div v-if="accelerationState?.target" class="text-xs text-slate-500 space-y-1">
                  <div>CNAME 目标：<span class="font-mono text-slate-700">{{ accelerationState.target }}</span></div>
                  <div v-if="accelerationState?.originalRecord?.type && accelerationState?.originalRecord?.value">
                    原始记录：<span class="font-mono text-slate-700">{{ accelerationState.originalRecord.type }} {{ accelerationState.originalRecord.value }}</span>
                  </div>
                </div>
                <NButton size="tiny" secondary :loading="accelerationStatusLoading" @click="checkAccelerationStatus">
                  检查加速状态
                </NButton>
                <div v-if="accelerationDomainStatus" class="text-xs space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="text-slate-500">域名状态：</span>
                    <NTag size="tiny" :type="accelerationDomainStatus.uiState === 'active' ? 'success' : accelerationDomainStatus.uiState === 'deploying' ? 'warning' : 'error'" :bordered="false">
                      {{ accelerationDomainStatus.uiState === 'active' ? '生效中' : accelerationDomainStatus.uiState === 'deploying' ? '部署中' : accelerationDomainStatus.uiState === 'cname_pending' ? '异常请添加 CNAME' : accelerationDomainStatus.uiState === 'paused' ? '已暂停' : accelerationDomainStatus.domainStatus || '未知' }}
                    </NTag>
                  </div>
                  <div v-if="accelerationCnameTarget" class="text-slate-500">
                    需要添加 CNAME：<span class="font-mono text-slate-700">{{ currentFullDomain }} → {{ accelerationCnameTarget }}</span>
                  </div>
                </div>
              </div>

              <div v-else-if="isEdit" class="flex items-center justify-between rounded-lg border border-panel-border bg-panel-bg px-3 py-2">
                <div>
                  <p class="text-sm text-slate-700">EdgeOne 加速</p>
                  <p class="text-xs text-slate-500">开启后此记录会被改写为指向 EdgeOne CNAME。关闭则按快照或手填源站恢复。</p>
                </div>
                <NSwitch :value="accelerationEnabled" @update:value="onAccelerationSwitch" />
              </div>

              <div v-else class="rounded-lg border border-panel-border bg-panel-bg px-3 py-2">
                <NCheckbox :checked="accelerationEnabled" @update:checked="onAccelerationSwitch">
                  <span class="text-sm text-slate-700">同时开启 EdgeOne 加速</span>
                </NCheckbox>
                <p class="mt-1 text-xs text-slate-500">保存记录后会自动创建加速域名并把当前记录改写为 CNAME。</p>
              </div>

              <div v-if="accelerationEnabled" class="space-y-3 rounded-lg border border-panel-border bg-panel-surface p-3">
                <div class="grid grid-cols-2 gap-3">
                  <NFormItem label="源站类型" :show-feedback="false">
                    <NSelect
                      :value="originForm.originType"
                      :options="[{ label: 'IP / 域名', value: 'IP_DOMAIN' }, { label: 'COS', value: 'COS' }, { label: 'AWS S3', value: 'AWS_S3' }]"
                      size="small"
                      @update:value="(v: string) => { originForm.originType = v; onOriginTouch(); }"
                    />
                  </NFormItem>
                  <NFormItem label="回源地址" :show-feedback="false">
                    <NInput
                      :value="originForm.originValue"
                      placeholder="合法 IP 或域名"
                      size="small"
                      @update:value="(v: string) => { originForm.originValue = v; onOriginTouch(); }"
                    />
                  </NFormItem>
                </div>
                <div class="grid grid-cols-[220px,1fr] gap-3">
                  <NFormItem label="HOST 头" :show-feedback="false">
                    <NSelect
                      :value="originForm.hostHeaderMode"
                      :options="[{ label: '使用当前域名', value: 'acceleration' }, { label: '自定义', value: 'custom' }]"
                      size="small"
                      @update:value="(v: 'acceleration' | 'custom') => { originForm.hostHeaderMode = v; onOriginTouch(); }"
                    />
                  </NFormItem>
                  <NFormItem label="当前 HOST 头" :show-feedback="false">
                    <div class="rounded-md border border-panel-border bg-panel-bg px-3 py-1.5 text-xs font-mono text-slate-700">{{ currentHostHeader || '-' }}</div>
                  </NFormItem>
                </div>
                <NFormItem v-if="originForm.hostHeaderMode === 'custom'" label="自定义 HOST 头" :show-feedback="false">
                  <NInput
                    :value="originForm.customHostHeader"
                    placeholder="origin.example.com"
                    size="small"
                    @update:value="(v: string) => { originForm.customHostHeader = v; onOriginTouch(); }"
                  />
                </NFormItem>
                <div class="grid grid-cols-3 gap-3">
                  <NFormItem label="回源协议" :show-feedback="false">
                    <NSelect
                      :value="originForm.originProtocol"
                      :options="[{ label: '协议跟随', value: 'FOLLOW' }, { label: 'HTTP', value: 'HTTP' }, { label: 'HTTPS', value: 'HTTPS' }]"
                      size="small"
                      @update:value="(v: string) => { originForm.originProtocol = v; onOriginTouch(); }"
                    />
                  </NFormItem>
                  <NFormItem label="HTTP" :show-feedback="false">
                    <NInputNumber
                      :value="originForm.httpOriginPort"
                      :min="1"
                      :max="65535"
                      :show-button="false"
                      size="small"
                      @update:value="(v: number | null) => { originForm.httpOriginPort = v || 80; onOriginTouch(); }"
                    />
                  </NFormItem>
                  <NFormItem label="HTTPS" :show-feedback="false">
                    <NInputNumber
                      :value="originForm.httpsOriginPort"
                      :min="1"
                      :max="65535"
                      :show-button="false"
                      size="small"
                      @update:value="(v: number | null) => { originForm.httpsOriginPort = v || 443; onOriginTouch(); }"
                    />
                  </NFormItem>
                </div>

                <NCollapse arrow-placement="right">
                  <NCollapseItem name="https" title="HTTPS 证书配置">
                    <template #header-extra>
                      <NTag size="small" :type="httpsCertStatus === 'deployed' ? 'success' : httpsCertStatus === 'deploying' ? 'warning' : httpsCertStatus === 'error' ? 'error' : 'default'" :bordered="false">
                        {{ httpsCertStatus === 'deployed' ? '已部署' : httpsCertStatus === 'deploying' ? '部署中' : httpsCertStatus === 'error' ? '异常' : '未配置' }}
                      </NTag>
                    </template>
                    <div class="space-y-3">
                      <NButton size="tiny" secondary :loading="httpsConfiguring" @click="loadHttpsCertificates">
                        查询可用证书
                      </NButton>

                      <div v-if="httpsSslMatched.length > 0" class="space-y-2">
                        <p class="text-xs text-slate-500">SSL 证书库中已有匹配证书，可直接部署：</p>
                        <div v-for="cert in httpsSslMatched" :key="cert.certId || cert.id" class="flex items-center justify-between rounded border border-panel-border bg-panel-bg px-3 py-2">
                          <div class="text-xs">
                            <span class="font-mono text-slate-700">{{ cert.domain }}{{ cert.san ? (Array.isArray(cert.san) ? `, ${cert.san.join(', ')}` : `, ${cert.san}`) : '' }}</span>
                            <span v-if="cert.notAfter" class="ml-2 text-slate-500">到期：{{ cert.notAfter }}</span>
                          </div>
                          <NButton size="tiny" type="primary" :loading="httpsApplying" @click="deployExistingSslCert(cert)">
                            部署
                          </NButton>
                        </div>
                      </div>

                      <div v-if="httpsExistingCerts.length > 0" class="space-y-2">
                        <p class="text-xs text-slate-500">EdgeOne 已有证书：</p>
                        <div v-for="cert in httpsExistingCerts" :key="cert.certificateId || cert.certId" class="flex items-center justify-between rounded border border-panel-border bg-panel-bg px-3 py-2">
                          <div class="text-xs">
                            <span class="font-mono text-slate-700">{{ cert.hosts?.join(', ') || cert.host }}</span>
                            <span v-if="cert.status" class="ml-2 text-slate-500">{{ cert.status }}</span>
                          </div>
                        </div>
                      </div>

                      <div v-if="httpsSslMatched.length === 0" class="space-y-2">
                        <NAlert type="info" :bordered="false">未找到匹配的 SSL 证书，可申请免费证书。</NAlert>
                        <NButton size="tiny" type="primary" :loading="httpsApplying" @click="applyHttpsCertificate">
                          申请免费证书
                        </NButton>
                      </div>
                    </div>
                  </NCollapseItem>
                </NCollapse>

                <NAlert type="info" :bordered="false">保存后将自动配置 CNAME 记录指向 EdgeOne 加速目标。</NAlert>
              </div>

              <div v-else-if="needsRestoreForm" class="space-y-3 rounded-lg border border-amber-200 bg-amber-50/70 p-3">
                <NAlert type="warning" :bordered="false">系统未找到原始记录快照，请填写恢复的源站信息。</NAlert>
                <div class="grid grid-cols-2 gap-3">
                  <NFormItem label="恢复类型" :show-feedback="false">
                    <NSelect
                      v-model:value="restoreForm.type"
                      :options="[{ label: 'A', value: 'A' }, { label: 'AAAA', value: 'AAAA' }, { label: 'CNAME', value: 'CNAME' }]"
                      size="small"
                    />
                  </NFormItem>
                  <NFormItem label="恢复值" :show-feedback="false">
                    <NInput v-model:value="restoreForm.value" placeholder="IP 或域名" size="small" />
                  </NFormItem>
                </div>
                <NFormItem label="TTL" :show-feedback="false">
                  <NSelect :value="restoreForm.ttl" :options="ttlOptions" size="small" @update:value="(v: number) => { restoreForm.ttl = v; }" />
                </NFormItem>
              </div>
            </div>
          </NCollapseItem>
        </NCollapse>

        <p v-if="validationError" class="text-sm text-red-500">{{ validationError }}</p>

        <div class="flex justify-end gap-2 pt-2">
          <NButton @click="emit('update:show', false)">取消</NButton>
          <NButton type="primary" :loading="loading" attr-type="submit">{{ isEdit ? '保存' : '添加' }}</NButton>
        </div>
      </div>
    </form>
  </NModal>
</template>