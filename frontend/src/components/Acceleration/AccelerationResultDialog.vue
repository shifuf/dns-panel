<script setup lang="ts">
import { computed } from 'vue';
import { NAlert, NButton, NModal, NTag } from 'naive-ui';
import type { DomainAccelerationConfig, RemoteAccelerationSite } from '@/services/accelerations';

type AccelerationResultState = {
  title?: string;
  dnsCredentialId?: number | null;
  pluginCredentialId?: number | null;
  remoteSiteId?: string;
  accelerationDomain?: string;
  config?: DomainAccelerationConfig | null;
  site?: RemoteAccelerationSite | null;
  dnsRecordsAdded?: Array<{ zoneName: string; type: string; name: string; value: string }>;
  dnsRecordsSkipped?: Array<{ zoneName: string; type: string; name: string; value: string }>;
  dnsErrors?: Array<{ error: string; name?: string }>;
};

const props = defineProps<{
  show: boolean;
  loading?: boolean;
  result?: AccelerationResultState | null;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
  'create-verify-record': [value: { zoneName: string; dnsCredentialId: number; pluginCredentialId?: number; remoteSiteId?: string; accelerationDomain?: string }];
}>();

const siteData = computed(() => props.result?.config || props.result?.site || null);
const dnsAdded = computed(() => props.result?.dnsRecordsAdded || []);
const dnsSkipped = computed(() => props.result?.dnsRecordsSkipped || []);
const dnsErrors = computed(() => props.result?.dnsErrors || []);

const statusMeta = computed(() => {
  const site = siteData.value;
  if (!site) return { type: 'default' as const, label: '待处理', detail: '加速配置已提交，请刷新查看最新状态。' };
  const detail = String(site.cnameStatus || site.identificationStatus || site.verifyStatus || site.domainStatus || site.siteStatus || '').trim();
  if (site.paused) return { type: 'warning' as const, label: '已暂停', detail: detail || '加速站点当前处于暂停状态。' };
  if (site.verified || ['online', 'active', 'enabled'].includes(String(site.domainStatus || '').trim().toLowerCase())) {
    return { type: 'success' as const, label: '已开启', detail: detail || '加速配置已创建，可继续核对 DNS 生效情况。' };
  }
  return { type: 'warning' as const, label: '配置中', detail: detail || '请按下方指引补充 CNAME 或验证记录。' };
});

const cnameRecordName = computed(() => {
  const site = siteData.value;
  if (!site) return '-';
  if (site.subDomain && site.subDomain !== '@') return site.subDomain;
  return '@';
});

const canAutoCreateVerifyRecord = computed(() => {
  const site = siteData.value;
  return Boolean(
    site
    && props.result?.dnsCredentialId
    && site.verifyRecordName
    && !site.verified,
  );
});

function copyText(text: string | undefined) {
  if (!text) return;
  navigator.clipboard.writeText(text).catch(() => {});
}

function handleAutoCreateVerifyRecord() {
  const site = siteData.value;
  if (!site || !props.result?.dnsCredentialId) return;
  emit('create-verify-record', {
    zoneName: String(site.zoneName || ''),
    dnsCredentialId: Number(props.result.dnsCredentialId),
    pluginCredentialId: props.result.pluginCredentialId || undefined,
    remoteSiteId: props.result.remoteSiteId || site.remoteSiteId || undefined,
    accelerationDomain: props.result.accelerationDomain || site.accelerationDomain || undefined,
  });
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    :title="result?.title || '加速配置结果'"
    :style="{ width: 'min(94vw, 900px)' }"
    @update:show="emit('update:show', $event)"
  >
    <div class="space-y-4">
      <div class="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3">
        <div class="flex flex-wrap items-center gap-2">
          <NTag size="small" :bordered="false" :type="statusMeta.type">
            {{ statusMeta.label }}
          </NTag>
          <NTag v-if="siteData?.remoteSiteId" size="small" :bordered="false">
            Site {{ siteData.remoteSiteId }}
          </NTag>
        </div>
        <p class="mt-3 break-all text-sm font-semibold text-slate-900">{{ siteData?.accelerationDomain || siteData?.zoneName || result?.accelerationDomain || '-' }}</p>
        <p class="mt-2 text-xs leading-6 text-slate-500">{{ statusMeta.detail }}</p>
      </div>

      <div class="grid gap-4 md:grid-cols-2">
        <div class="rounded-2xl border border-slate-200 bg-white p-4">
          <p class="text-sm font-semibold text-slate-800">CNAME 管理</p>
          <p class="mt-2 text-xs text-slate-500">请把加速域名解析到 EdgeOne 返回的 CNAME，保存后等待 DNS 生效。</p>
          <div class="mt-3 space-y-2">
            <button class="w-full rounded-xl bg-slate-50 px-3 py-3 text-left" @click="copyText(cnameRecordName)">
              <p class="text-xs text-slate-500">主机记录</p>
              <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ cnameRecordName }}</p>
            </button>
            <button class="w-full rounded-xl bg-slate-50 px-3 py-3 text-left" @click="copyText(siteData?.cnameTarget || '')">
              <p class="text-xs text-slate-500">CNAME 值</p>
              <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ siteData?.cnameTarget || '等待 EdgeOne 下发' }}</p>
            </button>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-4">
          <p class="text-sm font-semibold text-slate-800">验证记录</p>
          <p class="mt-2 text-xs text-slate-500">如果当前状态仍是“配置中”，可自动补写验证记录，也可手动复制以下值到 DNS 后再执行验证。</p>
          <div class="mt-3 space-y-2">
            <button class="w-full rounded-xl bg-slate-50 px-3 py-3 text-left" @click="copyText(siteData?.verifyRecordType || 'TXT')">
              <p class="text-xs text-slate-500">记录类型</p>
              <p class="mt-1 text-sm font-medium text-slate-700">{{ siteData?.verifyRecordType || 'TXT' }}</p>
            </button>
            <button class="w-full rounded-xl bg-slate-50 px-3 py-3 text-left" @click="copyText(siteData?.verifyRecordName || '')">
              <p class="text-xs text-slate-500">主机记录</p>
              <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ siteData?.verifyRecordName || '-' }}</p>
            </button>
            <button class="w-full rounded-xl bg-slate-50 px-3 py-3 text-left" @click="copyText(siteData?.verifyRecordValue || '')">
              <p class="text-xs text-slate-500">记录值</p>
              <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ siteData?.verifyRecordValue || '-' }}</p>
            </button>
          </div>
        </div>
      </div>

      <NAlert v-if="dnsAdded.length || dnsSkipped.length || dnsErrors.length" :type="dnsErrors.length ? 'warning' : 'success'" :bordered="false">
        <div class="space-y-1 text-xs leading-6">
          <p v-if="dnsAdded.length">自动新增验证记录 {{ dnsAdded.length }} 条。</p>
          <p v-if="dnsSkipped.length">已有验证记录 {{ dnsSkipped.length }} 条，无需重复添加。</p>
          <p v-if="dnsErrors.length">自动写入失败 {{ dnsErrors.length }} 条，可改为手动配置。</p>
        </div>
      </NAlert>

      <div class="rounded-2xl border border-panel-border bg-panel-surface px-4 py-3 text-xs leading-6 text-slate-500">
        <p>配置引导：1. 先确认 CNAME 已添加到正确的主机记录。</p>
        <p>2. 若尚未通过验证，补充上方验证记录后再等待生效或手动验证。</p>
        <p>3. 状态会在“配置中 / 已开启 / 已暂停”之间变化，可在列表页继续同步或验证。</p>
      </div>

      <div class="flex flex-wrap justify-end gap-3">
        <NButton
          v-if="canAutoCreateVerifyRecord"
          secondary
          :loading="loading"
          @click="handleAutoCreateVerifyRecord"
        >
          自动添加验证记录
        </NButton>
        <NButton @click="emit('update:show', false)">关闭</NButton>
      </div>
    </div>
  </NModal>
</template>
