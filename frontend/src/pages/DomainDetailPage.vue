<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation } from '@tanstack/vue-query';
import { NButton, NSpin, NTag, useMessage } from 'naive-ui';
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
import type { RecordsResponseCapabilities } from '@/services/dns';
import { useProviderStore } from '@/stores/provider';
import { useBreadcrumbStore } from '@/stores/breadcrumb';
import { useCredentialResolver } from '@/composables/useCredentialResolver';
import { useResponsive } from '@/composables/useResponsive';
import type { DNSRecord } from '@/types';
import type { DnsLine } from '@/types/dns';
import { normalizeProviderType } from '@/utils/provider';
import DNSRecordTable from '@/components/DNSRecordTable/DNSRecordTable.vue';
import QuickAddForm from '@/components/QuickAddForm/QuickAddForm.vue';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const { credentialId } = useCredentialResolver();
const { isMobile } = useResponsive();

const zoneId = computed(() => route.params.zoneId as string);
const showAddDialog = ref(false);

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
watch(() => records.value, (recs) => {
  if (recs.length > 0 && recs[0].zoneName) {
    breadcrumbStore.setLabel(`zone:${zoneId.value}`, recs[0].zoneName);
  }
}, { immediate: true });

// Mutations
const createMutation = useMutation({
  mutationFn: (params: Parameters<typeof createDNSRecord>[1]) => createDNSRecord(zoneId.value, params, credentialId.value),
  onSuccess: () => { message.success('记录已添加'); showAddDialog.value = false; refetchRecords(); },
  onError: (err: any) => message.error(String(err)),
});

const updateMutation = useMutation({
  mutationFn: (vars: { recordId: string; params: Parameters<typeof updateDNSRecord>[2] }) =>
    updateDNSRecord(zoneId.value, vars.recordId, vars.params, credentialId.value),
  onSuccess: () => { message.success('记录已更新'); refetchRecords(); },
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
      @submit="handleAddSubmit"
    />
  </div>
</template>
