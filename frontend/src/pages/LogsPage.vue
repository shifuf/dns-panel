<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useQuery } from '@tanstack/vue-query';
import { NSelect, NDataTable, NTag, NSpin, NEmpty, NPagination, NButton, NDrawer, useMessage } from 'naive-ui';
import { cleanupLogs, clearLogs, getLogs } from '@/services/logs';
import { getSystemSettings } from '@/services/auth';
import { formatDateTime } from '@/utils/formatters';
import { ACTION_TYPES, RESOURCE_TYPES, OPERATION_STATUS, TABLE_PAGE_SIZE } from '@/utils/constants';
import type { Log } from '@/types';
import { h } from 'vue';

const message = useMessage();
const page = ref(1);
const pageSize = TABLE_PAGE_SIZE;
const cleanupLoading = ref(false);
const clearLoading = ref(false);
const logRetentionDays = ref(90);
const filters = ref({
  action: null as string | null,
  resourceType: null as string | null,
  status: null as string | null,
});
const selectedLog = ref<Log | null>(null);
const showDetail = ref(false);

const { data, isLoading, refetch } = useQuery({
  queryKey: computed(() => ['logs', page.value, pageSize, filters.value]),
  queryFn: () => getLogs({
    page: page.value,
    limit: pageSize,
    action: filters.value.action || undefined,
    resourceType: filters.value.resourceType || undefined,
    status: filters.value.status || undefined,
  }),
});

const logs = computed<Log[]>(() => {
  const payload = data.value?.data as any;
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.logs)) return payload.logs;
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
});

const total = computed(() => {
  const payload = data.value?.data as any;
  const apiTotal = Number(
    data.value?.pagination?.total ??
    payload?.pagination?.total ??
    payload?.total
  );
  if (Number.isFinite(apiTotal) && apiTotal > 0) return apiTotal;
  return logs.value.length;
});

const tableData = computed(() => {
  if (data.value?.pagination?.total || (data.value?.data as any)?.pagination?.total) {
    return logs.value;
  }
  const start = (page.value - 1) * pageSize;
  return logs.value.slice(start, start + pageSize);
});

const successCount = computed(() => logs.value.filter((log) => log.status === 'SUCCESS').length);
const failedCount = computed(() => logs.value.filter((log) => log.status === 'FAILED').length);
const successRate = computed(() => {
  if (!logs.value.length) return 0;
  return Math.round((successCount.value / logs.value.length) * 100);
});

onMounted(async () => {
  try {
    const res = await getSystemSettings();
    logRetentionDays.value = Number(res.data?.logRetentionDays || 90);
  } catch {
    logRetentionDays.value = 90;
  }
});

watch(filters, () => { page.value = 1; }, { deep: true });

const actionOptions = [
  { label: '全部', value: null },
  ...Object.entries(ACTION_TYPES).map(([k, v]) => ({ label: v, value: k })),
];

const resourceOptions = [
  { label: '全部', value: null },
  ...Object.entries(RESOURCE_TYPES).map(([k, v]) => ({ label: v, value: k })),
];

const statusOptions = [
  { label: '全部', value: null },
  ...Object.entries(OPERATION_STATUS).map(([k, v]) => ({ label: v, value: k })),
];

function getRecordName(log: any): string {
  if (log?.recordName) return log.recordName;
  if (log?.resourceType === 'CREDENTIAL') {
    try {
      const parsed = JSON.parse(log?.newValue || log?.oldValue || '{}');
      return parsed?.name || parsed?.credential?.name || '-';
    } catch { return '-'; }
  }
  return '-';
}

function openDetail(log: Log) {
  selectedLog.value = log;
  showDetail.value = true;
}

async function handleCleanup() {
  if (!window.confirm(`将清理 ${logRetentionDays.value} 天之前的日志，是否继续？`)) return;
  try {
    cleanupLoading.value = true;
    const res = await cleanupLogs(logRetentionDays.value);
    message.success(res.message || '日志清理完成');
    await refetch();
  } catch (err: any) {
    message.error(String(err));
  } finally {
    cleanupLoading.value = false;
  }
}

async function handleClear() {
  if (!window.confirm('将清空当前账号的全部日志，只保留本次清空记录，是否继续？')) return;
  try {
    clearLoading.value = true;
    const res = await clearLogs();
    message.success(res.message || '日志已清空');
    await refetch();
  } catch (err: any) {
    message.error(String(err));
  } finally {
    clearLoading.value = false;
  }
}

function parseMaybeJson(value?: string): unknown {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function stringifyMaybe(value: unknown): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

const parsedOldValue = computed(() => parseMaybeJson(selectedLog.value?.oldValue));
const parsedNewValue = computed(() => parseMaybeJson(selectedLog.value?.newValue));

const diffItems = computed(() => {
  const oldObj = parsedOldValue.value;
  const newObj = parsedNewValue.value;
  if (!oldObj || !newObj || typeof oldObj !== 'object' || typeof newObj !== 'object') {
    return [];
  }

  const oldRecord = oldObj as Record<string, any>;
  const newRecord = newObj as Record<string, any>;
  const keys = new Set([...Object.keys(oldRecord), ...Object.keys(newRecord)]);
  const diffs: Array<{ key: string; oldValue: string; newValue: string; kind: 'changed' | 'added' | 'removed' }> = [];

  for (const key of keys) {
    const oldValue = oldRecord[key];
    const newValue = newRecord[key];
    const oldText = stringifyMaybe(oldValue);
    const newText = stringifyMaybe(newValue);
    if (oldText === newText) continue;
    if (oldValue === undefined) {
      diffs.push({ key, oldValue: '-', newValue: newText, kind: 'added' });
    } else if (newValue === undefined) {
      diffs.push({ key, oldValue: oldText, newValue: '-', kind: 'removed' });
    } else {
      diffs.push({ key, oldValue: oldText, newValue: newText, kind: 'changed' });
    }
  }

  return diffs;
});

const columns = computed(() => [
  { title: '时间', key: 'timestamp', width: 170, render: (row: Log) => h('span', { class: 'text-sm text-slate-400' }, formatDateTime(row.timestamp)) },
  {
    title: '操作', key: 'action', width: 90,
    render: (row: Log) => {
      const actionColors: Record<string, string> = {
        CREATE: '#10B981',
        UPDATE: '#3B82F6',
        DELETE: '#EF4444',
      };
      const color = actionColors[row.action] || '#6B7280';
      return h(NTag, {
        size: 'small',
        bordered: true,
        class: 'record-type-tag',
        style: {
          '--tag-bg': `${color}15`,
          '--tag-color': color,
          '--tag-border': `${color}30`,
          backgroundColor: 'var(--tag-bg)',
          color: 'var(--tag-color)',
          borderColor: 'var(--tag-border)',
          fontWeight: '700',
        },
      }, () => ACTION_TYPES[row.action as keyof typeof ACTION_TYPES] || row.action);
    },
  },
  {
    title: '资源类型', key: 'resourceType', width: 120,
    render: (row: Log) => h('span', { class: 'text-sm' }, RESOURCE_TYPES[row.resourceType as keyof typeof RESOURCE_TYPES] || row.resourceType),
  },
  {
    title: '记录名称', key: 'recordName', minWidth: 180,
    render: (row: Log) => {
      const name = getRecordName(row);
      const type = row.recordType ? ` (${row.recordType})` : '';
      return h('span', { class: 'text-sm text-slate-600 font-mono' }, `${name}${type}`);
    },
  },
  {
    title: '状态', key: 'status', width: 80,
    render: (row: Log) => h(NTag, {
      type: row.status === 'SUCCESS' ? 'success' : 'error',
      size: 'small', bordered: false,
    }, () => OPERATION_STATUS[row.status as keyof typeof OPERATION_STATUS] || row.status),
  },
  { title: 'IP', key: 'ipAddress', width: 130, render: (row: Log) => h('span', { class: 'text-sm text-slate-500 font-mono' }, row.ipAddress || '-') },
  {
    title: '',
    key: 'actions',
    width: 80,
    fixed: 'right' as const,
    render: (row: Log) => h(
      NButton,
      {
        size: 'small',
        secondary: true,
        onClick: () => openDetail(row),
        style: {
          background: 'linear-gradient(135deg, rgba(0, 82, 255, 0.08), rgba(77, 124, 255, 0.12))',
          borderColor: 'rgba(0, 82, 255, 0.2)',
          color: '#1f57cc',
          fontWeight: '700',
        },
      },
      () => '详情'
    ),
  },
]);
</script>

<template>
  <div class="bento-grid">
    <section class="bento-hero col-span-12 md:col-span-8">
      <div class="section-badge">
        <span class="dot" />
        <span class="label">Audit Trail</span>
      </div>
      <h1 class="page-title">
        操作
        <span class="gradient-text"> 日志</span>
      </h1>
      <p class="page-subtitle">按行为、资源与状态过滤，快速追踪历史变更与页面访问</p>
      <div class="mt-4 flex flex-wrap gap-4">
        <NSelect v-model:value="filters.action" :options="actionOptions" placeholder="操作类型" clearable size="small" class="!w-36" />
        <NSelect v-model:value="filters.resourceType" :options="resourceOptions" placeholder="资源类型" clearable size="small" class="!w-40" />
        <NSelect v-model:value="filters.status" :options="statusOptions" placeholder="状态" clearable size="small" class="!w-28" />
      </div>
    </section>

    <section class="col-span-12 grid grid-cols-1 gap-4 md:col-span-4">
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -right-12 -top-12 w-44 h-44 rounded-full bg-gradient-to-br from-rose-500/18 to-pink-500/18 blur-2xl" />
        <div class="absolute right-4 top-4 w-14 h-14 rounded-full bg-gradient-to-br from-rose-400/28 to-pink-400/28 blur-xl" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">成功率</p>
          <div class="mt-2 flex items-end gap-2">
            <p class="text-5xl bg-gradient-to-r from-rose-600 to-pink-600 bg-clip-text text-transparent">{{ successRate }}</p>
            <span class="text-2xl text-slate-400 mb-1">%</span>
          </div>
          <div class="mt-4 h-3.5 bg-slate-100 rounded-full overflow-hidden">
            <div class="h-full bg-gradient-to-r from-rose-500 to-pink-500 rounded-full" :style="{ width: successRate + '%' }"></div>
          </div>
          <div class="mt-3 flex items-center gap-4">
            <span class="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-600">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-lg shadow-emerald-500/35"></span>
              成功 {{ successCount }}
            </span>
            <span class="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-600">
              <span class="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-lg shadow-rose-500/35"></span>
              失败 {{ failedCount }}
            </span>
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -left-12 -bottom-12 w-36 h-36 rounded-full bg-gradient-to-br from-cyan-500/15 to-blue-500/15 blur-xl" />
        <div class="absolute left-4 bottom-4 w-12 h-12 rounded-full bg-gradient-to-br from-cyan-400/25 to-blue-400/25 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">当前页</p>
          <div class="mt-3 flex items-baseline gap-2">
            <span class="text-4xl text-slate-800">#</span>
            <span class="text-5xl text-cyan-600">{{ page }}</span>
          </div>
          <div class="mt-4 h-2.5 bg-slate-100 rounded-full overflow-hidden">
            <div class="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full" :style="{ width: Math.min(100, (page * pageSize / Math.max(1, total)) * 100) + '%' }"></div>
          </div>
        </div>
      </article>
      <article class="bento-card p-5 relative overflow-hidden">
        <div class="absolute -right-14 -top-14 w-44 h-44 rounded-full bg-gradient-to-br from-amber-500/15 to-orange-500/15 blur-xl" />
        <div class="absolute right-4 top-4 w-12 h-12 rounded-full bg-gradient-to-br from-amber-400/25 to-orange-400/25 blur-lg" />
        <div class="relative z-10">
          <p class="text-xs uppercase tracking-widest text-slate-500">日志总量</p>
          <div class="mt-3">
            <p class="text-5xl text-slate-800">{{ total }}</p>
            <p class="mt-1 text-lg text-amber-600">条记录</p>
          </div>
          <div class="mt-4 flex items-center gap-2">
            <span class="text-xs text-slate-500">每页</span>
            <span class="text-sm bg-amber-100 text-amber-700 px-2 py-0.5 rounded-lg font-semibold">{{ pageSize }}</span>
          </div>
        </div>
      </article>
    </section>

    <section class="bento-card col-span-12">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="bento-section-title">变更事件列表</p>
          <p class="bento-section-meta">支持分页、筛选、访问记录与字段级差异查看，当前保留时长 {{ logRetentionDays }} 天</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <NButton size="small" :loading="cleanupLoading" @click="handleCleanup">清理过期日志</NButton>
          <NButton size="small" secondary type="error" :loading="clearLoading" @click="handleClear">清空全部日志</NButton>
        </div>
      </div>

      <div v-if="isLoading" class="flex justify-center py-20"><NSpin size="large" /></div>
      <NEmpty v-else-if="logs.length === 0" description="暂无日志记录" class="py-10" />

      <NDataTable
        v-else
        :columns="columns"
        :data="tableData"
        :row-key="(row: Log) => row.id"
        :bordered="false"
        size="small"
        class="table-scrollable"
        :scroll-x="800"
        :max-height="620"
        :virtual-scroll="tableData.length > 120"
      />

      <div v-if="total > pageSize" class="mt-4 flex justify-end">
        <NPagination
          v-model:page="page"
          :page-size="pageSize"
          :item-count="total"
          show-quick-jumper
          size="small"
        />
      </div>
    </section>

    <NDrawer
      v-model:show="showDetail"
      placement="right"
      :width="460"
      :trap-focus="true"
      :auto-focus="false"
    >
      <div class="h-full overflow-y-auto bg-panel-surface p-4">
        <h3 class="mb-3 text-base font-bold text-slate-700">日志详情</h3>
        <div v-if="selectedLog" class="space-y-4">
          <div class="panel-muted p-4 text-sm text-slate-600">
            <p>时间: {{ formatDateTime(selectedLog.timestamp) }}</p>
            <p>操作: {{ ACTION_TYPES[selectedLog.action as keyof typeof ACTION_TYPES] || selectedLog.action }}</p>
            <p>资源: {{ RESOURCE_TYPES[selectedLog.resourceType as keyof typeof RESOURCE_TYPES] || selectedLog.resourceType }}</p>
            <p>状态: {{ OPERATION_STATUS[selectedLog.status as keyof typeof OPERATION_STATUS] || selectedLog.status }}</p>
            <p>IP: {{ selectedLog.ipAddress || '-' }}</p>
            <p>记录: {{ getRecordName(selectedLog) }}</p>
          </div>

          <div v-if="diffItems.length > 0" class="panel-muted p-4">
            <p class="mb-2 text-sm font-semibold text-slate-700">变更差异</p>
            <div class="space-y-4 text-xs">
              <div v-for="item in diffItems" :key="item.key" class="rounded-xl border border-panel-border bg-panel-surface p-3">
                <p class="mb-1 font-semibold text-slate-700">{{ item.key }}</p>
                <p class="text-slate-500">旧值: {{ item.oldValue }}</p>
                <p class="text-slate-500">新值: {{ item.newValue }}</p>
              </div>
            </div>
          </div>

          <div class="panel-muted p-4">
            <p class="mb-2 text-sm font-semibold text-slate-700">旧值</p>
            <pre class="max-h-48 overflow-auto rounded bg-panel-surface p-2 text-xs text-slate-600">{{ stringifyMaybe(parsedOldValue) }}</pre>
          </div>

          <div class="panel-muted p-4">
            <p class="mb-2 text-sm font-semibold text-slate-700">新值</p>
            <pre class="max-h-48 overflow-auto rounded bg-panel-surface p-2 text-xs text-slate-600">{{ stringifyMaybe(parsedNewValue) }}</pre>
          </div>
        </div>
      </div>
    </NDrawer>
  </div>
</template>
