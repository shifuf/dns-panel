<script setup lang="ts">
import { ref, computed, watch, h } from 'vue';
import {
  NDataTable,
  NTag,
  NButton,
  NEmpty,
  NPagination,
  NCheckbox,
  NPopover,
  NModal,
  NAlert,
  useDialog,
} from 'naive-ui';
import { Edit2, Trash2, Settings2, ArrowUp, ArrowDown } from 'lucide-vue-next';
import { useProviderStore } from '@/stores/provider';
import { useResponsive } from '@/composables/useResponsive';
import { formatDateTime, formatTTL } from '@/utils/formatters';
import type { DNSRecord } from '@/types';
import type { DnsLine } from '@/types/dns';
import type { RecordsResponseCapabilities } from '@/services/dns';

type ColumnKey = 'name' | 'type' | 'line' | 'content' | 'weight' | 'priority' | 'ttl' | 'remark' | 'updatedAt' | 'actions';

const COLUMN_ORDER_KEY = 'dns_records_column_order_v2';
const HIDDEN_COLUMNS_KEY = 'dns_records_hidden_columns_v2';

const props = defineProps<{
  records: DNSRecord[];
  page?: number;
  pageSize?: number;
  total?: number;
  totalPages?: number;
  pageSizeOptions?: number[];
  lines?: DnsLine[];
  minTtl?: number;
  capabilities?: RecordsResponseCapabilities;
  updateLoadingIds?: string[];
  deleteLoadingIds?: string[];
  statusLoadingIds?: string[];
  accelerationLoadingIds?: string[];
  batchStatusLoading?: 'enable' | 'disable' | null;
  batchDeleteLoading?: boolean;
}>();

const emit = defineEmits<{
  edit: [record: DNSRecord, options?: { focusAcceleration?: boolean }];
  delete: [recordId: string];
  'status-change': [recordId: string, enabled: boolean];
  'batch-delete': [recordIds: string[]];
  'batch-status-change': [recordIds: string[], enabled: boolean];
  'page-change': [page: number];
  'page-size-change': [pageSize: number];
  'pause-acceleration': [record: DNSRecord];
  'resume-acceleration': [record: DNSRecord];
  'restore-origin': [record: DNSRecord];
}>();

const providerStore = useProviderStore();
const dialog = useDialog();
const { isMobile } = useResponsive();

const caps = computed(() => {
  if (props.capabilities) return props.capabilities;
  const c = providerStore.currentCapabilities;
  return {
    supportsWeight: !!c?.supportsWeight,
    supportsLine: !!c?.supportsLine,
    supportsStatus: !!c?.supportsStatus,
    supportsRemark: !!c?.supportsRemark,
  } as RecordsResponseCapabilities;
});

const checkedRowKeys = ref<string[]>([]);
const columnOrder = ref<ColumnKey[]>([]);
const hiddenColumns = ref<ColumnKey[]>([]);

const availableColumns = computed(() => {
  const list: Array<{ key: ColumnKey; label: string }> = [
    { key: 'name', label: '主机记录' },
    { key: 'type', label: '记录类型' },
    { key: 'line', label: '线路类型' },
    { key: 'content', label: '记录值' },
    { key: 'weight', label: '权重' },
    { key: 'priority', label: '优先级' },
    { key: 'ttl', label: 'TTL' },
    { key: 'remark', label: '备注' },
    { key: 'updatedAt', label: '最后操作时间' },
    { key: 'actions', label: '操作' },
  ];
  return list;
});

function initColumnPrefs() {
  const availableKeys = availableColumns.value.map((x) => x.key);
  try {
    const savedOrder = JSON.parse(localStorage.getItem(COLUMN_ORDER_KEY) || '[]') as ColumnKey[];
    const savedHidden = JSON.parse(localStorage.getItem(HIDDEN_COLUMNS_KEY) || '[]') as ColumnKey[];
    const validOrder = savedOrder.filter((k) => availableKeys.includes(k));
    const rest = availableKeys.filter((k) => !validOrder.includes(k));
    columnOrder.value = [...validOrder, ...rest];
    hiddenColumns.value = savedHidden.filter((k) => availableKeys.includes(k));
  } catch {
    columnOrder.value = [...availableKeys];
    hiddenColumns.value = [];
  }
}

function persistColumnPrefs() {
  localStorage.setItem(COLUMN_ORDER_KEY, JSON.stringify(columnOrder.value));
  localStorage.setItem(HIDDEN_COLUMNS_KEY, JSON.stringify(hiddenColumns.value));
}

watch(availableColumns, () => {
  initColumnPrefs();
}, { immediate: true });

const visibleRecords = computed(() => props.records || []);
const currentPage = computed(() => Math.max(1, Number(props.page || 1)));
const currentPageSize = computed(() => Math.max(1, Number(props.pageSize || visibleRecords.value.length || 1)));
const totalCount = computed(() => Math.max(0, Number(props.total ?? visibleRecords.value.length)));
const totalPages = computed(() => Math.max(1, Number(props.totalPages || Math.ceil(totalCount.value / currentPageSize.value) || 1)));
const resolvedPageSizeOptions = computed(() => {
  const options = props.pageSizeOptions?.length ? props.pageSizeOptions : [10, 20, 50, 100, 200];
  return [...new Set([...options, currentPageSize.value])].sort((a, b) => a - b);
});

watch(
  () => visibleRecords.value.map((x) => x.id),
  (ids) => {
    const idSet = new Set(ids);
    checkedRowKeys.value = checkedRowKeys.value.filter((id) => idSet.has(id));
  }
);

const selectedRecords = computed(() => {
  const selected = new Set(checkedRowKeys.value);
  return visibleRecords.value.filter((r) => selected.has(r.id));
});

const typeColor: Record<string, string> = {
  A: '#2563EB',
  AAAA: '#7C3AED',
  CNAME: '#DB2777',
  MX: '#EA580C',
  TXT: '#0891B2',
  SRV: '#16A34A',
  CAA: '#DC2626',
  NS: '#CA8A04',
  PTR: '#0D9488',
  REDIRECT_URL: '#E11D48',
  FORWARD_URL: '#D97706',
};

const updateLoadingSet = computed(() => new Set(props.updateLoadingIds || []));
const deleteLoadingSet = computed(() => new Set(props.deleteLoadingIds || []));
const statusLoadingSet = computed(() => new Set(props.statusLoadingIds || []));
const accelerationLoadingSet = computed(() => new Set(props.accelerationLoadingIds || []));

function normalizeHost(value?: string | null) {
  return String(value || '').trim().replace(/\.+$/, '').toLowerCase();
}

function formatLineDisplay(record: DNSRecord) {
  const lineName = String(record.lineName || '').trim();
  const lineCode = String(record.line || '').trim();
  if (lineName.toLowerCase() === 'default' || lineCode.toLowerCase() === 'default') return '默认值';
  return lineName || lineCode || '-';
}

function formatRecordUpdatedAt(value?: string | null) {
  if (!value) return '-';
  try {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return formatDateTime(value);
  } catch {
    return String(value);
  }
}

function isRecordUpdating(recordId: string) {
  return updateLoadingSet.value.has(recordId);
}

function isRecordDeleting(recordId: string) {
  return deleteLoadingSet.value.has(recordId);
}

function isRecordStatusLoading(recordId: string) {
  return statusLoadingSet.value.has(recordId);
}

function isRecordAccelerationLoading(recordId: string) {
  return accelerationLoadingSet.value.has(recordId);
}

function isRecordBusy(recordId: string) {
  return isRecordUpdating(recordId)
    || isRecordDeleting(recordId)
    || isRecordStatusLoading(recordId)
    || isRecordAccelerationLoading(recordId);
}

function canToggleAcceleration(record: DNSRecord) {
  if (record.acceleration?.enabled) return true;
  return ['A', 'AAAA', 'CNAME'].includes(record.type) && normalizeHost(record.name) !== normalizeHost(record.zoneName);
}

function isAccelerationActive(record: DNSRecord) {
  return !!record.acceleration?.enabled;
}

function isAccelerationPaused(record: DNSRecord) {
  return record.acceleration?.uiState === 'paused';
}

function accelerationButtonLabel(record: DNSRecord) {
  if (!isAccelerationActive(record)) return '开启加速';
  const ui = record.acceleration?.uiState;
  if (ui === 'deploying') return '部署中';
  if (ui === 'cname_pending') return '请添加CNAME';
  if (isAccelerationPaused(record)) return '已暂停';
  return '已加速';
}

function accelerationButtonType(record: DNSRecord): 'success' | 'warning' | 'error' | 'primary' | 'default' {
  if (!isAccelerationActive(record)) return 'primary';
  const ui = record.acceleration?.uiState;
  if (ui === 'deploying') return 'warning';
  if (ui === 'cname_pending' || ui === 'error') return 'error';
  if (isAccelerationPaused(record)) return 'warning';
  return 'success';
}

const accelerationActionRecord = ref<DNSRecord | null>(null);
const showAccelerationActionModal = ref(false);

function openAccelerationActionModal(record: DNSRecord) {
  accelerationActionRecord.value = record;
  showAccelerationActionModal.value = true;
}

function closeAccelerationActionModal() {
  showAccelerationActionModal.value = false;
  accelerationActionRecord.value = null;
}

function triggerAccelerationPauseOrResume() {
  const record = accelerationActionRecord.value;
  if (!record) return;
  if (isAccelerationPaused(record)) {
    emit('resume-acceleration', record);
  } else {
    emit('pause-acceleration', record);
  }
  closeAccelerationActionModal();
}

function triggerAccelerationRestoreOrigin() {
  const record = accelerationActionRecord.value;
  if (!record) return;
  emit('restore-origin', record);
  closeAccelerationActionModal();
}

function handleAccelerationButtonClick(record: DNSRecord) {
  if (isAccelerationActive(record)) {
    openAccelerationActionModal(record);
  } else {
    emit('edit', record, { focusAcceleration: true });
  }
}

function confirmDelete(record: DNSRecord) {
  dialog.info({
    title: '确认删除记录',
    content: `确定删除 ${record.type} ${record.name} 吗？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: () => emit('delete', record.id),
  });
}

function confirmStatusToggle(record: DNSRecord, enabled: boolean) {
  if ((record.enabled !== false) === enabled) return;
  dialog.warning({
    title: enabled ? '确认启用' : '确认禁用',
    content: `${enabled ? '启用' : '禁用'} ${record.type} ${record.name} 后会立即生效，是否继续？`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: () => emit('status-change', record.id, enabled),
  });
}

function confirmBatchDelete() {
  if (!checkedRowKeys.value.length) return;
  dialog.info({
    title: '批量删除',
    content: `将删除 ${checkedRowKeys.value.length} 条记录，此操作不可恢复。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: () => emit('batch-delete', [...checkedRowKeys.value]),
  });
}

function confirmBatchStatus(enabled: boolean) {
  if (!checkedRowKeys.value.length) return;
  dialog.warning({
    title: enabled ? '批量启用' : '批量禁用',
    content: `将${enabled ? '启用' : '禁用'} ${checkedRowKeys.value.length} 条记录。`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: () => emit('batch-status-change', [...checkedRowKeys.value], enabled),
  });
}

function clearSelection() {
  checkedRowKeys.value = [];
}

function setCheckedRowKeys(keys: Array<string | number>) {
  checkedRowKeys.value = keys.map((x) => String(x));
}

function toggleMobileChecked(id: string, checked: boolean) {
  if (checked) {
    checkedRowKeys.value = [...new Set([...checkedRowKeys.value, id])];
    return;
  }
  checkedRowKeys.value = checkedRowKeys.value.filter((x) => x !== id);
}

function handlePageChange(page: number) {
  emit('page-change', Math.max(1, Number(page || 1)));
}

function handlePageSizeChange(pageSize: number) {
  emit('page-size-change', Math.max(1, Number(pageSize || currentPageSize.value)));
}

function toggleColumn(key: ColumnKey, checked: boolean) {
  if (checked) {
    hiddenColumns.value = hiddenColumns.value.filter((x) => x !== key);
  } else {
    hiddenColumns.value = [...hiddenColumns.value, key];
  }
  persistColumnPrefs();
}

function moveColumn(key: ColumnKey, direction: 'up' | 'down') {
  const idx = columnOrder.value.indexOf(key);
  if (idx < 0) return;
  const target = direction === 'up' ? idx - 1 : idx + 1;
  if (target < 0 || target >= columnOrder.value.length) return;
  const next = [...columnOrder.value];
  const [item] = next.splice(idx, 1);
  next.splice(target, 0, item);
  columnOrder.value = next;
  persistColumnPrefs();
}

const orderedVisibleColumnKeys = computed(() => {
  const available = new Set(availableColumns.value.map((x) => x.key));
  return columnOrder.value.filter((key) => available.has(key) && !hiddenColumns.value.includes(key));
});

const columns = computed(() => {
  const defs: Record<ColumnKey, any> = {
    type: {
      title: '记录类型',
      key: 'type',
      width: 96,
      render(row: DNSRecord) {
        const color = typeColor[row.type] || '#64748B';
        return h(
          NTag,
          {
            size: 'small',
            bordered: true,
            type: 'default' as const,
            class: 'record-type-tag',
            style: {
              '--tag-bg': `${color}18`,
              '--tag-color': color,
              '--tag-border': `${color}35`,
              backgroundColor: 'var(--tag-bg)',
              color: 'var(--tag-color)',
              borderColor: 'var(--tag-border)',
            },
          },
          () => row.type
        );
      },
    },
    name: {
      title: '主机记录',
      key: 'name',
      minWidth: 160,
      ellipsis: { tooltip: true },
      render(row: DNSRecord) {
        return h('div', { class: 'flex flex-wrap items-center gap-2' }, [
          h('span', { class: 'font-mono text-sm text-slate-700' }, row.name),
          isAccelerationActive(row)
            ? h(
                NTag,
                { size: 'small', type: 'success', bordered: false },
                () => '已加速'
              )
            : null,
        ]);
      },
    },
    content: {
      title: '记录值',
      key: 'content',
      minWidth: 220,
      ellipsis: { tooltip: true },
      render(row: DNSRecord) {
        return h('span', { class: 'font-mono text-sm text-slate-500' }, row.content);
      },
    },
    line: {
      title: '线路类型',
      key: 'line',
      width: 130,
      render(row: DNSRecord) {
        return h('span', { class: 'text-sm text-slate-500' }, formatLineDisplay(row));
      },
    },
    weight: {
      title: '权重',
      key: 'weight',
      width: 88,
      render(row: DNSRecord) {
        return h('span', { class: 'text-sm text-slate-500' }, row.weight ?? '-');
      },
    },
    priority: {
      title: '优先级',
      key: 'priority',
      width: 88,
      render(row: DNSRecord) {
        return h('span', { class: 'text-sm text-slate-500' }, row.priority ?? '-');
      },
    },
    ttl: {
      title: 'TTL',
      key: 'ttl',
      width: 100,
      render(row: DNSRecord) {
        return h('span', { class: 'text-sm text-slate-500' }, formatTTL(row.ttl));
      },
    },
    remark: {
      title: '备注',
      key: 'remark',
      width: 150,
      ellipsis: { tooltip: true },
      render(row: DNSRecord) {
        return h('span', { class: 'text-sm text-slate-500' }, row.remark || '-');
      },
    },
    updatedAt: {
      title: '最后操作时间',
      key: 'updatedAt',
      minWidth: 176,
      render(row: DNSRecord) {
        return h('span', { class: 'text-sm text-slate-500' }, formatRecordUpdatedAt(row.updatedAt));
      },
    },
    actions: {
      title: '操作',
      key: 'actions',
      width: 320,
      fixed: 'right' as const,
      render(row: DNSRecord) {
        const actions: any[] = [];
        if (canToggleAcceleration(row)) {
          actions.push(
            h(
              NButton,
              {
                size: 'small',
                round: true,
                secondary: true,
                type: accelerationButtonType(row),
                loading: isRecordAccelerationLoading(row.id),
                disabled: isRecordBusy(row.id) && !isRecordAccelerationLoading(row.id),
                onClick: () => handleAccelerationButtonClick(row),
              },
              () => accelerationButtonLabel(row)
            )
          );
        }
        if (caps.value?.supportsStatus) {
          actions.push(
            h(
              NButton,
              {
                size: 'small',
                secondary: true,
                type: row.enabled === false ? 'success' : 'warning',
                loading: isRecordStatusLoading(row.id),
                disabled: isRecordBusy(row.id) && !isRecordStatusLoading(row.id),
                onClick: () => confirmStatusToggle(row, row.enabled === false),
              },
              () => (row.enabled === false ? '启用' : '禁用')
            )
          );
        }
        actions.push(
          h(
            NButton,
            {
              size: 'small',
              tertiary: true,
              loading: isRecordUpdating(row.id),
              disabled: isRecordBusy(row.id),
              onClick: () => emit('edit', row),
            },
            {
              icon: () => h(Edit2, { size: 14 }),
              default: () => '编辑',
            }
          )
        );
        actions.push(
          h(
            NButton,
            { text: true, type: 'error', size: 'small', loading: isRecordDeleting(row.id), disabled: isRecordBusy(row.id) && !isRecordDeleting(row.id), onClick: () => confirmDelete(row) },
            { icon: () => h(Trash2, { size: 14 }) }
          )
        );
        return h('div', { class: 'flex flex-wrap justify-end gap-2' }, actions);
      },
    },
  };

  const cols: any[] = [
    {
      type: 'selection',
      key: '__selection',
      width: 44,
      fixed: 'left' as const,
    },
  ];

  for (const key of orderedVisibleColumnKeys.value) {
    cols.push(defs[key]);
  }
  return cols;
});
</script>

<template>
  <NEmpty v-if="visibleRecords.length === 0" description="暂无 DNS 记录" class="py-10" />

  <template v-else>
    <div class="mb-3 flex flex-wrap items-center gap-4">
      <span class="text-xs font-semibold text-slate-500">已选 {{ checkedRowKeys.length }} 条</span>
      <NButton size="tiny" secondary :loading="batchStatusLoading === 'enable'" :disabled="checkedRowKeys.length === 0 || !!batchStatusLoading || !!batchDeleteLoading" @click="confirmBatchStatus(true)">批量启用</NButton>
      <NButton size="tiny" secondary :loading="batchStatusLoading === 'disable'" :disabled="checkedRowKeys.length === 0 || !!batchStatusLoading || !!batchDeleteLoading" @click="confirmBatchStatus(false)">批量禁用</NButton>
      <NButton size="tiny" type="error" secondary :loading="!!batchDeleteLoading" :disabled="checkedRowKeys.length === 0 || !!batchStatusLoading || !!batchDeleteLoading" @click="confirmBatchDelete">批量删除</NButton>
      <NButton size="tiny" quaternary :disabled="checkedRowKeys.length === 0 || !!batchStatusLoading || !!batchDeleteLoading" @click="clearSelection">清空选择</NButton>
      <div class="flex-1" />

      <NPopover v-if="!isMobile" trigger="click" placement="bottom-end">
        <template #trigger>
          <NButton size="tiny" secondary>
            <template #icon><Settings2 :size="12" /></template>
            列设置
          </NButton>
        </template>
        <div class="w-56 space-y-2">
          <div
            v-for="item in availableColumns"
            :key="item.key"
            class="flex items-center gap-4 rounded-xl border border-panel-border bg-panel-surface px-3 py-2"
          >
            <NCheckbox
              :checked="!hiddenColumns.includes(item.key)"
              @update:checked="(checked: boolean) => toggleColumn(item.key, checked)"
            >
              <span class="text-xs text-slate-600">{{ item.label }}</span>
            </NCheckbox>
            <div class="ml-auto flex items-center gap-4">
              <button class="rounded p-0.5 text-slate-500 hover:bg-panel-bg" @click="moveColumn(item.key, 'up')">
                <ArrowUp :size="12" />
              </button>
              <button class="rounded p-0.5 text-slate-500 hover:bg-panel-bg" @click="moveColumn(item.key, 'down')">
                <ArrowDown :size="12" />
              </button>
            </div>
          </div>
        </div>
      </NPopover>
    </div>

    <div v-if="isMobile" class="space-y-2">
      <div
        v-for="record in visibleRecords"
        :key="record.id"
        class="rounded-lg border border-panel-border bg-panel-surface p-3"
      >
        <div class="mb-3 flex items-start justify-between gap-3">
          <div class="min-w-0 flex-1">
            <div class="mb-2 flex flex-wrap items-center gap-2">
              <NTag
                size="small"
                :bordered="true"
                type="default"
                class="record-type-tag"
                :style="{
                  '--tag-bg': `${typeColor[record.type] || '#64748B'}18`,
                  '--tag-color': typeColor[record.type] || '#64748B',
                  '--tag-border': `${typeColor[record.type] || '#64748B'}35`,
                  backgroundColor: 'var(--tag-bg)',
                  color: 'var(--tag-color)',
                  borderColor: 'var(--tag-border)',
                }"
              >
                {{ record.type }}
              </NTag>
              <NTag v-if="caps.supportsStatus" size="small" :type="record.enabled !== false ? 'success' : 'default'" :bordered="false">
                {{ record.enabled !== false ? '启用' : '禁用' }}
              </NTag>
              <NTag v-if="isAccelerationActive(record)" size="small" type="success" :bordered="false">
                已加速
              </NTag>
            </div>
            <div class="truncate font-mono text-sm font-semibold text-slate-800">{{ record.name }}</div>
            <div class="mt-1 break-all font-mono text-xs text-slate-500">{{ record.content }}</div>
          </div>
          <NCheckbox
            :checked="checkedRowKeys.includes(record.id)"
            @update:checked="(checked: boolean) => toggleMobileChecked(record.id, checked)"
          />
        </div>
        <div class="mb-2 flex items-center justify-between text-xs text-slate-500">
          <span>TTL: {{ formatTTL(record.ttl) }}</span>
          <span>{{ formatLineDisplay(record) }}</span>
        </div>

        <div class="flex flex-wrap items-center gap-4">
          <NButton
            v-if="canToggleAcceleration(record)"
            secondary
            round
            size="tiny"
            :type="isAccelerationActive(record) ? 'success' : 'primary'"
            :loading="isRecordAccelerationLoading(record.id)"
            :disabled="isRecordBusy(record.id) && !isRecordAccelerationLoading(record.id)"
            @click="emit('edit', record, { focusAcceleration: true })"
          >
            {{ accelerationButtonLabel(record) }}
          </NButton>
          <NButton tertiary size="tiny" :loading="isRecordUpdating(record.id)" :disabled="isRecordBusy(record.id)" @click="emit('edit', record)">
            <template #icon><Edit2 :size="12" /></template>
            编辑
          </NButton>
          <NButton
            v-if="caps.supportsStatus"
            text
            size="tiny"
            :loading="isRecordStatusLoading(record.id)"
            :disabled="isRecordBusy(record.id) && !isRecordStatusLoading(record.id)"
            @click="confirmStatusToggle(record, record.enabled === false)"
          >
            {{ record.enabled === false ? '启用' : '禁用' }}
          </NButton>
          <NButton text size="tiny" type="error" :loading="isRecordDeleting(record.id)" :disabled="isRecordBusy(record.id) && !isRecordDeleting(record.id)" @click="confirmDelete(record)">
            <template #icon><Trash2 :size="12" /></template>
            删除
          </NButton>
        </div>
      </div>
    </div>

    <NDataTable
      v-else
      :columns="columns"
      :data="visibleRecords"
      :row-key="(row: DNSRecord) => row.id"
      :checked-row-keys="checkedRowKeys"
      :bordered="false"
      size="small"
      class="table-scrollable"
      :scroll-x="1100"
      :max-height="600"
      :virtual-scroll="visibleRecords.length > 120"
      @update:checked-row-keys="setCheckedRowKeys"
    />

    <NModal
      :show="showAccelerationActionModal"
      preset="card"
      title="加速操作"
      :style="{ width: 'min(92vw, 480px)' }"
      @update:show="(v: boolean) => { if (!v) closeAccelerationActionModal(); }"
    >
      <div v-if="accelerationActionRecord" class="space-y-3">
        <div class="flex flex-wrap items-center gap-2">
          <NTag
            size="small"
            :type="accelerationButtonType(accelerationActionRecord) === 'error' ? 'error' : isAccelerationPaused(accelerationActionRecord) ? 'warning' : 'success'"
            :bordered="false"
          >
            {{ accelerationButtonLabel(accelerationActionRecord) }}
          </NTag>
          <span class="font-mono text-sm text-slate-700">{{ accelerationActionRecord.name }}</span>
        </div>
        <div class="rounded-lg border border-panel-border bg-panel-bg p-3 text-xs text-slate-500 space-y-1">
          <div>
            加速域名：<span class="font-mono text-slate-700">{{ accelerationActionRecord.acceleration?.domainName || accelerationActionRecord.name }}</span>
          </div>
          <div>
            EdgeOne CNAME：<span class="font-mono text-slate-700">{{ accelerationActionRecord.acceleration?.target || accelerationActionRecord.content || '-' }}</span>
          </div>
          <div v-if="accelerationActionRecord.acceleration?.originalRecord?.type && accelerationActionRecord.acceleration?.originalRecord?.value">
            原始记录：<span class="font-mono text-slate-700">{{ accelerationActionRecord.acceleration.originalRecord.type }} {{ accelerationActionRecord.acceleration.originalRecord.value }}</span>
          </div>
          <div v-if="accelerationActionRecord.acceleration?.uiState === 'cname_pending'" class="mt-2 text-red-500 font-medium">
            ⚠ 异常：请添加 CNAME 记录指向上方目标地址
          </div>
          <div v-if="accelerationActionRecord.acceleration?.uiState === 'deploying'" class="mt-2 text-amber-600 font-medium">
            ⏳ 部署中：加速配置正在生效，请稍候
          </div>
        </div>
        <NAlert type="info" :bordered="false">
          <template v-if="isAccelerationPaused(accelerationActionRecord)">
            恢复加速后 EdgeOne 将重新接管此域名的加速服务。
          </template>
          <template v-else>
            暂停加速后 DNS 记录保持 CNAME，但 EdgeOne 不再提供加速。
          </template>
          「返回源站」会把 DNS 记录恢复为开启加速前的原始值。
        </NAlert>
        <div class="flex flex-wrap justify-end gap-2 pt-2">
          <NButton @click="closeAccelerationActionModal">取消</NButton>
          <NButton
            type="warning"
            :loading="isRecordAccelerationLoading(accelerationActionRecord.id)"
            :disabled="isRecordBusy(accelerationActionRecord.id) && !isRecordAccelerationLoading(accelerationActionRecord.id)"
            @click="triggerAccelerationRestoreOrigin"
          >
            返回源站
          </NButton>
          <NButton
            type="primary"
            :loading="isRecordAccelerationLoading(accelerationActionRecord.id)"
            :disabled="isRecordBusy(accelerationActionRecord.id) && !isRecordAccelerationLoading(accelerationActionRecord.id)"
            @click="triggerAccelerationPauseOrResume"
          >
            {{ isAccelerationPaused(accelerationActionRecord) ? '恢复加速' : '暂停加速' }}
          </NButton>
        </div>
      </div>
    </NModal>

    <div v-if="totalCount > 0" class="mt-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <div class="text-xs text-slate-500">
        共 {{ totalCount }} 条 · 当前第 {{ currentPage }} 页 · 共 {{ totalPages }} 页 · 每页 {{ currentPageSize }} 条
      </div>
      <NPagination
        :page="currentPage"
        :page-size="currentPageSize"
        :item-count="totalCount"
        :page-sizes="resolvedPageSizeOptions"
        show-quick-jumper
        show-size-picker
        size="small"
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </div>
  </template>
</template>
