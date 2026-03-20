<script setup lang="ts">
import { ref, computed, watch, h } from 'vue';
import {
  NDataTable,
  NTag,
  NButton,
  NInput,
  NSelect,
  NSwitch,
  NEmpty,
  NPagination,
  NModal,
  NCheckbox,
  NPopover,
  useDialog,
} from 'naive-ui';
import { Edit2, Trash2, Check, X, Settings2, ArrowUp, ArrowDown } from 'lucide-vue-next';
import { useProviderStore } from '@/stores/provider';
import { useResponsive } from '@/composables/useResponsive';
import { formatTTL } from '@/utils/formatters';
import { TTL_OPTIONS, TABLE_PAGE_SIZE } from '@/utils/constants';
import type { DNSRecord } from '@/types';
import type { DnsLine } from '@/types/dns';
import type { RecordsResponseCapabilities } from '@/services/dns';

type ColumnKey = 'type' | 'name' | 'content' | 'proxied' | 'line' | 'ttl' | 'enabled' | 'remark' | 'acceleration' | 'actions';

type RecordAccelerationState = {
  matched: boolean;
  label: string;
  type: 'success' | 'warning' | 'error' | 'default';
  detail?: string;
};

const COLUMN_ORDER_KEY = 'dns_records_column_order_v1';
const HIDDEN_COLUMNS_KEY = 'dns_records_hidden_columns_v1';

const props = defineProps<{
  records: DNSRecord[];
  lines?: DnsLine[];
  minTtl?: number;
  capabilities?: RecordsResponseCapabilities;
  showAccelerationToggle?: boolean;
  accelerationToggleLabel?: string;
  resolveAccelerationState?: (record: DNSRecord) => RecordAccelerationState | null | undefined;
}>();

const emit = defineEmits<{
  update: [recordId: string, params: any];
  delete: [recordId: string];
  'status-change': [recordId: string, enabled: boolean];
  'batch-delete': [recordIds: string[]];
  'batch-status-change': [recordIds: string[], enabled: boolean];
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
const isCloudflare = computed(() => providerStore.selectedProvider === 'cloudflare');

const editingId = ref<string | null>(null);
const mobileEditVisible = ref(false);
const editForm = ref<any>({});

const currentPage = ref(1);
const pageSize = TABLE_PAGE_SIZE;
const checkedRowKeys = ref<string[]>([]);
const columnOrder = ref<ColumnKey[]>([]);
const hiddenColumns = ref<ColumnKey[]>([]);

const availableColumns = computed(() => {
  const list: Array<{ key: ColumnKey; label: string }> = [
    { key: 'type', label: '类型' },
    { key: 'name', label: '名称' },
    { key: 'content', label: '内容' },
    { key: 'ttl', label: 'TTL' },
  ];
  if (isCloudflare.value) list.push({ key: 'proxied', label: '代理' });
  if (caps.value?.supportsLine && (props.lines || []).length > 0) list.push({ key: 'line', label: '线路' });
  if (caps.value?.supportsStatus) list.push({ key: 'enabled', label: '状态' });
  if (caps.value?.supportsRemark) list.push({ key: 'remark', label: '备注' });
  if (props.showAccelerationToggle) list.push({ key: 'acceleration', label: '加速' });
  list.push({ key: 'actions', label: '操作' });
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

const visibleRecords = computed(() =>
  props.records.filter((r) => !(r.type === 'NS' && r.name === r.zoneName))
);

const paginatedRecords = computed(() => {
  const start = (currentPage.value - 1) * pageSize;
  return visibleRecords.value.slice(start, start + pageSize);
});

watch(() => visibleRecords.value.length, () => {
  const maxPage = Math.max(1, Math.ceil(visibleRecords.value.length / pageSize));
  if (currentPage.value > maxPage) currentPage.value = 1;
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

const lineOptions = computed(() => (props.lines || []).map((l) => ({ label: l.name, value: l.code })));
const ttlOptions = computed(() =>
  TTL_OPTIONS.filter((o) => o.value >= (props.minTtl || 1)).map((o) => ({ label: o.label, value: o.value }))
);

function startEdit(record: DNSRecord) {
  editingId.value = record.id;
  editForm.value = {
    type: record.type,
    name: record.name,
    content: record.content,
    ttl: record.ttl,
    proxied: record.proxied,
    priority: record.priority,
    weight: record.weight,
    line: record.line,
    remark: record.remark,
    enableAcceleration: Boolean(getAccelerationState(record)?.matched),
  };
  if (isMobile.value) mobileEditVisible.value = true;
}

function cancelEdit() {
  editingId.value = null;
  editForm.value = {};
  mobileEditVisible.value = false;
}

function saveEdit() {
  if (!editingId.value) return;
  emit('update', editingId.value, editForm.value);
  cancelEdit();
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

function getAccelerationState(record: DNSRecord) {
  return props.resolveAccelerationState?.(record) || null;
}

function renderAccelerationTag(record: DNSRecord) {
  const state = getAccelerationState(record);
  if (!state) {
    return h(NTag, {
      size: 'small',
      bordered: false,
      type: 'default',
    }, () => '未接入');
  }
  return h(
    NTag,
    {
      size: 'small',
      bordered: false,
      type: state.type,
    },
    () => state.label,
  );
}

function getAccelerationActionLabel(record: DNSRecord) {
  const state = getAccelerationState(record);
  if (state?.matched) return '已接入';
  return '编辑时可选';
}

function getAccelerationActionHint(record: DNSRecord) {
  const state = getAccelerationState(record);
  return state?.detail || '保存记录后自动创建或接管当前域名的加速配置';
}

function isEditingAccelerationEnabled(record: DNSRecord) {
  return Boolean(getAccelerationState(record)?.matched || editForm.value.enableAcceleration);
}

const columns = computed(() => {
  const defs: Record<ColumnKey, any> = {
    type: {
      title: '类型',
      key: 'type',
      width: 80,
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
      title: '名称',
      key: 'name',
      minWidth: 160,
      ellipsis: { tooltip: true },
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h(NInput, {
            value: editForm.value.name,
            'onUpdate:value': (v: string) => (editForm.value.name = v),
            size: 'small',
          });
        }
        return h('span', { class: 'font-mono text-sm text-slate-700' }, row.name);
      },
    },
    content: {
      title: '内容',
      key: 'content',
      minWidth: 220,
      ellipsis: { tooltip: true },
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h(NInput, {
            value: editForm.value.content,
            'onUpdate:value': (v: string) => (editForm.value.content = v),
            size: 'small',
          });
        }
        return h('span', { class: 'font-mono text-sm text-slate-500' }, row.content);
      },
    },
    proxied: {
      title: '代理',
      key: 'proxied',
      width: 90,
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h(NSwitch, {
            value: editForm.value.proxied,
            'onUpdate:value': (v: boolean) => (editForm.value.proxied = v),
            size: 'small',
          });
        }
        return h(
          NTag,
          { size: 'small', type: row.proxied ? 'warning' : 'default', bordered: false },
          () => (row.proxied ? '已代理' : '仅 DNS')
        );
      },
    },
    line: {
      title: '线路',
      key: 'line',
      width: 130,
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h(NSelect, {
            value: editForm.value.line,
            'onUpdate:value': (v: string) => (editForm.value.line = v),
            options: lineOptions.value,
            size: 'small',
            style: { minWidth: '100px' },
          });
        }
        return h('span', { class: 'text-sm text-slate-500' }, row.lineName || row.line || '-');
      },
    },
    ttl: {
      title: 'TTL',
      key: 'ttl',
      width: 100,
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h(NSelect, {
            value: editForm.value.ttl,
            'onUpdate:value': (v: number) => (editForm.value.ttl = v),
            options: ttlOptions.value,
            size: 'small',
            style: { minWidth: '88px' },
          });
        }
        return h('span', { class: 'text-sm text-slate-500' }, formatTTL(row.ttl));
      },
    },
    enabled: {
      title: '状态',
      key: 'enabled',
      width: 90,
      render(row: DNSRecord) {
        return h(NSwitch, {
          value: row.enabled !== false,
          size: 'small',
          'onUpdate:value': (v: boolean) => confirmStatusToggle(row, v),
        });
      },
    },
    remark: {
      title: '备注',
      key: 'remark',
      width: 150,
      ellipsis: { tooltip: true },
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h(NInput, {
            value: editForm.value.remark,
            'onUpdate:value': (v: string) => (editForm.value.remark = v),
            size: 'small',
          });
        }
        return h('span', { class: 'text-sm text-slate-500' }, row.remark || '-');
      },
    },
    acceleration: {
      title: '加速',
      key: 'acceleration',
      width: 140,
      render(row: DNSRecord) {
        if (!props.showAccelerationToggle) {
          return h('span', { class: 'text-sm text-slate-400' }, '-');
        }
        if (editingId.value === row.id) {
          return h('div', { class: 'flex flex-col items-start gap-1' }, [
            h(NSwitch, {
              value: isEditingAccelerationEnabled(row),
              'onUpdate:value': (v: boolean) => (editForm.value.enableAcceleration = v),
              size: 'small',
            }),
            h('span', { class: 'text-[11px] text-slate-400' }, getAccelerationActionHint(row)),
          ]);
        }
        const state = getAccelerationState(row);
        return h('div', { class: 'flex flex-col items-start gap-1' }, [
          renderAccelerationTag(row),
          h('span', { class: 'text-[11px] text-slate-400' }, state?.detail || getAccelerationActionLabel(row)),
        ]);
      },
    },
    actions: {
      title: '',
      key: 'actions',
      width: 96,
      fixed: 'right' as const,
      render(row: DNSRecord) {
        if (editingId.value === row.id) {
          return h('div', { class: 'flex gap-4' }, [
            h(
              NButton,
              { text: true, type: 'primary', size: 'small', onClick: saveEdit },
              { icon: () => h(Check, { size: 14 }) }
            ),
            h(
              NButton,
              { text: true, size: 'small', onClick: cancelEdit },
              { icon: () => h(X, { size: 14 }) }
            ),
          ]);
        }
        return h('div', { class: 'flex gap-4' }, [
          h(
            NButton,
            { text: true, size: 'small', onClick: () => startEdit(row) },
            { icon: () => h(Edit2, { size: 14 }) }
          ),
          h(
            NButton,
            { text: true, type: 'error', size: 'small', onClick: () => confirmDelete(row) },
            { icon: () => h(Trash2, { size: 14 }) }
          ),
        ]);
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
      <NButton size="tiny" secondary :disabled="checkedRowKeys.length === 0" @click="confirmBatchStatus(true)">批量启用</NButton>
      <NButton size="tiny" secondary :disabled="checkedRowKeys.length === 0" @click="confirmBatchStatus(false)">批量禁用</NButton>
      <NButton size="tiny" type="error" secondary :disabled="checkedRowKeys.length === 0" @click="confirmBatchDelete">批量删除</NButton>
      <NButton size="tiny" quaternary :disabled="checkedRowKeys.length === 0" @click="clearSelection">清空选择</NButton>
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
        v-for="record in paginatedRecords"
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
              <component :is="renderAccelerationTag(record)" v-if="showAccelerationToggle" />
            </div>
            <div class="truncate font-mono text-sm font-semibold text-slate-800">{{ record.name }}</div>
            <div class="mt-1 break-all font-mono text-xs text-slate-500">{{ record.content }}</div>
            <p v-if="showAccelerationToggle" class="mt-2 text-[11px] text-slate-400">
              {{ getAccelerationActionHint(record) }}
            </p>
          </div>
          <NCheckbox
            :checked="checkedRowKeys.includes(record.id)"
            @update:checked="(checked: boolean) => toggleMobileChecked(record.id, checked)"
          />
        </div>
        <div class="mb-2 flex items-center justify-between text-xs text-slate-500">
          <span>TTL: {{ formatTTL(record.ttl) }}</span>
          <span v-if="caps.supportsLine">{{ record.lineName || record.line || '-' }}</span>
        </div>

        <div class="flex flex-wrap items-center gap-4">
          <NButton text size="tiny" @click="startEdit(record)">
            <template #icon><Edit2 :size="12" /></template>
            编辑
          </NButton>
          <NButton
            v-if="caps.supportsStatus"
            text
            size="tiny"
            @click="confirmStatusToggle(record, record.enabled === false)"
          >
            {{ record.enabled === false ? '启用' : '禁用' }}
          </NButton>
          <NButton text size="tiny" type="error" @click="confirmDelete(record)">
            <template #icon><Trash2 :size="12" /></template>
            删除
          </NButton>
        </div>
      </div>
    </div>

    <NDataTable
      v-else
      :columns="columns"
      :data="paginatedRecords"
      :row-key="(row: DNSRecord) => row.id"
      :checked-row-keys="checkedRowKeys"
      :bordered="false"
      size="small"
      class="table-scrollable"
      :scroll-x="1100"
      :max-height="600"
      :virtual-scroll="paginatedRecords.length > 120"
      @update:checked-row-keys="setCheckedRowKeys"
    />

    <div v-if="visibleRecords.length > pageSize" class="mt-4 flex justify-end">
      <NPagination
        v-model:page="currentPage"
        :page-size="pageSize"
        :item-count="visibleRecords.length"
        show-quick-jumper
        size="small"
      />
    </div>
  </template>

  <NModal
    :show="mobileEditVisible"
    preset="card"
    title="编辑 DNS 记录"
    :style="{ width: 'min(96vw, 560px)' }"
    @update:show="(v: boolean) => { if (!v) cancelEdit(); }"
  >
    <div class="space-y-3">
      <NInput
        :value="editForm.name"
        placeholder="记录名称"
        size="small"
        @update:value="(v: string) => { editForm.name = v; }"
      />
      <NInput
        :value="editForm.content"
        placeholder="记录值"
        size="small"
        @update:value="(v: string) => { editForm.content = v; }"
      />
      <NSelect
        :value="editForm.ttl"
        :options="ttlOptions"
        size="small"
        @update:value="(v: number) => { editForm.ttl = v; }"
      />
      <NSelect
        v-if="caps.supportsLine && lineOptions.length > 0"
        :value="editForm.line"
        :options="lineOptions"
        size="small"
        placeholder="线路"
        @update:value="(v: string) => { editForm.line = v; }"
      />
      <NInput
        v-if="caps.supportsRemark"
        :value="editForm.remark"
        placeholder="备注"
        size="small"
        @update:value="(v: string) => { editForm.remark = v; }"
      />
      <div v-if="isCloudflare" class="flex items-center justify-between rounded-lg border border-panel-border bg-panel-bg px-3 py-2">
        <span class="text-sm text-slate-600">Cloudflare 代理</span>
        <NSwitch
          :value="!!editForm.proxied"
          size="small"
          @update:value="(v: boolean) => { editForm.proxied = v; }"
        />
      </div>

      <div v-if="showAccelerationToggle" class="flex items-center justify-between rounded-lg border border-panel-border bg-panel-bg px-3 py-2">
        <div>
          <p class="text-sm text-slate-600">{{ accelerationToggleLabel || '修改后自动接入加速' }}</p>
          <p class="text-xs text-slate-400">保存记录后自动创建或接管当前域名的加速配置</p>
        </div>
        <NSwitch
          :value="!!editForm.enableAcceleration"
          size="small"
          @update:value="(v: boolean) => { editForm.enableAcceleration = v; }"
        />
      </div>

      <div class="flex justify-end gap-4 pt-1">
        <NButton size="small" @click="cancelEdit">取消</NButton>
        <NButton size="small" type="primary" @click="saveEdit">保存</NButton>
      </div>
    </div>
  </NModal>
</template>
