<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NDataTable, NButton, NTag, NModal, NInput, NSelect, NSwitch, NFormItem, NSpin, NEmpty, NPagination, useMessage } from 'naive-ui';
import { Plus, RefreshCw, Trash2, Edit2, Shield } from 'lucide-vue-next';
import {
  listEsaRecords, createEsaRecord, updateEsaRecord, deleteEsaRecord,
  listEsaCertificatesByRecord, applyEsaCertificate, checkEsaCnameStatus,
  type EsaDnsRecord,
} from '@/services/aliyunEsa';
import { useResponsive } from '@/composables/useResponsive';
import { TABLE_PAGE_SIZE } from '@/utils/constants';
import { h } from 'vue';

const props = defineProps<{
  credentialId: number;
  siteId: string;
  siteName: string;
  region?: string;
  accessType?: string;
}>();

const message = useMessage();
const queryClient = useQueryClient();
const { isMobile } = useResponsive();

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'];

// Dialog state
const showEditor = ref(false);
const editingRecord = ref<EsaDnsRecord | null>(null);
const showHttps = ref(false);
const selectedRecordForCert = ref<string | null>(null);
const page = ref(1);
const pageSize = TABLE_PAGE_SIZE;

// Form state
const formType = ref('A');
const formHost = ref('');
const formValue = ref('');
const formTTL = ref(300);
const formProxied = ref(false);
const formComment = ref('');

// Records query
const { data: recordsData, isLoading, refetch } = useQuery({
  queryKey: computed(() => ['esa-records', props.credentialId, props.siteId]),
  queryFn: async () => {
    const res = await listEsaRecords({
      credentialId: props.credentialId,
      siteId: props.siteId,
      region: props.region,
      pageSize: 500,
    });
    return res.data?.records || [];
  },
});

const records = computed(() => recordsData.value || []);
const paginatedRecords = computed(() => {
  const start = (page.value - 1) * pageSize;
  return records.value.slice(start, start + pageSize);
});

// CNAME status check
const cnameRecords = computed(() =>
  records.value.filter(r => r.type === 'CNAME' && r.recordCname)
    .map(r => ({ recordName: r.recordName, recordCname: r.recordCname! }))
);

const { data: cnameStatusData } = useQuery({
  queryKey: computed(() => ['esa-cname-status', cnameRecords.value]),
  queryFn: () => checkEsaCnameStatus({ records: cnameRecords.value }),
  enabled: computed(() => cnameRecords.value.length > 0),
});

function getCnameStatus(recordName: string): string {
  const results = cnameStatusData.value?.data?.results || [];
  const entry = results.find(r => r.recordName === recordName);
  return entry?.status || '-';
}

// Certificate status
const recordNames = computed(() => records.value.map(r => r.recordName));
const { data: certData } = useQuery({
  queryKey: computed(() => ['esa-certs', props.credentialId, props.siteId, recordNames.value]),
  queryFn: () => listEsaCertificatesByRecord({
    credentialId: props.credentialId,
    siteId: props.siteId,
    recordNames: recordNames.value,
    region: props.region,
  }),
  enabled: computed(() => recordNames.value.length > 0),
});

function getCertStatus(recordName: string): string {
  const records = certData.value?.data?.records || [];
  const entry = records.find(r => r.recordName === recordName);
  if (!entry) return '-';
  if (entry.applyingCount && entry.applyingCount > 0) return '申请中';
  return entry.status || '-';
}

// CRUD mutations
const createMutation = useMutation({
  mutationFn: () => createEsaRecord({
    credentialId: props.credentialId,
    siteId: props.siteId,
    recordName: formHost.value,
    type: formType.value,
    ttl: formTTL.value,
    proxied: formProxied.value,
    comment: formComment.value,
    data: { value: formValue.value },
    region: props.region,
  }),
  onSuccess: () => { message.success('记录已添加'); showEditor.value = false; refetch(); },
  onError: (err: any) => message.error(String(err)),
});

const updateMutation = useMutation({
  mutationFn: () => {
    if (!editingRecord.value) throw new Error('No record');
    return updateEsaRecord(editingRecord.value.recordId, {
      credentialId: props.credentialId,
      ttl: formTTL.value,
      proxied: formProxied.value,
      comment: formComment.value,
      data: { value: formValue.value },
      region: props.region,
    });
  },
  onSuccess: () => { message.success('记录已更新'); showEditor.value = false; refetch(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteMutation = useMutation({
  mutationFn: (recordId: string) => deleteEsaRecord({ credentialId: props.credentialId, recordId, region: props.region }),
  onSuccess: () => { message.success('记录已删除'); refetch(); },
  onError: (err: any) => message.error(String(err)),
});

const applyCertMutation = useMutation({
  mutationFn: (domains: string[]) => applyEsaCertificate({
    credentialId: props.credentialId,
    siteId: props.siteId,
    domains,
    region: props.region,
  }),
  onSuccess: () => {
    message.success('证书申请已提交');
    queryClient.invalidateQueries({ queryKey: ['esa-certs'] });
  },
  onError: (err: any) => message.error(String(err)),
});

function openAdd() {
  editingRecord.value = null;
  formType.value = 'A';
  formHost.value = '';
  formValue.value = '';
  formTTL.value = 300;
  formProxied.value = false;
  formComment.value = '';
  showEditor.value = true;
}

function openEdit(record: EsaDnsRecord) {
  editingRecord.value = record;
  formType.value = record.type;
  formHost.value = record.recordName;
  formValue.value = (record.data as any)?.value || '';
  formTTL.value = record.ttl || 300;
  formProxied.value = record.proxied || false;
  formComment.value = record.comment || '';
  showEditor.value = true;
}

function handleSave() {
  if (editingRecord.value) {
    updateMutation.mutate();
  } else {
    createMutation.mutate();
  }
}

function getRecordValue(record: EsaDnsRecord): string {
  const data = record.data as Record<string, unknown> | undefined;
  if (!data) return '-';
  return String(data.value || data.content || '-');
}

// Table columns
const columns = computed(() => [
  { title: '类型', key: 'type', width: 70, render: (row: EsaDnsRecord) => h(NTag, { size: 'small', bordered: false }, () => row.type) },
  { title: '主机记录', key: 'recordName', minWidth: 180, ellipsis: { tooltip: true } },
  { title: '记录值', key: 'value', minWidth: 200, render: (row: EsaDnsRecord) => h('span', { class: 'text-sm font-mono text-slate-600' }, getRecordValue(row)) },
  { title: 'TTL', key: 'ttl', width: 80, render: (row: EsaDnsRecord) => h('span', { class: 'text-slate-500 text-sm' }, String(row.ttl || '-')) },
  {
    title: '操作',
    key: 'actions',
    width: 100,
    fixed: 'right' as const,
    render: (row: EsaDnsRecord) => h('div', { class: 'flex gap-4' }, [
      h(NButton, { text: true, size: 'small', onClick: () => openEdit(row) }, { icon: () => h(Edit2, { size: 14 }) }),
      h(NButton, { text: true, size: 'small', type: 'error', onClick: () => deleteMutation.mutate(row.recordId) }, { icon: () => h(Trash2, { size: 14 }) }),
      h(NButton, { text: true, size: 'small', onClick: () => { selectedRecordForCert.value = row.recordName; showHttps.value = true; } }, { icon: () => h(Shield, { size: 14 }) }),
    ]),
  },
]);
</script>

<template>
  <div class="py-2">
    <div class="mb-3 flex items-center gap-4">
      <span class="text-sm text-slate-400 font-medium">ESA 记录 — {{ siteName }}</span>
      <div class="flex-1" />
      <NButton size="tiny" secondary @click="refetch()">
        <template #icon><RefreshCw :size="12" /></template>
      </NButton>
      <NButton size="tiny" type="primary" @click="openAdd">
        <template #icon><Plus :size="12" /></template>
        添加
      </NButton>
    </div>

    <NSpin v-if="isLoading" size="small" class="block mx-auto py-6" />
    <NEmpty v-else-if="records.length === 0" description="暂无记录" size="small" />
    <NDataTable
      v-else
      :columns="columns"
      :data="paginatedRecords"
      :row-key="(r: EsaDnsRecord) => r.recordId"
      :bordered="false"
      size="small"
      class="table-scrollable"
      :max-height="400"
      :scroll-x="600"
      :virtual-scroll="paginatedRecords.length > 120"
    />
    <div v-if="records.length > pageSize" class="mt-3 flex justify-end">
      <NPagination
        v-model:page="page"
        :page-size="pageSize"
        :item-count="records.length"
        show-quick-jumper
        size="small"
      />
    </div>

    <!-- Add/Edit dialog -->
    <NModal v-model:show="showEditor" preset="card" :title="editingRecord ? '编辑记录' : '添加记录'" :style="{ width: '480px' }">
      <div class="space-y-3">
        <NFormItem label="类型" :show-feedback="false">
          <NSelect v-model:value="formType" :options="RECORD_TYPES.map(t => ({ label: t, value: t }))" :disabled="!!editingRecord" size="small" />
        </NFormItem>
        <NFormItem label="主机记录" :show-feedback="false">
          <NInput v-model:value="formHost" :placeholder="`记录名.${siteName}`" :disabled="!!editingRecord" size="small" />
        </NFormItem>
        <NFormItem label="记录值" :show-feedback="false">
          <NInput v-model:value="formValue" placeholder="记录值" size="small" />
        </NFormItem>
        <div class="grid grid-cols-2 gap-4">
          <NFormItem label="TTL" :show-feedback="false">
            <NInput v-model:value="formTTL" type="number" size="small" />
          </NFormItem>
          <NFormItem label="代理" :show-feedback="false">
            <NSwitch v-model:value="formProxied" />
          </NFormItem>
        </div>
        <NFormItem label="备注" :show-feedback="false">
          <NInput v-model:value="formComment" size="small" />
        </NFormItem>
        <div class="flex justify-end gap-4">
          <NButton @click="showEditor = false">取消</NButton>
          <NButton type="primary" :loading="createMutation.isPending.value || updateMutation.isPending.value" @click="handleSave">
            {{ editingRecord ? '更新' : '添加' }}
          </NButton>
        </div>
      </div>
    </NModal>

    <!-- Certificate dialog -->
    <NModal v-model:show="showHttps" preset="card" title="HTTPS 证书管理" :style="{ width: '480px' }">
      <div class="space-y-3">
        <p class="text-sm text-slate-400">为 <code class="text-accent">{{ selectedRecordForCert }}</code> 申请证书</p>
        <NButton
          type="primary"
          size="small"
          :loading="applyCertMutation.isPending.value"
          @click="selectedRecordForCert && applyCertMutation.mutate([selectedRecordForCert])"
        >申请免费证书</NButton>
        <div class="flex justify-end">
          <NButton @click="showHttps = false">关闭</NButton>
        </div>
      </div>
    </NModal>
  </div>
</template>
