<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { NModal, NInput, NButton, NSelect, NAlert, NTag, NSpin, NDataTable } from 'naive-ui';
import { useQueryClient, useMutation } from '@tanstack/vue-query';
import { addZones } from '@/services/domains';
import type { DnsCredential } from '@/types/dns';
import type { AddZoneResult } from '@/services/domains';
import { h } from 'vue';

const props = defineProps<{
  show: boolean;
  credentials: DnsCredential[];
  initialCredentialId?: number;
  initialDomainsText?: string;
}>();

const emit = defineEmits<{ 'update:show': [val: boolean] }>();

const queryClient = useQueryClient();
const credentialId = ref<number | null>(null);
const domainsText = ref('');
const results = ref<AddZoneResult[] | null>(null);
const submitError = ref('');

watch(() => props.show, (open) => {
  if (open) {
    credentialId.value = props.initialCredentialId ?? props.credentials[0]?.id ?? null;
    domainsText.value = props.initialDomainsText ?? '';
    results.value = null;
    submitError.value = '';
  }
});

const credentialOptions = computed(() =>
  props.credentials.map(c => ({ label: c.name, value: c.id }))
);

function parseDomains(text: string): string[] {
  const seen = new Set<string>();
  return text
    .split(/[\s,;]+/)
    .map(s => s.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '').toLowerCase())
    .filter(s => {
      if (!s || seen.has(s)) return false;
      seen.add(s);
      return true;
    });
}

const mutation = useMutation({
  mutationFn: () => {
    if (!credentialId.value) throw new Error('请选择账户');
    const domains = parseDomains(domainsText.value);
    if (!domains.length) throw new Error('请输入域名');
    return addZones(credentialId.value, domains);
  },
  onSuccess: (res) => {
    results.value = res.data?.results || [];
    queryClient.invalidateQueries({ queryKey: ['domains'] });
  },
  onError: (err: any) => { submitError.value = String(err); },
});

function close() { emit('update:show', false); }
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="添加域名"
    :style="{ width: '560px' }"
    :mask-closable="!mutation.isPending.value"
    @update:show="emit('update:show', $event)"
  >
    <template v-if="!results">
      <div class="space-y-4">
        <NSelect
          v-if="credentialOptions.length > 1"
          v-model:value="credentialId"
          :options="credentialOptions"
          placeholder="选择账户"
          size="small"
        />

        <NInput
          v-model:value="domainsText"
          type="textarea"
          placeholder="输入域名，每行一个或用逗号分隔"
          :rows="6"
          :disabled="mutation.isPending.value"
        />

        <NAlert v-if="submitError" type="error" :bordered="false">{{ submitError }}</NAlert>

        <div class="flex justify-end gap-4">
          <NButton @click="close">取消</NButton>
          <NButton type="primary" :loading="mutation.isPending.value" @click="mutation.mutate()">
            添加
          </NButton>
        </div>
      </div>
    </template>

    <template v-else>
      <div class="space-y-3">
        <NDataTable
          :columns="[
            { title: '域名', key: 'domain' },
            { title: '状态', key: 'status', width: 100, render(row: AddZoneResult) { return h(NTag, { type: row.success ? 'success' : 'error', size: 'small', bordered: false }, () => row.success ? (row.existed ? '已存在' : '成功') : '失败'); } },
          ]"
          :data="results"
          :row-key="(r: AddZoneResult) => r.domain"
          :bordered="false"
          size="small"
          class="table-scrollable"
          :max-height="300"
          :scroll-x="380"
          :virtual-scroll="results.length > 120"
        />
        <div class="flex justify-end">
          <NButton type="primary" @click="close">完成</NButton>
        </div>
      </div>
    </template>
  </NModal>
</template>
