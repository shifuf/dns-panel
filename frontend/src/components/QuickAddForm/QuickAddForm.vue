<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { NModal, NForm, NFormItem, NInput, NSelect, NSwitch, NButton, NCollapse, NCollapseItem } from 'naive-ui';
import { useProviderStore } from '@/stores/provider';
import { validateDNSContent } from '@/utils/validators';
import { TTL_OPTIONS, DNS_RECORD_TYPES } from '@/utils/constants';
import type { DnsLine } from '@/types/dns';

const props = defineProps<{
  show: boolean;
  lines?: DnsLine[];
  minTtl?: number;
  loading?: boolean;
  showAccelerationToggle?: boolean;
  accelerationToggleLabel?: string;
}>();

const emit = defineEmits<{
  'update:show': [val: boolean];
  submit: [params: any];
}>();

const providerStore = useProviderStore();
const caps = computed(() => providerStore.currentCapabilities);
const isCloudflare = computed(() => providerStore.selectedProvider === 'cloudflare');

const form = ref({
  type: 'A',
  name: '',
  content: '',
  ttl: 1,
  proxied: false,
  priority: 10,
  weight: 0,
  line: '',
  remark: '',
  enableAcceleration: false,
});

const validationError = ref('');

watch(() => props.show, (open) => {
  if (open) {
    form.value = { type: 'A', name: '', content: '', ttl: 1, proxied: false, priority: 10, weight: 0, line: '', remark: '', enableAcceleration: false };
    validationError.value = '';
  }
});

const recordTypeOptions = computed(() => {
  const types = caps.value?.recordTypes || [...DNS_RECORD_TYPES];
  let allTypes = [...types];
  if (caps.value?.supportsUrlForward) {
    allTypes = [...allTypes, 'REDIRECT_URL', 'FORWARD_URL'];
  }
  const uniqueTypes = [...new Set(allTypes)];
  return uniqueTypes.map(t => ({ label: t, value: t }));
});

const ttlOptions = computed(() => {
  const min = props.minTtl || 1;
  const options = TTL_OPTIONS.filter(o => o.value >= min || o.value === 1);
  return options.map(o => ({ label: o.label, value: o.value }));
});

const lineOptions = computed(() => {
  if (!props.lines) return [];
  return props.lines.map(l => ({
    label: l.name,
    value: l.code,
  }));
});

const showPriority = computed(() => ['MX', 'SRV'].includes(form.value.type));

function handleSubmit() {
  if (!form.value.name.trim()) { validationError.value = '请输入记录名称'; return; }
  if (!form.value.content.trim()) { validationError.value = '请输入记录值'; return; }

  const contentErr = validateDNSContent(form.value.type, form.value.content);
  if (contentErr) { validationError.value = contentErr; return; }

  validationError.value = '';

  const params: any = {
    type: form.value.type,
    name: form.value.name,
    content: form.value.content,
    ttl: form.value.ttl,
  };

  if (isCloudflare.value && ['A', 'AAAA', 'CNAME'].includes(form.value.type)) {
    params.proxied = form.value.proxied;
  }
  if (showPriority.value) params.priority = form.value.priority;
  if (caps.value?.supportsWeight) params.weight = form.value.weight;
  if (caps.value?.supportsLine && form.value.line) params.line = form.value.line;
  if (caps.value?.supportsRemark && form.value.remark) params.remark = form.value.remark;
  if (props.showAccelerationToggle) params.enableAcceleration = Boolean(form.value.enableAcceleration);

  emit('submit', params);
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="添加 DNS 记录"
    :style="{ width: '520px' }"
    @update:show="emit('update:show', $event)"
  >
    <form @submit.prevent="handleSubmit">
      <div class="space-y-3">
        <div class="grid grid-cols-2 gap-3">
          <NFormItem label="类型" :show-feedback="false">
            <NSelect v-model:value="form.type" :options="recordTypeOptions" size="small" />
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
            <NInput v-model:value="form.priority" type="number" size="small" />
          </NFormItem>

          <NFormItem v-if="caps?.supportsWeight" label="权重" :show-feedback="false">
            <NInput v-model:value="form.weight" type="number" size="small" />
          </NFormItem>
        </div>

        <NFormItem v-if="isCloudflare && ['A', 'AAAA', 'CNAME'].includes(form.type)" label="代理" :show-feedback="false">
          <NSwitch v-model:value="form.proxied" />
        </NFormItem>

        <NFormItem v-if="caps?.supportsLine && lineOptions.length > 0" label="线路" :show-feedback="false">
          <NSelect v-model:value="form.line" :options="lineOptions" clearable size="small" />
        </NFormItem>

        <NCollapse v-if="caps?.supportsRemark">
          <NCollapseItem title="备注">
            <NInput v-model:value="form.remark" placeholder="备注信息" size="small" />
          </NCollapseItem>
        </NCollapse>

        <NFormItem v-if="showAccelerationToggle" :show-feedback="false">
          <div class="flex w-full items-center justify-between rounded-2xl border border-panel-border bg-panel-surface px-3 py-2">
            <div>
              <p class="text-sm font-medium text-slate-700">{{ accelerationToggleLabel || '创建后自动接入加速' }}</p>
              <p class="text-xs text-slate-500">保存记录后自动创建或接管当前域名的加速配置</p>
            </div>
            <NSwitch v-model:value="form.enableAcceleration" />
          </div>
        </NFormItem>

        <p v-if="validationError" class="text-red-400 text-sm">{{ validationError }}</p>

        <div class="flex justify-end gap-2 pt-2">
          <NButton @click="emit('update:show', false)">取消</NButton>
          <NButton type="primary" :loading="loading" attr-type="submit">添加</NButton>
        </div>
      </div>
    </form>
  </NModal>
</template>
