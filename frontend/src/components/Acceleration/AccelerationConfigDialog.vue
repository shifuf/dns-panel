<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NAlert, NButton, NFormItem, NInput, NModal, NSelect } from 'naive-ui';
import type { AccelerationConfigInput, DomainAccelerationConfig } from '@/services/accelerations';

const props = defineProps<{
  show: boolean;
  zoneName: string;
  loading?: boolean;
  value?: Partial<DomainAccelerationConfig> | null;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
  submit: [value: AccelerationConfigInput];
}>();

const form = ref<AccelerationConfigInput>({
  subDomain: '@',
  originType: 'IP_DOMAIN',
  originValue: '',
  backupOriginValue: '',
  hostHeader: '',
  originProtocol: 'FOLLOW',
  httpOriginPort: 80,
  httpsOriginPort: 443,
  ipv6Status: 'follow',
});
const errorText = ref('');

const accelerationDomainPreview = computed(() => {
  const zone = String(props.zoneName || '').trim().toLowerCase();
  const sub = String(form.value.subDomain || '@').trim().toLowerCase();
  if (!zone) return '';
  if (!sub || sub === '@') return zone;
  if (sub.endsWith(`.${zone}`)) return sub;
  return `${sub}.${zone}`;
});

function resetForm() {
  form.value = {
    subDomain: props.value?.subDomain || '@',
    accelerationDomain: props.value?.accelerationDomain || '',
    originType: props.value?.originType || 'IP_DOMAIN',
    originValue: props.value?.originValue || '',
    backupOriginValue: props.value?.backupOriginValue || '',
    hostHeader: props.value?.hostHeader || '',
    originProtocol: props.value?.originProtocol || 'FOLLOW',
    httpOriginPort: props.value?.httpOriginPort || 80,
    httpsOriginPort: props.value?.httpsOriginPort || 443,
    ipv6Status: props.value?.ipv6Status || 'follow',
  };
  errorText.value = '';
}

watch(() => props.show, (show) => {
  if (show) resetForm();
});

watch(() => props.value, () => {
  if (props.show) resetForm();
});

function handleSubmit() {
  if (!props.zoneName.trim()) {
    errorText.value = '缺少根域名';
    return;
  }
  if (!String(form.value.originValue || '').trim()) {
    errorText.value = '请输入源站地址';
    return;
  }
  errorText.value = '';
  emit('submit', {
    ...form.value,
    accelerationDomain: accelerationDomainPreview.value,
    subDomain: String(form.value.subDomain || '@').trim() || '@',
    originValue: String(form.value.originValue || '').trim(),
    backupOriginValue: String(form.value.backupOriginValue || '').trim(),
    hostHeader: String(form.value.hostHeader || '').trim(),
  });
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="加速配置"
    :style="{ width: 'min(92vw, 760px)' }"
    :mask-closable="!loading"
    @update:show="emit('update:show', $event)"
  >
    <div class="space-y-4">
      <NAlert v-if="errorText" type="error" :bordered="false">
        {{ errorText }}
      </NAlert>

      <div class="grid gap-4 md:grid-cols-2">
        <NFormItem label="子域名前缀" :show-feedback="false">
          <NInput v-model:value="form.subDomain" placeholder="@ / www / api" />
        </NFormItem>
        <NFormItem label="加速域名预览" :show-feedback="false">
          <NInput :value="accelerationDomainPreview" readonly />
        </NFormItem>
      </div>

      <div class="grid gap-4 md:grid-cols-2">
        <NFormItem label="源站类型" :show-feedback="false">
          <NSelect
            v-model:value="form.originType"
            :options="[
              { label: 'IP / 域名', value: 'IP_DOMAIN' },
              { label: '源站组', value: 'ORIGIN_GROUP' },
            ]"
          />
        </NFormItem>
        <NFormItem label="IPv6" :show-feedback="false">
          <NSelect
            v-model:value="form.ipv6Status"
            :options="[
              { label: '跟随系统', value: 'follow' },
              { label: '关闭', value: 'close' },
            ]"
          />
        </NFormItem>
      </div>

      <div class="grid gap-4 md:grid-cols-2">
        <NFormItem label="主源站" :show-feedback="false">
          <NInput v-model:value="form.originValue" placeholder="源站 IP 或域名" />
        </NFormItem>
        <NFormItem label="备用源站" :show-feedback="false">
          <NInput v-model:value="form.backupOriginValue" placeholder="可选" />
        </NFormItem>
      </div>

      <div class="grid gap-4 md:grid-cols-3">
        <NFormItem label="回源协议" :show-feedback="false">
          <NSelect
            v-model:value="form.originProtocol"
            :options="[
              { label: '跟随请求', value: 'FOLLOW' },
              { label: 'HTTP', value: 'HTTP' },
              { label: 'HTTPS', value: 'HTTPS' },
            ]"
          />
        </NFormItem>
        <NFormItem label="HTTP 端口" :show-feedback="false">
          <NInput v-model:value="form.httpOriginPort" type="number" placeholder="80" />
        </NFormItem>
        <NFormItem label="HTTPS 端口" :show-feedback="false">
          <NInput v-model:value="form.httpsOriginPort" type="number" placeholder="443" />
        </NFormItem>
      </div>

      <NFormItem label="Host Header" :show-feedback="false">
        <NInput v-model:value="form.hostHeader" placeholder="可选，不填则由 EdgeOne / 源站默认处理" />
      </NFormItem>

      <div class="rounded-2xl border border-panel-border bg-panel-surface px-4 py-3 text-xs text-slate-500">
        创建或更新后，系统会同步 EdgeOne 站点与加速域名配置；如果当前域名还未验证，会同时返回验证记录用于自动或手动补录。
      </div>

      <div class="flex justify-end gap-3">
        <NButton :disabled="loading" @click="emit('update:show', false)">取消</NButton>
        <NButton type="primary" :loading="loading" @click="handleSubmit">保存配置</NButton>
      </div>
    </div>
  </NModal>
</template>
