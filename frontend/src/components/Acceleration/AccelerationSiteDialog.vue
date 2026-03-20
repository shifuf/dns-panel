<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NAlert, NButton, NFormItem, NInput, NModal, NSelect } from 'naive-ui';
import type { Domain } from '@/types';
import type { DnsCredential } from '@/types/dns';
import type { AccelerationConfigInput, DomainAccelerationConfig } from '@/services/accelerations';

type SubmitPayload = AccelerationConfigInput & {
  zoneName: string;
  dnsCredentialId: number;
  pluginCredentialId: number;
};

const props = defineProps<{
  show: boolean;
  loading?: boolean;
  mode?: 'create' | 'edit';
  domains: Domain[];
  accelerationCredentials: DnsCredential[];
  value?: (Partial<DomainAccelerationConfig> & {
    zoneName?: string;
    dnsCredentialId?: number | null;
    pluginCredentialId?: number | null;
  }) | null;
  lockDomain?: boolean;
  lockPluginCredential?: boolean;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
  submit: [value: SubmitPayload];
}>();

const form = ref<{
  domainKey: string;
  zoneName: string;
  dnsCredentialId: number | null;
  pluginCredentialId: number | null;
  subDomain: string;
  originType: string;
  originValue: string;
  backupOriginValue: string;
  hostHeader: string;
  originProtocol: string;
  httpOriginPort: number;
  httpsOriginPort: number;
  ipv6Status: string;
}>({
  domainKey: '',
  zoneName: '',
  dnsCredentialId: null,
  pluginCredentialId: null,
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

const domainOptions = computed(() =>
  props.domains.map((domain) => ({
    label: `${domain.name} / ${domain.credentialName || `DNS #${domain.credentialId || '-'}`}`,
    value: `${domain.credentialId || 0}::${domain.name}`,
    domain,
  })),
);

const selectedDomain = computed(() =>
  domainOptions.value.find((item) => item.value === form.value.domainKey)?.domain
    || props.domains.find((domain) =>
      String(domain.name || '').trim().toLowerCase() === String(form.value.zoneName || '').trim().toLowerCase()
      && Number(domain.credentialId || 0) === Number(form.value.dnsCredentialId || 0),
    )
    || null,
);

const accelerationDomainPreview = computed(() => {
  const zone = String(form.value.zoneName || '').trim().toLowerCase();
  const sub = String(form.value.subDomain || '@').trim().toLowerCase();
  if (!zone) return '';
  if (!sub || sub === '@') return zone;
  if (sub.endsWith(`.${zone}`)) return sub;
  return `${sub}.${zone}`;
});

function buildDomainKey(zoneName: string | undefined, dnsCredentialId: number | null | undefined) {
  const zone = String(zoneName || '').trim();
  const dnsId = Number(dnsCredentialId || 0);
  return zone && dnsId > 0 ? `${dnsId}::${zone}` : '';
}

function resetForm() {
  const defaultDomain = props.domains[0] || null;
  const defaultAccelerationCredential = props.accelerationCredentials[0] || null;
  const zoneName = String(props.value?.zoneName || defaultDomain?.name || '').trim();
  const dnsCredentialId = Number(props.value?.dnsCredentialId || defaultDomain?.credentialId || 0) || null;
  const pluginCredentialId = Number(props.value?.pluginCredentialId || defaultAccelerationCredential?.id || 0) || null;
  form.value = {
    domainKey: buildDomainKey(zoneName, dnsCredentialId),
    zoneName,
    dnsCredentialId,
    pluginCredentialId,
    subDomain: String(props.value?.subDomain || '@').trim() || '@',
    originType: String(props.value?.originType || 'IP_DOMAIN').trim() || 'IP_DOMAIN',
    originValue: String(props.value?.originValue || '').trim(),
    backupOriginValue: String(props.value?.backupOriginValue || '').trim(),
    hostHeader: String(props.value?.hostHeader || '').trim(),
    originProtocol: String(props.value?.originProtocol || 'FOLLOW').trim() || 'FOLLOW',
    httpOriginPort: Number(props.value?.httpOriginPort || 80) || 80,
    httpsOriginPort: Number(props.value?.httpsOriginPort || 443) || 443,
    ipv6Status: String(props.value?.ipv6Status || 'follow').trim() || 'follow',
  };
  errorText.value = '';
}

watch(() => props.show, (show) => {
  if (show) resetForm();
});

watch(() => props.value, () => {
  if (props.show) resetForm();
});

watch(() => form.value.domainKey, (value) => {
  const selected = domainOptions.value.find((item) => item.value === value)?.domain;
  if (!selected) return;
  form.value.zoneName = String(selected.name || '').trim();
  form.value.dnsCredentialId = Number(selected.credentialId || 0) || null;
});

function handleSubmit() {
  if (!String(form.value.zoneName || '').trim() || !form.value.dnsCredentialId) {
    errorText.value = '请选择要接入加速的域名';
    return;
  }
  if (!form.value.pluginCredentialId) {
    errorText.value = '请选择加速账户';
    return;
  }
  if (!String(form.value.originValue || '').trim()) {
    errorText.value = '请输入源站地址';
    return;
  }
  errorText.value = '';
  emit('submit', {
    zoneName: String(form.value.zoneName || '').trim(),
    dnsCredentialId: Number(form.value.dnsCredentialId),
    pluginCredentialId: Number(form.value.pluginCredentialId),
    accelerationDomain: accelerationDomainPreview.value,
    subDomain: String(form.value.subDomain || '@').trim() || '@',
    originType: String(form.value.originType || 'IP_DOMAIN').trim() || 'IP_DOMAIN',
    originValue: String(form.value.originValue || '').trim(),
    backupOriginValue: String(form.value.backupOriginValue || '').trim(),
    hostHeader: String(form.value.hostHeader || '').trim(),
    originProtocol: String(form.value.originProtocol || 'FOLLOW').trim() || 'FOLLOW',
    httpOriginPort: Number(form.value.httpOriginPort || 80) || 80,
    httpsOriginPort: Number(form.value.httpsOriginPort || 443) || 443,
    ipv6Status: String(form.value.ipv6Status || 'follow').trim() || 'follow',
  });
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    :title="mode === 'edit' ? '编辑加速配置' : '新增加速域名'"
    :style="{ width: 'min(94vw, 860px)' }"
    :mask-closable="!loading"
    @update:show="emit('update:show', $event)"
  >
    <div class="space-y-4">
      <NAlert v-if="errorText" type="error" :bordered="false">
        {{ errorText }}
      </NAlert>

      <div class="grid gap-4 md:grid-cols-2">
        <NFormItem label="域名" :show-feedback="false">
          <NSelect
            v-model:value="form.domainKey"
            filterable
            :disabled="lockDomain"
            :options="domainOptions"
            placeholder="选择 DNS 域名"
          />
        </NFormItem>
        <NFormItem label="加速账户" :show-feedback="false">
          <NSelect
            v-model:value="form.pluginCredentialId"
            filterable
            :disabled="lockPluginCredential"
            :options="accelerationCredentials.map((item) => ({ label: item.name, value: item.id }))"
            placeholder="选择 EdgeOne 账户"
          />
        </NFormItem>
      </div>

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
        保存后会自动创建或更新当前域名的 EdgeOne 加速配置；如果尚未生效，系统会继续返回验证记录，供自动或手动补录。
      </div>

      <div class="flex justify-end gap-3">
        <NButton :disabled="loading" @click="emit('update:show', false)">取消</NButton>
        <NButton type="primary" :loading="loading" @click="handleSubmit">
          {{ mode === 'edit' ? '保存修改' : '创建加速' }}
        </NButton>
      </div>
    </div>
  </NModal>
</template>
