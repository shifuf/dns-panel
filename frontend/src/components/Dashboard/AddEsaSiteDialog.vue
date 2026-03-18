<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { NModal, NInput, NButton, NSelect, NAlert, NSpin } from 'naive-ui';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { createEsaSite, listEsaRatePlanInstances, ESA_SUPPORTED_REGIONS } from '@/services/aliyunEsa';
import type { EsaRatePlanInstance } from '@/services/aliyunEsa';
import type { DnsCredential } from '@/types/dns';

const props = defineProps<{
  show: boolean;
  credentials: DnsCredential[];
  initialCredentialId?: number;
}>();

const emit = defineEmits<{ 'update:show': [val: boolean] }>();

const queryClient = useQueryClient();
const credentialId = ref<number | null>(null);
const siteName = ref('');
const accessType = ref('NS');
const coverage = ref('overseas');
const instanceId = ref<string | null>(null);
const submitError = ref('');
const createdResult = ref<{ siteId: string; verifyCode?: string; nameServerList?: string } | null>(null);

const coverageOptions = [
  { label: '海外', value: 'overseas' },
  { label: '国内', value: 'domestic' },
  { label: '全球', value: 'global' },
];
const accessTypeOptions = [
  { label: 'NS 接入', value: 'NS' },
  { label: 'CNAME 接入', value: 'CNAME' },
];
const credentialOptions = computed(() => props.credentials.map(c => ({ label: c.name, value: c.id })));

watch(() => props.show, (open) => {
  if (open) {
    credentialId.value = props.initialCredentialId ?? props.credentials[0]?.id ?? null;
    siteName.value = '';
    accessType.value = 'NS';
    coverage.value = 'overseas';
    instanceId.value = null;
    submitError.value = '';
    createdResult.value = null;
  }
});

const { data: instancesData, isLoading: loadingInstances } = useQuery({
  queryKey: computed(() => ['esa-instances', credentialId.value]),
  queryFn: async () => {
    if (!credentialId.value) return [];
    const all: EsaRatePlanInstance[] = [];
    const seen = new Set<string>();
    for (const region of ESA_SUPPORTED_REGIONS) {
      const res = await listEsaRatePlanInstances({ credentialId: credentialId.value, region, checkRemainingSiteQuota: true });
      for (const inst of res.data?.instances || []) {
        if (!seen.has(inst.instanceId)) { seen.add(inst.instanceId); all.push(inst); }
      }
    }
    return all;
  },
  enabled: computed(() => props.show && !!credentialId.value),
});

const instanceOptions = computed(() =>
  (instancesData.value || [])
    .filter(i => (i.siteQuota || 0) - (i.usedSiteCount || 0) > 0)
    .map(i => ({
      label: `${i.planName || i.instanceId} (${i.usedSiteCount}/${i.siteQuota})`,
      value: i.instanceId,
    }))
);

const mutation = useMutation({
  mutationFn: () => {
    if (!credentialId.value || !siteName.value || !instanceId.value) throw new Error('请填写完整');
    const inst = instancesData.value?.find(i => i.instanceId === instanceId.value);
    return createEsaSite({
      credentialId: credentialId.value,
      siteName: siteName.value,
      coverage: coverage.value,
      accessType: accessType.value,
      instanceId: instanceId.value,
      region: inst?.region,
    });
  },
  onSuccess: (res) => {
    createdResult.value = res.data || null;
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
    title="添加 ESA 站点"
    :style="{ width: '520px' }"
    :mask-closable="!mutation.isPending.value"
    @update:show="emit('update:show', $event)"
  >
    <template v-if="!createdResult">
      <div class="space-y-4">
        <NSelect v-if="credentialOptions.length > 1" v-model:value="credentialId" :options="credentialOptions" placeholder="选择账户" size="small" />
        <NInput v-model:value="siteName" placeholder="站点域名 (如 example.com)" />
        <div class="grid grid-cols-2 gap-3">
          <NSelect v-model:value="accessType" :options="accessTypeOptions" />
          <NSelect v-model:value="coverage" :options="coverageOptions" />
        </div>
        <NSpin v-if="loadingInstances" size="small" class="block mx-auto" />
        <NSelect v-else v-model:value="instanceId" :options="instanceOptions" placeholder="选择实例" />
        <NAlert v-if="submitError" type="error" :bordered="false">{{ submitError }}</NAlert>
        <div class="flex justify-end gap-4">
          <NButton @click="close">取消</NButton>
          <NButton type="primary" :loading="mutation.isPending.value" @click="mutation.mutate()">创建</NButton>
        </div>
      </div>
    </template>
    <template v-else>
      <div class="space-y-3">
        <p class="text-sm text-status-success">站点创建成功</p>
        <div v-if="createdResult.nameServerList" class="rounded-xl bg-panel-bg p-3 font-mono text-sm text-slate-600">
          {{ createdResult.nameServerList }}
        </div>
        <div v-if="createdResult.verifyCode" class="text-sm text-slate-400">
          验证码: <code class="text-accent">{{ createdResult.verifyCode }}</code>
        </div>
        <div class="flex justify-end">
          <NButton type="primary" @click="close">完成</NButton>
        </div>
      </div>
    </template>
  </NModal>
</template>
