<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { NModal, NInput, NButton, NAlert, NSpin } from 'naive-ui';
import { Eye, EyeOff, Plus } from 'lucide-vue-next';
import { getProviders, createDnsCredential } from '@/services/dnsCredentials';
import { useProviderStore } from '@/stores/provider';
import { normalizeProviderType } from '@/utils/provider';
import type { ProviderConfig, ProviderType } from '@/types/dns';
import ProviderSelector from '@/components/Settings/ProviderSelector.vue';

const props = defineProps<{
  show: boolean;
  presetProvider?: ProviderType | null;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
  created: [];
}>();

const providerStore = useProviderStore();

const providers = ref<ProviderConfig[]>([]);
const loadingProviders = ref(false);
const submitting = ref(false);
const submitError = ref('');

const formName = ref('');
const formProvider = ref<ProviderType>('cloudflare');
const formSecrets = ref<Record<string, string>>({});
const showSecretFields = ref<Record<string, boolean>>({});

const selectedProviderConfig = computed(() =>
  providers.value.find((p) => p.type === formProvider.value)
);

const visibleProviders = computed(() =>
  providers.value.filter((p) => p.type !== 'dnspod_token')
);

function mergeProviders(list: ProviderConfig[]): ProviderConfig[] {
  const map = new Map<ProviderType, ProviderConfig>();

  for (const item of list) {
    const type = normalizeProviderType(item.type);
    const normalized: ProviderConfig = { ...item, type };
    const existing = map.get(type);
    if (!existing) {
      map.set(type, normalized);
      continue;
    }

    const fieldByKey = new Map<string, ProviderConfig['authFields'][number]>();
    [...(existing.authFields || []), ...(normalized.authFields || [])].forEach((field) => {
      if (!fieldByKey.has(field.key)) fieldByKey.set(field.key, field);
    });

    const preferNewName = /token/i.test(existing.name || '') && !/token/i.test(normalized.name || '');
    map.set(type, {
      ...existing,
      name: preferNewName ? normalized.name : existing.name,
      authFields: Array.from(fieldByKey.values()),
      capabilities: existing.capabilities || normalized.capabilities,
    });
  }

  return Array.from(map.values());
}

async function loadProviders() {
  if (providers.value.length > 0) return;
  loadingProviders.value = true;
  submitError.value = '';
  try {
    const res = await getProviders();
    providers.value = mergeProviders(res.data?.providers || []);
  } catch (err: any) {
    submitError.value = String(err);
  } finally {
    loadingProviders.value = false;
  }
}

function resetForm() {
  formName.value = '';
  formSecrets.value = {};
  showSecretFields.value = {};
  submitError.value = '';
  const preset = props.presetProvider ? normalizeProviderType(props.presetProvider) : null;
  if (preset && visibleProviders.value.some((p) => p.type === preset)) {
    formProvider.value = preset;
    return;
  }
  formProvider.value = visibleProviders.value[0]?.type || 'cloudflare';
}

watch(
  () => props.show,
  async (open) => {
    if (!open) return;
    await loadProviders();
    resetForm();
  }
);

watch(
  () => formProvider.value,
  () => {
    formSecrets.value = {};
    showSecretFields.value = {};
  }
);

function close() {
  emit('update:show', false);
}

function toggleSecretVisibility(key: string) {
  showSecretFields.value = {
    ...showSecretFields.value,
    [key]: !showSecretFields.value[key],
  };
}

async function handleSubmit() {
  if (!formName.value.trim()) {
    submitError.value = '请输入账户别名';
    return;
  }
  const secrets = { ...formSecrets.value };
  Object.keys(secrets).forEach((k) => {
    if (!secrets[k]) delete secrets[k];
  });

  if (formProvider.value === 'dnspod') {
    const hasTC3 = Boolean(secrets.secretId && secrets.secretKey);
    const hasTC3Partial = Boolean(secrets.secretId || secrets.secretKey);
    const hasLegacy = Boolean(
      (secrets.tokenId && secrets.token) ||
      (!secrets.tokenId && secrets.token && String(secrets.token).includes(','))
    );
    const hasLegacyPartial = Boolean(secrets.tokenId || secrets.token);

    if (!hasTC3 && !hasLegacy) {
      submitError.value = '请填写 SecretId/SecretKey 或 DNSPod Token（二选一）';
      return;
    }
    if (hasTC3Partial && !hasTC3) {
      submitError.value = 'SecretId/SecretKey 需同时填写';
      return;
    }
    if (hasLegacyPartial && !hasLegacy) {
      submitError.value = 'DNSPod Token 请填写 ID + Token 或组合格式 ID,Token';
      return;
    }
  }

  submitting.value = true;
  submitError.value = '';
  try {
    await createDnsCredential({
      name: formName.value.trim(),
      provider: formProvider.value,
      secrets,
    });
    await providerStore.loadData();
    emit('created');
    close();
  } catch (err: any) {
    submitError.value = String(err);
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="添加 DNS 账户"
    :style="{ width: '640px' }"
    :mask-closable="!submitting"
    @update:show="emit('update:show', $event)"
  >
    <div class="space-y-4">
      <NAlert v-if="submitError" type="error" :bordered="false">{{ submitError }}</NAlert>

      <NSpin v-if="loadingProviders" class="py-4" />

      <template v-else>
        <div>
          <label class="mb-1 block text-sm text-slate-500">账户别名</label>
          <NInput v-model:value="formName" size="small" placeholder="例如：公司主账号" />
        </div>

        <div>
          <label class="mb-2 block text-sm text-slate-500">选择服务商</label>
          <ProviderSelector
            :providers="visibleProviders"
            :selected-provider="formProvider"
            @select="formProvider = $event"
          />
        </div>

        <div v-if="selectedProviderConfig" class="rounded-xl border border-panel-border bg-panel-bg p-3">
          <p class="mb-2 text-sm font-semibold text-accent">{{ selectedProviderConfig.name }} 认证信息</p>
          <div class="space-y-4">
            <div v-for="field in selectedProviderConfig.authFields" :key="field.key">
              <label class="mb-0.5 block text-xs text-slate-500">{{ field.label }}</label>
              <NInput
                :value="formSecrets[field.key] || ''"
                :type="field.type === 'password' && !showSecretFields[field.key] ? 'password' : 'text'"
                :placeholder="field.placeholder"
                size="small"
                @update:value="(val: string) => { formSecrets = { ...formSecrets, [field.key]: val }; }"
              >
                <template v-if="field.type === 'password'" #suffix>
                  <button
                    type="button"
                    class="p-0.5 text-slate-500 transition-colors hover:text-slate-700"
                    @click="toggleSecretVisibility(field.key)"
                  >
                    <EyeOff v-if="showSecretFields[field.key]" :size="14" />
                    <Eye v-else :size="14" />
                  </button>
                </template>
              </NInput>
              <p v-if="field.helpText" class="mt-0.5 text-xs text-slate-500">{{ field.helpText }}</p>
            </div>
          </div>
        </div>

        <div class="flex justify-end gap-4 pt-1">
          <NButton size="small" @click="close">取消</NButton>
          <NButton size="small" type="primary" :loading="submitting" @click="handleSubmit">
            <template #icon><Plus :size="14" /></template>
            添加账户
          </NButton>
        </div>
      </template>
    </div>
  </NModal>
</template>
