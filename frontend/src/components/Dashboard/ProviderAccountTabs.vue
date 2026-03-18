<script setup lang="ts">
import { computed } from 'vue';
import { NSkeleton } from 'naive-ui';
import { useProviderStore } from '@/stores/provider';

const props = defineProps<{
  mode: 'provider' | 'all';
}>();

const providerStore = useProviderStore();

const tabs = computed(() => {
  const list: Array<{ key: string; label: string }> = [{ key: 'all', label: '全部账户' }];

  if (props.mode === 'provider' && providerStore.selectedProvider) {
    const creds = providerStore.getCredentialsByProvider(providerStore.selectedProvider);
    creds.forEach(c => list.push({ key: String(c.id), label: c.name }));
  } else {
    providerStore.credentials.forEach(c => list.push({ key: String(c.id), label: c.name }));
  }
  return list;
});

const activeTab = computed(() => String(providerStore.selectedCredentialId ?? 'all'));

function handleChange(key: string) {
  if (key === 'all') {
    providerStore.selectCredential('all');
    return;
  }
  const parsed = parseInt(key, 10);
  if (!Number.isFinite(parsed)) return;
  providerStore.selectCredential(parsed);
}
</script>

<template>
  <div v-if="providerStore.isLoading" class="mb-4">
    <NSkeleton height="42px" :sharp="false" class="rounded-lg" />
  </div>
  <div v-else-if="tabs.length > 2" class="mb-4 panel-muted p-3">
    <div class="flex flex-wrap gap-4">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        class="rounded-xl border px-3 py-2 text-xs font-semibold transition-colors"
        :class="tab.key === activeTab
          ? 'border-[#bdd2ef] bg-[#e7f1fd] text-[#2f6fbd]'
          : 'border-transparent bg-transparent text-slate-500 hover:bg-panel-surface hover:text-slate-700'"
        @click="handleChange(tab.key)"
      >
        {{ tab.label }}
      </button>
    </div>
  </div>
</template>
