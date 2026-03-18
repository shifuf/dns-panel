import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { useProviderStore } from '@/stores/provider';

export function useCredentialResolver() {
  const route = useRoute();
  const providerStore = useProviderStore();

  const credentialId = computed<number | undefined>(() => {
    const q = route.query.credentialId;
    if (q) {
      const parsed = parseInt(String(q), 10);
      if (Number.isFinite(parsed)) return parsed;
    }

    const sel = providerStore.selectedCredentialId;
    if (typeof sel === 'number' && Number.isFinite(sel)) return sel;

    return undefined;
  });

  return { credentialId };
}
