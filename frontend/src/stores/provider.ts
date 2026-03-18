import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import type { ProviderType, ProviderConfig, DnsCredential, ProviderCapabilities } from '@/types/dns';
import { getProviders, getDnsCredentials } from '@/services/dnsCredentials';
import { normalizeProviderType } from '@/utils/provider';

const STORAGE_KEY_PROVIDER = 'dns_selected_provider';
const STORAGE_KEY_CREDENTIAL = 'dns_selected_credential';
const CACHE_KEY_PROVIDERS = 'dns_cached_providers';
const CACHE_KEY_CREDENTIALS = 'dns_cached_credentials';

function readCache<T>(key: string): T[] {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export const useProviderStore = defineStore('provider', () => {
  const cachedProviders = readCache<ProviderConfig>(CACHE_KEY_PROVIDERS);
  const cachedCredentials = readCache<DnsCredential>(CACHE_KEY_CREDENTIALS);

  const providers = ref<ProviderConfig[]>(cachedProviders);
  const credentials = ref<DnsCredential[]>(cachedCredentials);
  const selectedProvider = ref<ProviderType | null>(null);
  const selectedCredentialId = ref<number | 'all' | null>(null);
  const isLoading = ref(cachedProviders.length === 0);
  const error = ref<string | null>(null);

  // Synchronous rehydration from localStorage when cache exists
  if (cachedCredentials.length > 0) {
    const savedProviderRaw = localStorage.getItem(STORAGE_KEY_PROVIDER);

    // Empty string = explicit "no provider" (dashboard / SSL page)
    if (savedProviderRaw === '') {
      selectedProvider.value = null;
      selectedCredentialId.value = null;
    } else {
    const savedProvider = savedProviderRaw ? normalizeProviderType(savedProviderRaw as ProviderType) : null;
    const savedCredential = localStorage.getItem(STORAGE_KEY_CREDENTIAL);

    const providersWithCreds = [...new Set(cachedCredentials.map(c => normalizeProviderType(c.provider)))];

    const providerToSelect = (savedProvider && providersWithCreds.includes(savedProvider))
      ? savedProvider
      : (providersWithCreds.length > 0 ? providersWithCreds[0] : null);

    selectedProvider.value = providerToSelect;

    const credsForProvider = providerToSelect
      ? cachedCredentials.filter(c => normalizeProviderType(c.provider) === providerToSelect)
      : [];

    if (savedCredential === 'all') {
      selectedCredentialId.value = 'all';
    } else if (savedCredential) {
      const savedId = parseInt(savedCredential);
      if (credsForProvider.some(c => c.id === savedId)) {
        selectedCredentialId.value = savedId;
      } else {
        selectedCredentialId.value = credsForProvider.length > 1 ? 'all' : credsForProvider.length === 1 ? credsForProvider[0].id : 'all';
      }
    } else {
      selectedCredentialId.value = credsForProvider.length > 1 ? 'all' : credsForProvider.length === 1 ? credsForProvider[0].id : 'all';
    }
    } // end else (non-empty savedProviderRaw)
  }

  const getCredentialsByProvider = computed(() => {
    return (provider: ProviderType) => {
      const p = normalizeProviderType(provider);
      return credentials.value.filter(c => normalizeProviderType(c.provider) === p);
    };
  });

  const getCredentialCountByProvider = computed(() => {
    return (provider: ProviderType) => {
      const p = normalizeProviderType(provider);
      return credentials.value.filter(c => normalizeProviderType(c.provider) === p).length;
    };
  });

  const getProviderCapabilities = computed(() => {
    return (provider?: ProviderType | null): ProviderCapabilities | null => {
      const raw = provider ?? selectedProvider.value;
      const p = raw ? normalizeProviderType(raw) : null;
      if (!p) return null;
      const config = providers.value.find(c => c.type === p);
      return config?.capabilities ?? null;
    };
  });

  const currentCapabilities = computed(() => getProviderCapabilities.value(selectedProvider.value));

  async function loadData() {
    try {
      const hasCache = providers.value.length > 0;
      if (!hasCache) isLoading.value = true;
      error.value = null;

      const [provsRes, credsRes] = await Promise.all([
        getProviders(),
        getDnsCredentials(),
      ]);

      const providerList = (provsRes.data?.providers || [])
        .map((p) => ({
          ...p,
          type: normalizeProviderType(p.type),
        }))
        .filter((p, index, self) =>
          index === self.findIndex((t) => t.type === p.type)
        );
      const credentialList = (credsRes.data?.credentials || []).map((c) => ({
        ...c,
        provider: normalizeProviderType(c.provider),
      }));

      providers.value = providerList;
      credentials.value = credentialList;

      // Persist to localStorage for next session's instant render
      try {
        localStorage.setItem(CACHE_KEY_PROVIDERS, JSON.stringify(providerList));
        localStorage.setItem(CACHE_KEY_CREDENTIALS, JSON.stringify(credentialList));
      } catch { /* quota exceeded – non-critical */ }

      if (credentialList.length > 0) {
        const savedProviderRaw = localStorage.getItem(STORAGE_KEY_PROVIDER);

        // Empty string = explicit "no provider" (dashboard / SSL page) — preserve it
        if (savedProviderRaw === '') {
          selectedProvider.value = null;
          selectedCredentialId.value = null;
        } else {
        const savedProvider = savedProviderRaw ? normalizeProviderType(savedProviderRaw as ProviderType) : null;
        const savedCredential = localStorage.getItem(STORAGE_KEY_CREDENTIAL);

        const providersWithCreds = [...new Set(credentialList.map(c => normalizeProviderType(c.provider)))];

        const providerToSelect = (savedProvider && providersWithCreds.includes(savedProvider))
          ? savedProvider
          : (providersWithCreds.length > 0 ? providersWithCreds[0] : null);

        selectedProvider.value = providerToSelect;
        if (providerToSelect) {
          localStorage.setItem(STORAGE_KEY_PROVIDER, providerToSelect);
        }

        const credsForProvider = providerToSelect
          ? credentialList.filter(c => normalizeProviderType(c.provider) === providerToSelect)
          : [];

        let nextCredential: number | 'all' | null = null;

        if (savedCredential === 'all') {
          nextCredential = 'all';
        } else if (savedCredential) {
          const savedId = parseInt(savedCredential);
          if (credsForProvider.some(c => c.id === savedId)) {
            nextCredential = savedId;
          }
        }

        if (nextCredential === null) {
          nextCredential = credsForProvider.length > 1
            ? 'all'
            : credsForProvider.length === 1
              ? credsForProvider[0].id
              : 'all';
        }

        selectedCredentialId.value = nextCredential;
        if (nextCredential !== null) {
          localStorage.setItem(STORAGE_KEY_CREDENTIAL, String(nextCredential));
        }
        } // end else (non-empty savedProviderRaw)
      } else {
        selectedProvider.value = null;
        selectedCredentialId.value = null;
        localStorage.removeItem(STORAGE_KEY_PROVIDER);
        localStorage.removeItem(STORAGE_KEY_CREDENTIAL);
      }
    } catch (err: any) {
      error.value = err?.message || '加载数据失败';
    } finally {
      isLoading.value = false;
    }
  }

  function selectProvider(provider: ProviderType | null) {
    if (provider === null) {
      selectedProvider.value = null;
      selectedCredentialId.value = null;
      localStorage.setItem(STORAGE_KEY_PROVIDER, '');
      localStorage.setItem(STORAGE_KEY_CREDENTIAL, '');
      return;
    }

    const normalizedProvider = normalizeProviderType(provider);
    const credsForProvider = credentials.value.filter(c => normalizeProviderType(c.provider) === normalizedProvider);
    const nextCredential: number | 'all' = credsForProvider.length > 1
      ? 'all'
      : credsForProvider.length === 1
        ? credsForProvider[0].id
        : 'all';

    selectedProvider.value = normalizedProvider;
    selectedCredentialId.value = nextCredential;
    localStorage.setItem(STORAGE_KEY_PROVIDER, normalizedProvider);
    localStorage.setItem(STORAGE_KEY_CREDENTIAL, String(nextCredential));
  }

  function selectCredential(id: number | 'all') {
    const normalized = typeof id === 'string' && id !== 'all' ? parseInt(id, 10) : id;
    if (normalized === 'all') {
      selectedCredentialId.value = 'all';
      localStorage.setItem(STORAGE_KEY_CREDENTIAL, 'all');
      return;
    }
    if (!Number.isFinite(normalized)) return;

    selectedCredentialId.value = normalized;
    localStorage.setItem(STORAGE_KEY_CREDENTIAL, String(normalized));
  }

  return {
    providers,
    credentials,
    selectedProvider,
    selectedCredentialId,
    isLoading,
    error,
    loadData,
    selectProvider,
    selectCredential,
    getCredentialsByProvider,
    getCredentialCountByProvider,
    getProviderCapabilities,
    currentCapabilities,
  };
});
