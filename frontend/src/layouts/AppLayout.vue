<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Menu, ChevronsRight } from 'lucide-vue-next';
import AppSidebar from '@/components/Sidebar/AppSidebar.vue';
import { useProviderStore } from '@/stores/provider';
import { useBreadcrumbStore } from '@/stores/breadcrumb';
import { useResponsive } from '@/composables/useResponsive';
import { getProviderDisplayName } from '@/utils/provider';

const providerStore = useProviderStore();
const breadcrumbStore = useBreadcrumbStore();
const { isMobile } = useResponsive();
const route = useRoute();
const router = useRouter();

const mobileOpen = ref(false);
const initializedRootDefault = ref(false);
providerStore.loadData();

watch(
  [() => route.path, () => route.query.scope, () => providerStore.isLoading],
  ([path, scope, loading]) => {
    if (loading) return;
    // First visit to "/" should default to overview, not persisted provider scope.
    if (!initializedRootDefault.value && path === '/' && scope === undefined) {
      if (providerStore.selectedProvider) providerStore.selectProvider(null);
      if (providerStore.selectedCredentialId !== 'all') providerStore.selectCredential('all');
      initializedRootDefault.value = true;
      return;
    }
    if (path !== '/') {
      initializedRootDefault.value = true;
    }
    // Route scope takes precedence: dashboard "?scope=all" always means global overview.
    if (path === '/' && scope === 'all' && providerStore.selectedProvider) {
      providerStore.selectProvider(null);
    }
  },
  { immediate: true }
);

watch(() => route.path, () => {
  window.scrollTo({ top: 0, behavior: isMobile.value ? 'instant' : 'smooth' });
});

watch(isMobile, (mobile) => {
  if (!mobile) mobileOpen.value = false;
});

const selectedProviderName = computed(() => {
  if (!providerStore.selectedProvider) return '';
  const mapped = getProviderDisplayName(providerStore.selectedProvider);
  const fromConfig = providerStore.providers.find((p) => p.type === providerStore.selectedProvider)?.name;
  return mapped || fromConfig || providerStore.selectedProvider;
});

const dashboardRootLabel = computed(() =>
  selectedProviderName.value ? `${selectedProviderName.value}域名管理` : '域名仪表盘'
);

const breadcrumbNameMap: Record<string, string> = {
  logs: '操作日志',
  settings: '设置中心',
  tunnels: 'Cloudflare Tunnel',
  ssl: 'SSL 证书管理',
  accelerations: '加速管理',
};

const breadcrumbs = computed(() => {
  const segments = route.path.split('/').filter(Boolean);
  const zoneParam = Array.isArray(route.params.zoneId)
    ? route.params.zoneId[0]
    : (route.params.zoneId as string | undefined);
  const items: Array<{ label: string; path?: string }> = [];

  if (segments.length === 0) {
    items.push({ label: dashboardRootLabel.value });
    return items;
  }

  if (segments[0] === 'settings') {
    items.push({ label: '设置中心' });
    return items;
  }

  items.push({ label: dashboardRootLabel.value, path: '/' });

  if (segments[0] === 'domain' && zoneParam) {
    const zoneId = zoneParam;
    const label = breadcrumbStore.labels[`zone:${zoneId}`] || zoneId;
    items.push({ label });
  } else if (segments[0] === 'hostnames' && zoneParam) {
    const zoneId = zoneParam;
    const zoneLabel = breadcrumbStore.labels[`zone:${zoneId}`] || zoneId;
    const query = route.query.credentialId ? `?credentialId=${route.query.credentialId}` : '';
    items.push({ label: zoneLabel, path: `/domain/${encodeURIComponent(zoneId)}${query}` });
    items.push({ label: '自定义 Hostname' });
  } else if (segments[0] === 'tunnels') {
    items.push({ label: 'Cloudflare Tunnel' });
  } else {
    const name = breadcrumbNameMap[segments[0]] || segments[0];
    items.push({ label: name });
  }

  return items;
});

const scopeHint = computed(() => {
  if (route.path.startsWith('/settings')) return '当前范围：全局设置';
  if (route.path.startsWith('/accelerations')) return '当前范围：加速管理';
  if (!providerStore.selectedProvider) return '当前范围：全部服务商';
  return `当前范围：${selectedProviderName.value || providerStore.selectedProvider}`;
});

function onSidebarClose() {
  mobileOpen.value = false;
}
</script>

<template>
  <div class="app-shell">
    <button
      class="mobile-menu-btn"
      @click="mobileOpen = true"
      aria-label="打开菜单"
    >
      <Menu :size="18" />
    </button>

    <div
      class="sidebar-backdrop"
      :class="{ 'is-open': mobileOpen }"
      @click="mobileOpen = false"
    />

    <aside
      class="sidebar-container"
      :class="{ 'is-open': mobileOpen }"
    >
      <AppSidebar @close="onSidebarClose" />
    </aside>

    <main class="app-main">
      <header class="app-topbar">
        <div class="flex min-w-0 flex-1 flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <nav class="flex min-w-0 items-center gap-4 text-sm">
            <template v-for="(item, i) in breadcrumbs" :key="i">
              <button
                v-if="item.path"
                class="truncate rounded-lg px-1 py-0.5 font-semibold text-slate-500 transition-colors hover:text-slate-700"
                @click="router.push(item.path)"
              >
                {{ item.label }}
              </button>
              <span v-else class="truncate font-semibold text-slate-700">{{ item.label }}</span>
              <ChevronsRight v-if="i < breadcrumbs.length - 1" :size="14" class="shrink-0 text-slate-400" />
            </template>
          </nav>
          <span class="inline-flex max-w-full rounded-xl border border-panel-border bg-panel-surface px-3 py-1 text-xs font-semibold text-slate-500 md:max-w-[40%]">
            {{ scopeHint }}
          </span>
        </div>
      </header>

      <section class="app-content bento-scroll-y">
        <router-view v-slot="{ Component }">
          <transition name="page-slide" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </section>
    </main>
  </div>
</template>

<style scoped>
.page-slide-enter-active,
.page-slide-leave-active {
  transition: all 180ms ease;
}

.page-slide-enter-from,
.page-slide-leave-to {
  transform: translateY(4px);
  opacity: 0;
}
</style>
