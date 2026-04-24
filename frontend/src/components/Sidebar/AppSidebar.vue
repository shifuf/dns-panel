<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { useDialog } from 'naive-ui';
import {
  Globe2, LayoutDashboard, History, Settings, LogOut, ShieldCheck, Moon, Sun, Rocket,
} from 'lucide-vue-next';
import { useTheme } from '@/composables/useTheme';
import { useProviderStore } from '@/stores/provider';
import { clearAuthData, getStoredUser } from '@/services/auth';
import type { ProviderType } from '@/types/dns';
import { normalizeProviderType } from '@/utils/provider';
import { useResponsive } from '@/composables/useResponsive';
import ProviderItem from './ProviderItem.vue';

const emit = defineEmits<{ close: [] }>();

const router = useRouter();
const route = useRoute();
const providerStore = useProviderStore();
const user = getStoredUser();
const dialog = useDialog();
const { isMobile } = useResponsive();
const { isDark, toggle: toggleTheme } = useTheme();

const PROVIDER_ORDER_KEY = 'dns-panel.sidebar.providerOrder.v1';

const sidebarProviders = computed(() => {
  const map = new Map<ProviderType, (typeof providerStore.providers)[number]>();
  providerStore.providers
    .filter((p) => (p.capabilities?.recordTypes?.length ?? 1) > 0)
    .forEach((p) => {
    const type = normalizeProviderType(p.type);
    const item = p.type === type ? p : { ...p, type };
    if (!map.has(type) || (type === 'dnspod' && p.type === 'dnspod')) {
      map.set(type, item);
    }
  });
  return Array.from(map.values());
});

const providerOrder = ref<ProviderType[]>([]);
const draggingType = ref<ProviderType | null>(null);
const longPressTimer = ref<number | null>(null);
const suppressClick = ref(false);
let rafId: number | null = null;

function readOrder(): ProviderType[] {
  try {
    const raw = localStorage.getItem(PROVIDER_ORDER_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeOrder(order: ProviderType[]) {
  try {
    localStorage.setItem(PROVIDER_ORDER_KEY, JSON.stringify(order));
  } catch {}
}

watch(sidebarProviders, (list) => {
  const types = list.map(p => p.type);
  if (!types.length) return;
  const saved = readOrder().filter(t => types.includes(t));
  const rest = types.filter(t => !saved.includes(t));
  providerOrder.value = [...saved, ...rest];
}, { immediate: true });

const sortedProviders = computed(() =>
  providerOrder.value
    .map(type => sidebarProviders.value.find(p => p.type === type))
    .filter((p): p is NonNullable<typeof p> => !!p),
);

function onProviderPointerDown(type: ProviderType) {
  if (isMobile.value) return;
  const timer = window.setTimeout(() => {
    draggingType.value = type;
    suppressClick.value = true;
  }, 260);
  longPressTimer.value = timer;
}

function onProviderPointerUp() {
  if (longPressTimer.value) {
    window.clearTimeout(longPressTimer.value);
    longPressTimer.value = null;
  }
  if (draggingType.value) {
    draggingType.value = null;
    if (rafId) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    setTimeout(() => { suppressClick.value = false; }, 0);
  }
}

function onProviderPointerMove(e: PointerEvent) {
  if (!draggingType.value) return;
  
  if (rafId) {
    cancelAnimationFrame(rafId);
  }
  
  rafId = requestAnimationFrame(() => {
    const el = document.elementFromPoint(e.clientX, e.clientY) as HTMLElement | null;
    const item = el?.closest?.('[data-provider-type]') as HTMLElement | null;
    const over = item?.getAttribute('data-provider-type') as ProviderType | null;
    if (!over || over === draggingType.value) return;

    const order = providerOrder.value;
    const from = order.indexOf(draggingType.value);
    const to = order.indexOf(over);
    if (from < 0 || to < 0 || from === to) return;

    const next = [...order];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    providerOrder.value = next;
    writeOrder(next);
  });
}

onMounted(() => {
  if (!isMobile.value) {
    window.addEventListener('pointermove', onProviderPointerMove);
    window.addEventListener('pointerup', onProviderPointerUp);
    window.addEventListener('pointercancel', onProviderPointerUp);
  }
});

onUnmounted(() => {
  if (!isMobile.value) {
    window.removeEventListener('pointermove', onProviderPointerMove);
    window.removeEventListener('pointerup', onProviderPointerUp);
    window.removeEventListener('pointercancel', onProviderPointerUp);
  }
  if (longPressTimer.value) {
    window.clearTimeout(longPressTimer.value);
  }
  if (rafId) {
    cancelAnimationFrame(rafId);
  }
});

function goToDashboard() {
  providerStore.selectProvider(null);
  navigate('/?scope=all');
}

function selectProvider(type: ProviderType) {
  if (suppressClick.value) return;
  providerStore.selectProvider(type);
  navigate('/');
}

function goToLogs() {
  navigate('/logs');
}

function goToSettings() {
  navigate('/settings');
}

function goToSsl() {
  providerStore.selectProvider(null);
  navigate('/ssl');
}

function goToEdgeOne() {
  providerStore.selectProvider(null);
  navigate('/edgeone');
}


function confirmLogout() {
  dialog.info({
    title: '确认退出登录',
    content: '确定要退出当前账户吗？',
    positiveText: '退出',
    negativeText: '取消',
    onPositiveClick: () => {
      clearAuthData();
      navigate('/login');
    },
  });
}

async function navigate(path: string) {
  emit('close');
  await nextTick();
  try {
    await router.push(path);
  } catch {
    window.location.assign(path);
  }
}
</script>

<template>
  <div class="app-sidebar">
    <header class="sidebar-header">
      <div class="sidebar-logo">
        <Globe2 :size="24" />
      </div>
      <div class="sidebar-title">
        <p class="sidebar-name">DNS Control Desk</p>
        <p class="sidebar-desc">多服务商解析工作台</p>
      </div>
    </header>

    <button class="nav-btn" :class="{ active: route.path === '/' }" @click="goToDashboard">
      <LayoutDashboard :size="18" />
      总览仪表盘
    </button>

    <button class="nav-btn" :class="{ active: route.path === '/ssl' }" @click="goToSsl">
      <ShieldCheck :size="18" />
      SSL 证书
    </button>

    <button class="nav-btn" :class="{ active: route.path === '/edgeone' }" @click="goToEdgeOne">
      <Rocket :size="18" />
      EdgeOne 加速
    </button>

    <div class="providers-section">
      <div class="section-header">
        <p class="section-label">Providers</p>
        <div class="section-dot"></div>
      </div>
      <div v-if="providerStore.isLoading" class="space-y-3 px-1">
        <div v-for="i in 4" :key="i" class="sidebar-skeleton" />
      </div>
      <div
        v-else
        class="providers-list"
        :style="{ touchAction: draggingType ? 'none' : 'pan-y' }"
      >
        <ProviderItem
          v-for="provider in sortedProviders"
          :key="provider.type"
          :provider="provider"
          :is-selected="providerStore.selectedProvider === provider.type"
          :count="providerStore.getCredentialCountByProvider(provider.type)"
          :is-dragging="draggingType === provider.type"
          @click="selectProvider(provider.type)"
          @pointerdown="onProviderPointerDown(provider.type)"
        />
      </div>
    </div>

    <footer class="sidebar-footer">
      <div class="footer-decoration"></div>
      <div class="user-info">
        <div class="user-avatar">
          {{ user?.username?.charAt(0)?.toUpperCase() || 'U' }}
        </div>
        <span class="user-name">{{ user?.username || 'User' }}</span>
      </div>
      <div class="user-actions">
        <button class="action-btn" :title="isDark ? '浅色模式' : '深色模式'" @click="toggleTheme">
          <Sun v-if="isDark" :size="16" />
          <Moon v-else :size="16" />
        </button>
        <button class="action-btn" title="日志" @click="goToLogs">
          <History :size="16" />
        </button>
        <button class="action-btn" title="设置" @click="goToSettings">
          <Settings :size="16" />
        </button>
        <button class="action-btn action-btn-danger" title="退出" @click="confirmLogout">
          <LogOut :size="16" />
        </button>
      </div>
    </footer>
  </div>
</template>

<style scoped>
.sidebar-skeleton {
  height: 44px;
  border-radius: 12px;
  background: linear-gradient(90deg, #f1f5f9 25%, #e2e8f0 50%, #f1f5f9 75%);
  background-size: 200% 100%;
  animation: shimmer 1.4s ease-in-out infinite;
}

@keyframes shimmer {
  0% {
    background-position: 200% 0;
  }
  100% {
    background-position: -200% 0;
  }
}
</style>
