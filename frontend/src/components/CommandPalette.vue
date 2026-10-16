<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
import { NModal, NInput, NEmpty, NTag } from 'naive-ui';
import {
  Search, LayoutDashboard, Shield, Rocket, History, Settings, Globe2, FileKey2,
} from 'lucide-vue-next';
import { useProviderStore } from '@/stores/provider';
import { getProviderDisplayName } from '@/utils/provider';

interface CommandItem {
  id: string;
  title: string;
  subtitle?: string;
  group: string;
  keywords?: string;
  icon?: any;
  run: () => void;
}

const router = useRouter();
const providerStore = useProviderStore();

const open = ref(false);
const query = ref('');
const activeIndex = ref(0);

const staticCommands = computed<CommandItem[]>(() => [
  {
    id: 'nav-dashboard',
    title: '域名仪表盘',
    subtitle: '总览 / 同步 / 告警',
    group: '导航',
    icon: LayoutDashboard,
    keywords: 'dashboard home 总览',
    run: () => router.push({ path: '/', query: { scope: 'all' } }),
  },
  {
    id: 'nav-ssl',
    title: 'SSL 证书管理',
    subtitle: '申请 / 续期 / 部署',
    group: '导航',
    icon: Shield,
    keywords: 'ssl certificate 证书',
    run: () => router.push('/ssl'),
  },
  {
    id: 'nav-edgeone',
    title: 'EdgeOne 加速',
    subtitle: '站点 / 加速域名',
    group: '导航',
    icon: Rocket,
    keywords: 'edgeone cdn 加速',
    run: () => router.push('/edgeone'),
  },
  {
    id: 'nav-tunnels',
    title: 'Cloudflare Tunnel',
    group: '导航',
    icon: Globe2,
    keywords: 'tunnel cloudflare',
    run: () => router.push('/tunnels'),
  },
  {
    id: 'nav-logs',
    title: '操作日志',
    group: '导航',
    icon: History,
    keywords: 'logs audit 审计',
    run: () => router.push('/logs'),
  },
  {
    id: 'nav-settings',
    title: '设置中心',
    group: '导航',
    icon: Settings,
    keywords: 'settings 设置 token smtp',
    run: () => router.push('/settings'),
  },
  {
    id: 'nav-settings-tokens',
    title: 'API Token 管理',
    subtitle: '设置 → API Token',
    group: '快捷',
    icon: FileKey2,
    keywords: 'api token dpan',
    run: () => router.push({ path: '/settings', query: { tab: 'api-token' } }),
  },
]);

const providerCommands = computed<CommandItem[]>(() => {
  const creds = providerStore.credentials || [];
  return creds.slice(0, 30).map((c) => {
    const provider = String(c.provider || '');
    const name = String(c.name || provider);
    return {
      id: `cred-${c.id}`,
      title: name,
      subtitle: getProviderDisplayName(provider) || provider,
      group: '凭证',
      icon: Globe2,
      keywords: `${provider} ${name} credential`,
      run: () => {
        providerStore.selectProvider(provider as any);
        providerStore.selectCredential(Number(c.id));
        router.push({ path: '/', query: { scope: provider, credentialId: String(c.id) } });
      },
    };
  });
});

const allCommands = computed(() => [...staticCommands.value, ...providerCommands.value]);

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase();
  if (!q) return allCommands.value;
  return allCommands.value.filter((item) => {
    const hay = `${item.title} ${item.subtitle || ''} ${item.group} ${item.keywords || ''}`.toLowerCase();
    return hay.includes(q);
  });
});

const grouped = computed(() => {
  const map = new Map<string, CommandItem[]>();
  for (const item of filtered.value) {
    if (!map.has(item.group)) map.set(item.group, []);
    map.get(item.group)!.push(item);
  }
  return Array.from(map.entries()).map(([group, items]) => ({ group, items }));
});

function openPalette() {
  open.value = true;
  query.value = '';
  activeIndex.value = 0;
  nextTick(() => {
    const el = document.querySelector<HTMLInputElement>('.command-palette-input input');
    el?.focus();
  });
}

function closePalette() {
  open.value = false;
}

function runItem(item: CommandItem) {
  closePalette();
  item.run();
}

function onKeydown(e: KeyboardEvent) {
  const isMac = navigator.platform.toLowerCase().includes('mac');
  const mod = isMac ? e.metaKey : e.ctrlKey;
  if (mod && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (open.value) closePalette();
    else openPalette();
    return;
  }
  if (!open.value) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    closePalette();
    return;
  }
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    activeIndex.value = Math.min(activeIndex.value + 1, Math.max(filtered.value.length - 1, 0));
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    activeIndex.value = Math.max(activeIndex.value - 1, 0);
  } else if (e.key === 'Enter') {
    e.preventDefault();
    const item = filtered.value[activeIndex.value];
    if (item) runItem(item);
  }
}

watch(filtered, () => {
  activeIndex.value = 0;
});

onMounted(() => {
  window.addEventListener('keydown', onKeydown);
  if (!providerStore.providers.length) {
    providerStore.loadData().catch(() => undefined);
  }
});

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown);
});

function flatIndex(groupIdx: number, itemIdx: number) {
  let n = 0;
  for (let i = 0; i < groupIdx; i++) n += grouped.value[i].items.length;
  return n + itemIdx;
}
</script>

<template>
  <NModal
    v-model:show="open"
    preset="card"
    :bordered="false"
    style="width: min(640px, 94vw); max-height: 78vh"
    :segmented="{ content: true }"
    :closable="false"
    class="command-palette-modal"
  >
    <div class="space-y-3">
      <NInput
        v-model:value="query"
        class="command-palette-input"
        size="large"
        placeholder="搜索页面、凭证…（Ctrl/⌘ + K）"
        clearable
      >
        <template #prefix>
          <Search :size="16" class="text-slate-400" />
        </template>
      </NInput>

      <div v-if="filtered.length" class="max-h-[52vh] space-y-3 overflow-y-auto pr-1">
        <div v-for="(g, gi) in grouped" :key="g.group">
          <p class="mb-1 px-1 text-[11px] font-bold uppercase tracking-wide text-slate-400">{{ g.group }}</p>
          <button
            v-for="(item, ii) in g.items"
            :key="item.id"
            type="button"
            class="mb-1 flex w-full items-center gap-3 rounded-lg border px-3 py-2 text-left transition"
            :class="flatIndex(gi, ii) === activeIndex
              ? 'border-accent/40 bg-accent/10'
              : 'border-transparent hover:border-panel-border hover:bg-panel-muted'"
            @mouseenter="activeIndex = flatIndex(gi, ii)"
            @click="runItem(item)"
          >
            <component :is="item.icon || Search" :size="16" class="shrink-0 text-slate-500" />
            <div class="min-w-0 flex-1">
              <p class="truncate text-sm font-semibold text-slate-800 dark:text-slate-100">{{ item.title }}</p>
              <p v-if="item.subtitle" class="truncate text-xs text-slate-500">{{ item.subtitle }}</p>
            </div>
            <NTag size="tiny" :bordered="false">{{ item.group }}</NTag>
          </button>
        </div>
      </div>
      <NEmpty v-else description="没有匹配的命令" size="small" />
    </div>
  </NModal>
</template>
