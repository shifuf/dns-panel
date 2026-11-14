<script setup lang="ts">
import { ref, computed, h } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NModal, NTabs, NTabPane, NInput, NButton, NEmpty, NAlert, NSelect, NCheckbox, NSpin, useMessage, useDialog } from 'naive-ui';
import { Plus, Trash2 } from 'lucide-vue-next';
import {
  getTunnelConfig, getTunnelZones, upsertTunnelPublicHostname, deleteTunnelPublicHostname,
  getTunnelCidrRoutes, createTunnelCidrRoute, deleteTunnelCidrRoute,
  getTunnelHostnameRoutes, createTunnelHostnameRoute, deleteTunnelHostnameRoute,
} from '@/services/tunnels';
import type { Tunnel, TunnelPublicHostnameRoute } from '@/types';

const props = defineProps<{
  tunnel: Tunnel;
  credentialId: number;
  accountId: string;
}>();

const emit = defineEmits<{ close: [] }>();
const message = useMessage();
const dialog = useDialog();
const queryClient = useQueryClient();
const activeTab = ref('public');
const locallyManaged = computed(() => props.tunnel.remote_config === false || props.tunnel.config_src === 'local');
const refreshConfig = () => queryClient.invalidateQueries({ queryKey: ['tunnel-config', props.credentialId, props.accountId, props.tunnel.id] });
const { data: zonesData, error: zonesError } = useQuery({
  queryKey: computed(() => ['tunnel-zones', props.credentialId, props.accountId]),
  queryFn: () => getTunnelZones(props.credentialId, props.accountId),
  enabled: computed(() => !locallyManaged.value && activeTab.value === 'public'),
});
const zoneOptions = computed(() => (zonesData.value?.data?.zones || []).map(z => ({ label: z.name, value: z.id })));

// Public hostnames from config
const { data: configData, error: configError, isLoading: configLoading, refetch: refetchConfig } = useQuery({
  queryKey: computed(() => ['tunnel-config', props.credentialId, props.accountId, props.tunnel.id]),
  queryFn: () => getTunnelConfig(props.tunnel.id, props.credentialId, props.accountId),
  enabled: computed(() => !locallyManaged.value && activeTab.value === 'public'),
});

const publicHostnames = computed<TunnelPublicHostnameRoute[]>(() => {
  const config = configData.value?.data?.config;
  const ingress = Array.isArray(config?.ingress) ? config.ingress : [];
  return ingress.filter((r: any) => r.hostname).map((r: any) => ({
    hostname: r.hostname, service: r.service, path: r.path,
  }));
});

// CIDR routes
const { data: cidrData, error: cidrError, isLoading: cidrLoading, refetch: refetchCidr } = useQuery({
  queryKey: computed(() => ['tunnel-cidr-routes', props.tunnel.id, props.credentialId, props.accountId]),
  queryFn: () => getTunnelCidrRoutes(props.tunnel.id, props.credentialId, props.accountId),
  enabled: computed(() => activeTab.value === 'cidr'),
});
const cidrRoutes = computed(() => cidrData.value?.data?.routes || []);

// Hostname routes
const { data: hostnameData, error: hostnameError, isLoading: hostnameLoading, refetch: refetchHostname } = useQuery({
  queryKey: computed(() => ['tunnel-hostname-routes', props.tunnel.id, props.credentialId, props.accountId]),
  queryFn: () => getTunnelHostnameRoutes(props.tunnel.id, props.credentialId, props.accountId),
  enabled: computed(() => activeTab.value === 'hostname'),
});
const hostnameRoutes = computed(() => hostnameData.value?.data?.routes || []);

// Forms
const newPublicHostname = ref('');
const newPublicService = ref('');
const newPublicZoneId = ref<string | null>(null);
const newPublicPath = ref('');
const editingPublic = ref(false);
const newCidrNetwork = ref('');
const newCidrComment = ref('');
const newHostnameRoute = ref('');
function resetPublicForm() {
  newPublicHostname.value = ''; newPublicService.value = ''; newPublicPath.value = ''; editingPublic.value = false;
}
function editPublic(route: TunnelPublicHostnameRoute) {
  newPublicHostname.value = route.hostname; newPublicPath.value = route.path || ''; newPublicService.value = route.service; editingPublic.value = true;
}

// Mutations
const upsertPublicMutation = useMutation({
  mutationFn: () => upsertTunnelPublicHostname(props.tunnel.id, {
    hostname: newPublicHostname.value.trim(), service: newPublicService.value.trim(), path: newPublicPath.value.trim(), zoneId: newPublicZoneId.value || undefined,
  }, props.credentialId, props.accountId),
  onSuccess: () => { message.success('公共路由已保存'); resetPublicForm(); refreshConfig(); },
  onError: (err: any) => message.error(String(err)),
});

const deletePublicMutation = useMutation({
  mutationFn: (vars: { hostname: string; path?: string; deleteDns: boolean }) =>
    deleteTunnelPublicHostname(props.tunnel.id, vars, props.credentialId, props.accountId),
  onSuccess: (result) => { message.success(result.data?.dns?.reason || '公共路由已删除'); resetPublicForm(); refreshConfig(); },
  onError: (err: any) => message.error(String(err)),
});

const createCidrMutation = useMutation({
  mutationFn: () => createTunnelCidrRoute(props.tunnel.id, { network: newCidrNetwork.value.trim(), comment: newCidrComment.value.trim() }, props.credentialId, props.accountId),
  onSuccess: () => { message.success('已添加'); newCidrNetwork.value = ''; newCidrComment.value = ''; refetchCidr(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteCidrMutation = useMutation({
  mutationFn: (routeId: string) => deleteTunnelCidrRoute(props.tunnel.id, routeId, props.credentialId, props.accountId),
  onSuccess: () => { message.success('已删除'); refetchCidr(); },
  onError: (err: any) => message.error(String(err)),
});

const createHostnameMutation = useMutation({
  mutationFn: () => createTunnelHostnameRoute(props.tunnel.id, { hostname: newHostnameRoute.value.trim() }, props.credentialId, props.accountId),
  onSuccess: () => { message.success('已添加'); newHostnameRoute.value = ''; refetchHostname(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteHostnameMutation = useMutation({
  mutationFn: (routeId: string) => deleteTunnelHostnameRoute(props.tunnel.id, routeId, props.credentialId, props.accountId),
  onSuccess: () => { message.success('已删除'); refetchHostname(); },
  onError: (err: any) => message.error(String(err)),
});

const pending = computed(() => [upsertPublicMutation, deletePublicMutation, createCidrMutation, deleteCidrMutation, createHostnameMutation, deleteHostnameMutation].some(m => m.isPending.value));
function confirmPublicDelete(route: TunnelPublicHostnameRoute) {
  const deleteDns = ref(true);
  dialog.warning({
    title: '删除公共路由',
    content: () => h('div', { class: 'space-y-3' }, [
      h('p', `删除 ${route.hostname}${route.path || ''}？`),
      h(NCheckbox, { checked: deleteDns.value, 'onUpdate:checked': (value: boolean) => { deleteDns.value = value; } }, () => '同时清理指向本 Tunnel 的 DNS（其他路径仍使用时会保留）'),
    ]),
    positiveText: '删除', negativeText: '取消',
    onPositiveClick: async () => { try { await deletePublicMutation.mutateAsync({ ...route, deleteDns: deleteDns.value }); } catch { return false; } },
  });
}
function confirmPrivateDelete(kind: 'cidr' | 'hostname', id: string, name: string) {
  dialog.warning({ title: '删除私网路由', content: `确定删除 ${name}？`, positiveText: '删除', negativeText: '取消',
    onPositiveClick: async () => { try { await (kind === 'cidr' ? deleteCidrMutation : deleteHostnameMutation).mutateAsync(id); } catch { return false; } },
  });
}
</script>

<template>
  <NModal :show="true" preset="card" :title="`路由管理 — ${tunnel.name || tunnel.id}`" :style="{ width: '720px', maxWidth: 'calc(100vw - 24px)' }" @update:show="emit('close')">
    <NTabs v-model:value="activeTab" type="line" size="small">
      <!-- Public hostnames -->
      <NTabPane name="public" tab="公共路由">
        <NAlert v-if="locallyManaged" type="info">公共路由由本地 YAML 配置管理，请在 cloudflared 所在机器编辑。</NAlert>
        <div v-else class="space-y-3">
          <NAlert v-if="configError" type="error">配置读取失败：{{ String(configError) }} <NButton size="tiny" @click="refetchConfig()">重试</NButton></NAlert>
          <NAlert v-if="zonesError" type="warning">可用域名读取失败：{{ String(zonesError) }}</NAlert>
          <p class="text-xs text-slate-500">{{ editingPublic ? '编辑服务地址。主机名或路径变化时，请新建路由后删除旧路由。' : '填写完整主机名和服务地址；路径可选，支持正则表达式。' }}</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <NInput v-model:value="newPublicHostname" :disabled="editingPublic || pending" placeholder="app.example.com" aria-label="公共主机名" size="small" class="flex-1" />
            <NInput v-model:value="newPublicService" :disabled="pending" placeholder="http://localhost:8080" size="small" class="flex-1" />
            <NInput v-model:value="newPublicPath" :disabled="editingPublic || pending" placeholder="路径（可选），例如 /api/.*" aria-label="路由路径" size="small" />
            <NSelect v-model:value="newPublicZoneId" :disabled="pending" :options="zoneOptions" clearable placeholder="自动匹配所属域名" size="small" />
          </div>
          <div class="flex justify-end gap-2">
            <NButton v-if="editingPublic" size="small" :disabled="pending" @click="resetPublicForm">取消编辑</NButton>
            <NButton size="small" type="primary" :disabled="pending || configLoading || !!configError || !newPublicHostname.trim() || !newPublicService.trim()" :loading="upsertPublicMutation.isPending.value" @click="upsertPublicMutation.mutate()">{{ editingPublic ? '保存服务地址' : '保存公共路由' }}</NButton>
          </div>
          <NSpin v-if="configLoading" size="small" />
          <NEmpty v-else-if="!configError && publicHostnames.length === 0" description="暂无公共路由" size="small" />
          <div v-else class="space-y-1">
            <div v-for="(route, i) in publicHostnames" :key="i" class="flex items-center gap-2 text-sm bg-panel-bg rounded p-2">
              <span class="font-mono text-slate-700 flex-1 min-w-0 break-all">{{ route.hostname }}{{ route.path || '' }}</span>
              <span class="text-slate-500">→</span>
              <span class="text-slate-600 flex-1 min-w-0 break-all">{{ route.service }}</span>
              <NButton text size="tiny" :disabled="pending" @click="editPublic(route)">编辑</NButton>
              <NButton text size="tiny" type="error" :disabled="pending" :aria-label="`删除 ${route.hostname}${route.path || ''}`" @click="confirmPublicDelete(route)">
                <template #icon><Trash2 :size="12" /></template>
              </NButton>
            </div>
          </div>
        </div>
      </NTabPane>

      <!-- CIDR routes -->
      <NTabPane name="cidr" tab="CIDR 路由">
        <div class="space-y-3">
          <NAlert v-if="cidrError" type="error">{{ String(cidrError) }} <NButton size="tiny" @click="refetchCidr()">重试</NButton></NAlert>
          <div class="flex flex-wrap gap-2">
            <NInput v-model:value="newCidrNetwork" placeholder="10.0.0.0/8" size="small" class="flex-1" />
            <NInput v-model:value="newCidrComment" placeholder="备注" size="small" class="flex-1" />
            <NButton size="small" type="primary" aria-label="添加 CIDR 路由" :disabled="pending || !newCidrNetwork.trim()" :loading="createCidrMutation.isPending.value" @click="createCidrMutation.mutate()">
              <template #icon><Plus :size="14" /></template>
            </NButton>
          </div>
          <NSpin v-if="cidrLoading" size="small" />
          <NEmpty v-else-if="!cidrError && cidrRoutes.length === 0" description="暂无 CIDR 路由" size="small" />
          <div v-else class="space-y-1">
            <div v-for="route in cidrRoutes" :key="route.id" class="flex items-center gap-2 text-sm bg-panel-bg rounded p-2">
              <span class="font-mono text-slate-700 flex-1">{{ route.network }}</span>
              <span class="text-slate-400 flex-1">{{ route.comment || '-' }}</span>
              <NButton text size="tiny" type="error" :disabled="pending" :aria-label="`删除 ${route.network}`" @click="confirmPrivateDelete('cidr', route.id, route.network)">
                <template #icon><Trash2 :size="12" /></template>
              </NButton>
            </div>
          </div>
        </div>
      </NTabPane>

      <!-- Hostname routes -->
      <NTabPane name="hostname" tab="Hostname 路由">
        <div class="space-y-3">
          <NAlert v-if="hostnameError" type="error">{{ String(hostnameError) }} <NButton size="tiny" @click="refetchHostname()">重试</NButton></NAlert>
          <div class="flex gap-2">
            <NInput v-model:value="newHostnameRoute" placeholder="app.example.com" size="small" class="flex-1" />
            <NButton size="small" type="primary" aria-label="添加私网主机名路由" :disabled="pending || !newHostnameRoute.trim()" :loading="createHostnameMutation.isPending.value" @click="createHostnameMutation.mutate()">
              <template #icon><Plus :size="14" /></template>
            </NButton>
          </div>
          <NSpin v-if="hostnameLoading" size="small" />
          <NEmpty v-else-if="!hostnameError && hostnameRoutes.length === 0" description="暂无 Hostname 路由" size="small" />
          <div v-else class="space-y-1">
            <div v-for="route in hostnameRoutes" :key="route.id" class="flex items-center gap-2 text-sm bg-panel-bg rounded p-2">
              <span class="font-mono text-slate-700 flex-1">{{ route.hostname }}</span>
              <NButton text size="tiny" type="error" :disabled="pending" :aria-label="`删除 ${route.hostname}`" @click="confirmPrivateDelete('hostname', route.id, route.hostname)">
                <template #icon><Trash2 :size="12" /></template>
              </NButton>
            </div>
          </div>
        </div>
      </NTabPane>
    </NTabs>
  </NModal>
</template>
