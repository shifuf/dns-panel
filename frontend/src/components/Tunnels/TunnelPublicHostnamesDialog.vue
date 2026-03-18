<script setup lang="ts">
import { ref, computed } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NModal, NTabs, NTabPane, NInput, NButton, NDataTable, NFormItem, NEmpty, useMessage } from 'naive-ui';
import { Plus, Trash2 } from 'lucide-vue-next';
import {
  getTunnelConfig, upsertTunnelPublicHostname, deleteTunnelPublicHostname,
  getTunnelCidrRoutes, createTunnelCidrRoute, deleteTunnelCidrRoute,
  getTunnelHostnameRoutes, createTunnelHostnameRoute, deleteTunnelHostnameRoute,
} from '@/services/tunnels';
import type { Tunnel, TunnelPublicHostnameRoute, TunnelCidrRoute, TunnelHostnameRoute } from '@/types';
import { h } from 'vue';

const props = defineProps<{
  tunnel: Tunnel;
  credentialId: number;
}>();

const emit = defineEmits<{ close: [] }>();
const message = useMessage();
const queryClient = useQueryClient();

// Public hostnames from config
const { data: configData, refetch: refetchConfig } = useQuery({
  queryKey: computed(() => ['tunnel-config', props.credentialId, props.tunnel.id]),
  queryFn: () => getTunnelConfig(props.tunnel.id, props.credentialId),
});

const publicHostnames = computed<TunnelPublicHostnameRoute[]>(() => {
  const config = configData.value?.data?.config;
  const ingress = Array.isArray(config?.ingress) ? config.ingress : [];
  return ingress.filter((r: any) => r.hostname).map((r: any) => ({
    hostname: r.hostname, service: r.service, path: r.path,
  }));
});

// CIDR routes
const { data: cidrData, refetch: refetchCidr } = useQuery({
  queryKey: computed(() => ['tunnel-cidr-routes', props.tunnel.id, props.credentialId]),
  queryFn: () => getTunnelCidrRoutes(props.tunnel.id, props.credentialId),
});
const cidrRoutes = computed(() => cidrData.value?.data?.routes || []);

// Hostname routes
const { data: hostnameData, refetch: refetchHostname } = useQuery({
  queryKey: computed(() => ['tunnel-hostname-routes', props.tunnel.id, props.credentialId]),
  queryFn: () => getTunnelHostnameRoutes(props.tunnel.id, props.credentialId),
});
const hostnameRoutes = computed(() => hostnameData.value?.data?.routes || []);

// Forms
const newPublicHostname = ref('');
const newPublicService = ref('');
const newPublicZoneId = ref('');
const newCidrNetwork = ref('');
const newCidrComment = ref('');
const newHostnameRoute = ref('');

// Mutations
const upsertPublicMutation = useMutation({
  mutationFn: () => upsertTunnelPublicHostname(props.tunnel.id, {
    hostname: newPublicHostname.value, service: newPublicService.value, zoneId: newPublicZoneId.value,
  }, props.credentialId),
  onSuccess: () => { message.success('已添加'); newPublicHostname.value = ''; newPublicService.value = ''; refetchConfig(); },
  onError: (err: any) => message.error(String(err)),
});

const deletePublicMutation = useMutation({
  mutationFn: (vars: { hostname: string; path?: string }) =>
    deleteTunnelPublicHostname(props.tunnel.id, { hostname: vars.hostname, path: vars.path }, props.credentialId),
  onSuccess: () => { message.success('已删除'); refetchConfig(); },
  onError: (err: any) => message.error(String(err)),
});

const createCidrMutation = useMutation({
  mutationFn: () => createTunnelCidrRoute(props.tunnel.id, { network: newCidrNetwork.value, comment: newCidrComment.value }, props.credentialId),
  onSuccess: () => { message.success('已添加'); newCidrNetwork.value = ''; newCidrComment.value = ''; refetchCidr(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteCidrMutation = useMutation({
  mutationFn: (routeId: string) => deleteTunnelCidrRoute(props.tunnel.id, routeId, props.credentialId),
  onSuccess: () => { message.success('已删除'); refetchCidr(); },
  onError: (err: any) => message.error(String(err)),
});

const createHostnameMutation = useMutation({
  mutationFn: () => createTunnelHostnameRoute(props.tunnel.id, { hostname: newHostnameRoute.value }, props.credentialId),
  onSuccess: () => { message.success('已添加'); newHostnameRoute.value = ''; refetchHostname(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteHostnameMutation = useMutation({
  mutationFn: (routeId: string) => deleteTunnelHostnameRoute(props.tunnel.id, routeId, props.credentialId),
  onSuccess: () => { message.success('已删除'); refetchHostname(); },
  onError: (err: any) => message.error(String(err)),
});
</script>

<template>
  <NModal :show="true" preset="card" :title="`路由管理 — ${tunnel.name || tunnel.id}`" :style="{ width: '640px' }" @update:show="emit('close')">
    <NTabs type="line" size="small">
      <!-- Public hostnames -->
      <NTabPane name="public" tab="公共路由">
        <div class="space-y-3">
          <div class="flex gap-2">
            <NInput v-model:value="newPublicHostname" placeholder="hostname" size="small" class="flex-1" />
            <NInput v-model:value="newPublicService" placeholder="http://localhost:8080" size="small" class="flex-1" />
            <NButton size="small" type="primary" :loading="upsertPublicMutation.isPending.value" @click="upsertPublicMutation.mutate()">
              <template #icon><Plus :size="14" /></template>
            </NButton>
          </div>
          <NEmpty v-if="publicHostnames.length === 0" description="暂无公共路由" size="small" />
          <div v-else class="space-y-1">
            <div v-for="(route, i) in publicHostnames" :key="i" class="flex items-center gap-2 text-sm bg-panel-bg rounded p-2">
              <span class="font-mono text-slate-700 flex-1">{{ route.hostname }}</span>
              <span class="text-slate-500">→</span>
              <span class="text-slate-300 flex-1">{{ route.service }}</span>
              <NButton text size="tiny" type="error" @click="deletePublicMutation.mutate({ hostname: route.hostname, path: route.path })">
                <template #icon><Trash2 :size="12" /></template>
              </NButton>
            </div>
          </div>
        </div>
      </NTabPane>

      <!-- CIDR routes -->
      <NTabPane name="cidr" tab="CIDR 路由">
        <div class="space-y-3">
          <div class="flex gap-2">
            <NInput v-model:value="newCidrNetwork" placeholder="10.0.0.0/8" size="small" class="flex-1" />
            <NInput v-model:value="newCidrComment" placeholder="备注" size="small" class="flex-1" />
            <NButton size="small" type="primary" :loading="createCidrMutation.isPending.value" @click="createCidrMutation.mutate()">
              <template #icon><Plus :size="14" /></template>
            </NButton>
          </div>
          <NEmpty v-if="cidrRoutes.length === 0" description="暂无 CIDR 路由" size="small" />
          <div v-else class="space-y-1">
            <div v-for="route in cidrRoutes" :key="route.id" class="flex items-center gap-2 text-sm bg-panel-bg rounded p-2">
              <span class="font-mono text-slate-700 flex-1">{{ route.network }}</span>
              <span class="text-slate-400 flex-1">{{ route.comment || '-' }}</span>
              <NButton text size="tiny" type="error" @click="deleteCidrMutation.mutate(route.id)">
                <template #icon><Trash2 :size="12" /></template>
              </NButton>
            </div>
          </div>
        </div>
      </NTabPane>

      <!-- Hostname routes -->
      <NTabPane name="hostname" tab="Hostname 路由">
        <div class="space-y-3">
          <div class="flex gap-2">
            <NInput v-model:value="newHostnameRoute" placeholder="app.example.com" size="small" class="flex-1" />
            <NButton size="small" type="primary" :loading="createHostnameMutation.isPending.value" @click="createHostnameMutation.mutate()">
              <template #icon><Plus :size="14" /></template>
            </NButton>
          </div>
          <NEmpty v-if="hostnameRoutes.length === 0" description="暂无 Hostname 路由" size="small" />
          <div v-else class="space-y-1">
            <div v-for="route in hostnameRoutes" :key="route.id" class="flex items-center gap-2 text-sm bg-panel-bg rounded p-2">
              <span class="font-mono text-slate-700 flex-1">{{ route.hostname }}</span>
              <NButton text size="tiny" type="error" @click="deleteHostnameMutation.mutate(route.id)">
                <template #icon><Trash2 :size="12" /></template>
              </NButton>
            </div>
          </div>
        </div>
      </NTabPane>
    </NTabs>
  </NModal>
</template>
