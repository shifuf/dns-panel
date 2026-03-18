<script setup lang="ts">
import { computed } from 'vue';
import { useQuery } from '@tanstack/vue-query';
import { NTag, NSpin } from 'naive-ui';
import { getTunnelToken, getTunnelConfig } from '@/services/tunnels';
import { formatDateTime } from '@/utils/formatters';
import type { Tunnel } from '@/types';

const props = defineProps<{
  tunnel: Tunnel;
  credentialId: number;
}>();

const { data: tokenData } = useQuery({
  queryKey: computed(() => ['tunnel-token', props.tunnel.id, props.credentialId]),
  queryFn: () => getTunnelToken(props.tunnel.id, props.credentialId),
});

const { data: configData } = useQuery({
  queryKey: computed(() => ['tunnel-config', props.credentialId, props.tunnel.id]),
  queryFn: () => getTunnelConfig(props.tunnel.id, props.credentialId),
});

const token = computed(() => tokenData.value?.data?.token || '');
const ingress = computed(() => {
  const config = configData.value?.data?.config;
  return Array.isArray(config?.ingress) ? config.ingress : [];
});

const connections = computed(() => props.tunnel.connections || []);
</script>

<template>
  <div class="space-y-3 text-sm">
    <!-- Token -->
    <div v-if="token">
      <p class="text-slate-400 text-xs mb-1">安装命令:</p>
      <code class="block bg-panel-bg rounded p-2 text-xs text-slate-300 font-mono break-all select-all">
        cloudflared service install {{ token }}
      </code>
    </div>

    <!-- Connections -->
    <div v-if="connections.length > 0">
      <p class="text-slate-400 text-xs mb-1">连接 ({{ connections.length }}):</p>
      <div class="space-y-1">
        <div v-for="conn in connections" :key="conn.uuid" class="flex items-center gap-2 text-xs">
          <NTag size="small" :bordered="false" type="info">{{ conn.colo_name }}</NTag>
          <span class="text-slate-400">{{ conn.client_version }}</span>
          <span class="text-slate-500">{{ conn.origin_ip }}</span>
        </div>
      </div>
    </div>

    <!-- Ingress rules -->
    <div v-if="ingress.length > 0">
      <p class="text-slate-400 text-xs mb-1">路由规则 ({{ ingress.length }}):</p>
      <div class="space-y-1">
        <div v-for="(rule, i) in ingress" :key="i" class="flex items-center gap-2 text-xs">
          <span class="text-slate-700 font-mono">{{ rule.hostname || '*' }}</span>
          <span class="text-slate-500">→</span>
          <span class="text-slate-300">{{ rule.service }}</span>
        </div>
      </div>
    </div>

    <!-- Meta -->
    <div class="text-xs text-slate-500">
      <span>ID: {{ tunnel.id }}</span>
      <span v-if="tunnel.created_at" class="ml-3">创建: {{ formatDateTime(tunnel.created_at) }}</span>
    </div>
  </div>
</template>
