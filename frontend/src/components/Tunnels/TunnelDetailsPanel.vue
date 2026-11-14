<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useQuery } from '@tanstack/vue-query';
import { NTag, NButton, NAlert, NSpin } from 'naive-ui';
import { getTunnelToken, getTunnelConfig } from '@/services/tunnels';
import { formatDateTime } from '@/utils/formatters';
import type { Tunnel } from '@/types';

const props = defineProps<{
  tunnel: Tunnel;
  credentialId: number;
  accountId: string;
}>();

const locallyManaged = computed(() => props.tunnel.remote_config === false || props.tunnel.config_src === 'local');
const token = ref('');
const tokenLoading = ref(false);
const tokenError = ref('');
watch(() => [props.tunnel.id, props.credentialId, props.accountId], () => { token.value = ''; tokenError.value = ''; });
async function revealToken() {
  if (tokenLoading.value) return;
  tokenLoading.value = true;
  tokenError.value = '';
  try {
    const result = await getTunnelToken(props.tunnel.id, props.credentialId, props.accountId);
    token.value = result.data?.token || '';
    if (!token.value) tokenError.value = 'Cloudflare 未返回安装 Token';
  } catch (error) {
    tokenError.value = String(error);
  } finally {
    tokenLoading.value = false;
  }
}

const { data: configData, error: configError, isLoading: configLoading } = useQuery({
  queryKey: computed(() => ['tunnel-config', props.credentialId, props.accountId, props.tunnel.id]),
  queryFn: () => getTunnelConfig(props.tunnel.id, props.credentialId, props.accountId),
  enabled: computed(() => !locallyManaged.value),
});

const ingress = computed(() => {
  const config = configData.value?.data?.config;
  return Array.isArray(config?.ingress) ? config.ingress : [];
});

const connections = computed(() => props.tunnel.connections || []);
</script>

<template>
  <div class="space-y-3 text-sm">
    <NAlert v-if="locallyManaged" type="info">该 Tunnel 使用本地配置。请在运行 cloudflared 的机器上维护公共路由和安装凭证。</NAlert>
    <div v-else class="space-y-2">
      <NButton size="small" :loading="tokenLoading" @click="token ? token = '' : revealToken()">{{ token ? '隐藏安装命令' : '查看安装命令' }}</NButton>
      <NAlert v-if="tokenError" type="error">{{ tokenError }}</NAlert>
    </div>
    <!-- Token -->
    <div v-if="token">
      <p class="text-slate-500 text-xs mb-1">安装命令（包含敏感 Token，请勿公开分享）:</p>
      <code class="block bg-panel-bg rounded p-2 text-xs text-slate-700 font-mono break-all select-all">
        cloudflared service install {{ token }}
      </code>
    </div>

    <!-- Connections -->
    <div>
      <p class="text-slate-500 text-xs mb-1">连接 ({{ connections.length }}):</p>
      <p v-if="!connections.length" class="text-xs text-slate-500">暂无连接。列表每 30 秒自动刷新，可手动刷新检查状态。</p>
      <div class="space-y-1">
        <div v-for="(conn, index) in connections" :key="conn.id || conn.uuid || index" class="flex flex-wrap items-center gap-2 text-xs">
          <NTag size="small" :bordered="false" type="info">{{ conn.colo_name }}</NTag>
          <span class="text-slate-400">{{ conn.client_version }}</span>
          <span class="text-slate-500">{{ conn.origin_ip }}</span>
          <NTag v-if="conn.is_pending_reconnect" size="small" type="warning">等待重连</NTag>
        </div>
      </div>
    </div>

    <!-- Ingress rules -->
    <NAlert v-if="configError" type="error">配置读取失败：{{ String(configError) }}</NAlert>
    <NSpin v-if="configLoading" size="small" />
    <div v-if="ingress.length > 0">
      <p class="text-slate-400 text-xs mb-1">路由规则 ({{ ingress.length }}):</p>
      <div class="space-y-1">
        <div v-for="(rule, i) in ingress" :key="i" class="flex items-center gap-2 text-xs">
          <span class="text-slate-700 font-mono break-all">{{ rule.hostname || '*' }}{{ rule.path || '' }}</span>
          <span class="text-slate-500">→</span>
          <span class="text-slate-600 break-all">{{ rule.service }}</span>
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
