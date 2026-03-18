<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useQuery, useMutation } from '@tanstack/vue-query';
import { NInput, NButton, NTag, NDataTable, NModal, NFormItem, NEmpty, NSpin, NPagination, useMessage, useDialog } from 'naive-ui';
import { Plus, RefreshCw, Search, Trash2, ChevronDown, ChevronRight } from 'lucide-vue-next';
import { getTunnels, createTunnel, deleteTunnel } from '@/services/tunnels';
import { useProviderStore } from '@/stores/provider';
import { useCredentialResolver } from '@/composables/useCredentialResolver';
import { useResponsive } from '@/composables/useResponsive';
import { formatDateTime } from '@/utils/formatters';
import type { Tunnel } from '@/types';
import TunnelDetailsPanel from '@/components/Tunnels/TunnelDetailsPanel.vue';
import TunnelPublicHostnamesDialog from '@/components/Tunnels/TunnelPublicHostnamesDialog.vue';
import { h } from 'vue';

const message = useMessage();
const dlg = useDialog();
const providerStore = useProviderStore();
const { credentialId } = useCredentialResolver();
const { isMobile } = useResponsive();

const searchKeyword = ref('');
const showCreate = ref(false);
const createName = ref('');
const expandedId = ref<string | null>(null);
const publicHostnamesTunnel = ref<Tunnel | null>(null);
const page = ref(1);
const pageSize = ref(parseInt(localStorage.getItem('dns_tunnels_page_size') || '20'));

// Tunnels query
const { data: tunnelsData, isLoading, refetch } = useQuery({
  queryKey: computed(() => ['tunnels', credentialId.value]),
  queryFn: async () => {
    if (!credentialId.value) return [];
    const res = await getTunnels(credentialId.value);
    return res.data?.tunnels || [];
  },
  enabled: computed(() => !!credentialId.value && providerStore.selectedProvider === 'cloudflare'),
});

const tunnels = computed(() => {
  const all = tunnelsData.value || [];
  if (!searchKeyword.value) return all;
  const q = searchKeyword.value.toLowerCase();
  return all.filter(t => t.name?.toLowerCase().includes(q) || t.id.toLowerCase().includes(q));
});

const paginatedTunnels = computed(() => {
  const start = (page.value - 1) * pageSize.value;
  return tunnels.value.slice(start, start + pageSize.value);
});

watch([searchKeyword, pageSize], () => { page.value = 1; });
watch(pageSize, (size) => {
  localStorage.setItem('dns_tunnels_page_size', String(size));
});

const statusType: Record<string, 'success' | 'warning' | 'error' | 'default'> = {
  healthy: 'success', degraded: 'warning', down: 'error', inactive: 'default',
};
const statusLabel: Record<string, string> = {
  healthy: '正常', degraded: '降级', down: '离线', inactive: '未连接',
};

// Create mutation
const createMutation = useMutation({
  mutationFn: () => {
    if (!credentialId.value) throw new Error('Missing credential');
    return createTunnel(createName.value, credentialId.value);
  },
  onSuccess: () => { message.success('Tunnel 已创建'); showCreate.value = false; createName.value = ''; refetch(); },
  onError: (err: any) => message.error(String(err)),
});

// Delete mutation
function confirmDelete(tunnel: Tunnel) {
  dlg.warning({
    title: '删除 Tunnel',
    content: `确定要删除 ${tunnel.name || tunnel.id} 吗？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteTunnel(tunnel.id, credentialId.value!, { cleanupDns: true });
        message.success('Tunnel 已删除');
        refetch();
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}

function toggleExpand(id: string) {
  expandedId.value = expandedId.value === id ? null : id;
}

const columns = computed(() => [
  {
    title: '', key: 'expand', width: 40,
    render: (row: Tunnel) => h('button', {
      class: 'text-slate-500 transition-colors hover:text-slate-700',
      onClick: () => toggleExpand(row.id),
    }, [h(expandedId.value === row.id ? ChevronDown : ChevronRight, { size: 16 })]),
  },
  { title: '名称', key: 'name', minWidth: 180, render: (row: Tunnel) => h('span', { class: 'font-medium text-slate-700' }, row.name || row.id) },
  {
    title: '状态', key: 'status', width: 100,
    render: (row: Tunnel) => h(NTag, { type: statusType[row.status || ''] || 'default', size: 'small', bordered: false }, () => statusLabel[row.status || ''] || '未知'),
  },
  {
    title: '创建时间', key: 'created_at', width: 160,
    render: (row: Tunnel) => h('span', { class: 'text-sm text-slate-500' }, row.created_at ? formatDateTime(row.created_at) : '-'),
  },
  {
    title: '', key: 'actions', width: 80, fixed: 'right' as const,
    render: (row: Tunnel) => h('div', { class: 'flex gap-4' }, [
      h(NButton, { text: true, size: 'small', onClick: () => { publicHostnamesTunnel.value = row; } }, () => '路由'),
      h(NButton, { text: true, type: 'error', size: 'small', onClick: () => confirmDelete(row) }, { icon: () => h(Trash2, { size: 14 }) }),
    ]),
  },
]);
</script>

<template>
  <div class="space-y-4">
    <section class="panel p-4">
      <div class="toolbar-row">
        <div>
          <h1 class="page-title">Cloudflare Tunnel</h1>
          <p class="page-subtitle">私网出口、路由与连接状态集中管理</p>
        </div>
        <div class="flex-1" />
        <NInput v-model:value="searchKeyword" placeholder="搜索 Tunnel..." clearable size="small" class="!w-56">
          <template #prefix><Search :size="14" class="text-slate-500" /></template>
        </NInput>
        <NButton size="small" type="primary" @click="showCreate = true">
          <template #icon><Plus :size="14" /></template>
          创建
        </NButton>
        <NButton size="small" secondary :loading="isLoading" @click="refetch()">
          <template #icon><RefreshCw :size="14" /></template>
        </NButton>
      </div>
    </section>

    <section class="panel p-4">
      <div v-if="isLoading" class="flex justify-center py-20"><NSpin size="large" /></div>
      <NEmpty v-else-if="tunnels.length === 0" description="暂无 Tunnel" class="py-10" />

      <div v-else-if="isMobile" class="space-y-4">
        <div v-for="tunnel in paginatedTunnels" :key="tunnel.id" class="panel-muted p-4">
          <div class="mb-2 flex items-center justify-between">
            <span class="font-medium text-slate-700">{{ tunnel.name || tunnel.id }}</span>
            <NTag :type="statusType[tunnel.status || ''] || 'default'" size="small" :bordered="false">
              {{ statusLabel[tunnel.status || ''] || '未知' }}
            </NTag>
          </div>
          <div class="flex items-center justify-between text-xs text-slate-500">
            <span>{{ tunnel.created_at ? formatDateTime(tunnel.created_at) : '-' }}</span>
            <div class="flex gap-4">
              <NButton text size="tiny" @click="publicHostnamesTunnel = tunnel">路由</NButton>
              <NButton text size="tiny" type="error" @click="confirmDelete(tunnel)">删除</NButton>
            </div>
          </div>
          <TunnelDetailsPanel
            v-if="expandedId === tunnel.id"
            :tunnel="tunnel"
            :credential-id="credentialId!"
            class="mt-3 border-t border-panel-border pt-3"
          />
        </div>
      </div>

      <template v-else>
        <NDataTable
          :columns="columns"
          :data="paginatedTunnels"
          :row-key="(r: Tunnel) => r.id"
          :bordered="false"
          size="small"
          class="table-scrollable"
          :scroll-x="760"
          :max-height="560"
          :virtual-scroll="paginatedTunnels.length > 120"
        />
        <div v-for="tunnel in paginatedTunnels" :key="'detail-' + tunnel.id">
          <TunnelDetailsPanel
            v-if="expandedId === tunnel.id && credentialId"
            :tunnel="tunnel"
            :credential-id="credentialId"
            class="panel-muted ml-10 my-2 p-4"
          />
        </div>
      </template>

      <div v-if="tunnels.length > pageSize" class="mt-4 flex justify-end">
        <NPagination
          v-model:page="page"
          v-model:page-size="pageSize"
          :item-count="tunnels.length"
          :page-sizes="[20, 50, 100]"
          show-size-picker
          show-quick-jumper
          size="small"
        />
      </div>
    </section>

    <!-- Create dialog -->
    <NModal v-model:show="showCreate" preset="card" title="创建 Tunnel" :style="{ width: '400px' }">
      <div class="space-y-3">
        <NFormItem label="名称" :show-feedback="false">
          <NInput v-model:value="createName" placeholder="Tunnel 名称" @keydown.enter="createMutation.mutate()" />
        </NFormItem>
        <div class="flex justify-end gap-4">
          <NButton @click="showCreate = false">取消</NButton>
          <NButton type="primary" :loading="createMutation.isPending.value" @click="createMutation.mutate()">创建</NButton>
        </div>
      </div>
    </NModal>

    <!-- Public hostnames dialog -->
    <TunnelPublicHostnamesDialog
      v-if="publicHostnamesTunnel && credentialId"
      :tunnel="publicHostnamesTunnel"
      :credential-id="credentialId"
      @close="publicHostnamesTunnel = null"
    />
  </div>
</template>
