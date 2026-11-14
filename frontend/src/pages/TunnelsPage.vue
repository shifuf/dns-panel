<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useQuery, useMutation } from '@tanstack/vue-query';
import { NInput, NButton, NTag, NDataTable, NModal, NFormItem, NEmpty, NSpin, NPagination, NSelect, NAlert, NCheckbox, useMessage, useDialog } from 'naive-ui';
import { Plus, RefreshCw, Search, Trash2, ChevronDown, ChevronRight } from 'lucide-vue-next';
import { getTunnels, getTunnelAccounts, createTunnel, deleteTunnel } from '@/services/tunnels';
import { getDnsCredentials } from '@/services/dnsCredentials';
import { useProviderStore } from '@/stores/provider';
import { useResponsive } from '@/composables/useResponsive';
import { formatDateTime } from '@/utils/formatters';
import { TABLE_PAGE_SIZE } from '@/utils/constants';
import type { Tunnel } from '@/types';
import TunnelDetailsPanel from '@/components/Tunnels/TunnelDetailsPanel.vue';
import TunnelPublicHostnamesDialog from '@/components/Tunnels/TunnelPublicHostnamesDialog.vue';
import { h } from 'vue';

const message = useMessage();
const dlg = useDialog();
const providerStore = useProviderStore();
const credentialId = ref<number | null>(null);
const accountId = ref<string | null>(null);
const { isMobile } = useResponsive();

const { data: credentialData, isLoading: credentialsLoading, error: credentialsError, refetch: refetchCredentials } = useQuery({
  queryKey: ['tunnel-credentials'],
  queryFn: () => getDnsCredentials('dns'),
});
const credentials = computed(() => (credentialData.value?.data?.credentials || []).filter(c => c.provider === 'cloudflare'));
const credentialOptions = computed(() => credentials.value.map(c => ({ label: c.name, value: c.id })));
watch(credentials, (items) => {
  if (!items.some(c => c.id === credentialId.value)) {
    credentialId.value = items.find(c => c.id === providerStore.selectedCredentialId)?.id
      ?? items.find(c => c.isDefault)?.id ?? items[0]?.id ?? null;
  }
}, { immediate: true });
const { data: accountsData, isLoading: accountsLoading, error: accountsError, refetch: refetchAccounts } = useQuery({
  queryKey: computed(() => ['tunnel-accounts', credentialId.value]),
  queryFn: () => getTunnelAccounts(credentialId.value!),
  enabled: computed(() => !!credentialId.value),
});
const accountOptions = computed(() => (accountsData.value?.data?.accounts || []).map(a => ({ label: a.name || a.id, value: a.id })));
watch(accountOptions, (items) => {
  if (!items.some(a => a.value === accountId.value)) accountId.value = items[0]?.value ?? null;
}, { immediate: true });

const searchKeyword = ref('');
const showCreate = ref(false);
const createName = ref('');
const expandedId = ref<string | null>(null);
const publicHostnamesTunnel = ref<Tunnel | null>(null);
const page = ref(1);
const pageSize = TABLE_PAGE_SIZE;
const ready = computed(() => !!credentialId.value && !!accountId.value);

// Tunnels query
const { data: tunnelsData, isLoading, isFetching, error: tunnelsError, refetch: refetchList } = useQuery({
  queryKey: computed(() => ['tunnels', credentialId.value, accountId.value]),
  queryFn: async () => {
    if (!credentialId.value) return [];
    const res = await getTunnels(credentialId.value, accountId.value!);
    return res.data?.tunnels || [];
  },
  enabled: ready,
  refetchInterval: 30000,
});
const loadError = computed(() => credentialsError.value || accountsError.value || tunnelsError.value);
async function refetch() {
  if (credentialsError.value || !credentialId.value) return refetchCredentials();
  if (accountsError.value || !accountId.value) return refetchAccounts();
  return refetchList();
}

const tunnels = computed(() => {
  const all = tunnelsData.value || [];
  if (!searchKeyword.value) return all;
  const q = searchKeyword.value.toLowerCase();
  return all.filter(t => t.name?.toLowerCase().includes(q) || t.id.toLowerCase().includes(q));
});

const paginatedTunnels = computed(() => {
  const start = (page.value - 1) * pageSize;
  return tunnels.value.slice(start, start + pageSize);
});

watch(searchKeyword, () => { page.value = 1; });
watch([credentialId, accountId], () => {
  page.value = 1;
  expandedId.value = null;
  publicHostnamesTunnel.value = null;
  showCreate.value = false;
});
watch(() => tunnels.value.length, (count) => { page.value = Math.min(page.value, Math.max(1, Math.ceil(count / pageSize))); });

const statusType: Record<string, 'success' | 'warning' | 'error' | 'default'> = {
  healthy: 'success', degraded: 'warning', down: 'error', inactive: 'default',
};
const statusLabel: Record<string, string> = {
  healthy: '正常', degraded: '降级', down: '离线', inactive: '未连接',
};

// Create mutation
const createMutation = useMutation({
  mutationFn: () => {
    if (!ready.value) throw new Error('请先选择 Cloudflare 凭证和账户');
    if (!createName.value.trim()) throw new Error('请输入 Tunnel 名称');
    return createTunnel(createName.value.trim(), credentialId.value!, accountId.value!);
  },
  onSuccess: () => { message.success('Tunnel 已创建'); showCreate.value = false; createName.value = ''; refetch(); },
  onError: (err: any) => message.error(String(err)),
});

// Delete mutation
function confirmDelete(tunnel: Tunnel) {
  const selectedCredential = credentialId.value!;
  const selectedAccount = accountId.value!;
  const cleanupDns = ref(true);
  dlg.warning({
    title: '删除 Tunnel',
    content: () => h('div', { class: 'space-y-3' }, [
      h('p', `删除 ${tunnel.name || tunnel.id} 后将停止提供服务。存在活动连接时，请先停止 cloudflared。`),
      h(NCheckbox, { checked: cleanupDns.value, 'onUpdate:checked': (value: boolean) => { cleanupDns.value = value; } }, () => '清理此账户内指向该 Tunnel 的 CNAME（需要区域读取和 DNS 编辑权限）'),
    ]),
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const result = await deleteTunnel(tunnel.id, selectedCredential, { cleanupDns: cleanupDns.value }, selectedAccount);
        const cleanup = result.data?.cleanup;
        if (cleanup?.errors.length) {
          dlg.warning({ title: 'Tunnel 已删除，部分 DNS 清理失败', content: cleanup.errors.map(e => `${e.hostname}: ${e.message}`).join('\n'), positiveText: '知道了' });
        } else {
          message.success(cleanup ? `Tunnel 已删除，清理 ${cleanup.deleted} 条 DNS 记录` : 'Tunnel 已删除');
        }
        if (expandedId.value === tunnel.id) expandedId.value = null;
        refetch();
      } catch (err: any) {
        message.error(String(err));
        return false;
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
        <NSelect v-model:value="credentialId" :options="credentialOptions" :loading="credentialsLoading" placeholder="选择 Cloudflare 凭证" size="small" class="!w-48" :disabled="createMutation.isPending.value" />
        <NSelect v-model:value="accountId" :options="accountOptions" :loading="accountsLoading" placeholder="选择 Cloudflare 账户" size="small" class="!w-48" :disabled="!credentialId || createMutation.isPending.value" />
        <NInput v-model:value="searchKeyword" placeholder="搜索 Tunnel..." clearable size="small" class="!w-56">
          <template #prefix><Search :size="14" class="text-slate-500" /></template>
        </NInput>
        <NButton size="small" type="primary" :disabled="!ready" @click="showCreate = true">
          <template #icon><Plus :size="14" /></template>
          创建
        </NButton>
        <NButton size="small" secondary :loading="isFetching || credentialsLoading || accountsLoading" aria-label="刷新 Tunnel" @click="refetch()">
          <template #icon><RefreshCw :size="14" /></template>
        </NButton>
      </div>
    </section>

    <section class="panel p-4">
      <NAlert v-if="loadError" type="error" class="mb-4">{{ String(loadError) }}</NAlert>
      <div v-if="isLoading || credentialsLoading || accountsLoading" class="flex justify-center py-20"><NSpin size="large" /></div>
      <NEmpty v-else-if="!credentialId" description="请先在凭证管理中添加 Cloudflare 凭证" class="py-10" />
      <NEmpty v-else-if="!accountId" description="没有可用账户，请检查 Account ID 和 Token 权限" class="py-10" />
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
              <NButton text size="tiny" @click="toggleExpand(tunnel.id)">{{ expandedId === tunnel.id ? '收起' : '详情' }}</NButton>
              <NButton text size="tiny" @click="publicHostnamesTunnel = tunnel">路由</NButton>
              <NButton text size="tiny" type="error" @click="confirmDelete(tunnel)">删除</NButton>
            </div>
          </div>
          <TunnelDetailsPanel
            v-if="expandedId === tunnel.id"
            :tunnel="tunnel"
            :credential-id="credentialId!"
            :account-id="accountId!"
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
            :account-id="accountId!"
            class="panel-muted ml-10 my-2 p-4"
          />
        </div>
      </template>

      <div v-if="tunnels.length > pageSize" class="mt-4 flex justify-end">
        <NPagination
          v-model:page="page"
          :page-size="pageSize"
          :item-count="tunnels.length"
          show-quick-jumper
          size="small"
        />
      </div>
    </section>

    <!-- Create dialog -->
    <NModal v-model:show="showCreate" preset="card" title="创建 Tunnel" :style="{ width: '400px', maxWidth: 'calc(100vw - 24px)' }">
      <div class="space-y-3">
        <NFormItem label="名称" :show-feedback="false">
          <NInput v-model:value="createName" placeholder="Tunnel 名称" @keydown.enter="createMutation.mutate()" />
        </NFormItem>
        <div class="flex justify-end gap-4">
          <NButton @click="showCreate = false">取消</NButton>
          <NButton type="primary" :disabled="!createName.trim() || !ready" :loading="createMutation.isPending.value" @click="createMutation.mutate()">创建</NButton>
        </div>
      </div>
    </NModal>

    <!-- Public hostnames dialog -->
    <TunnelPublicHostnamesDialog
      v-if="publicHostnamesTunnel && credentialId"
      :tunnel="publicHostnamesTunnel"
      :credential-id="credentialId"
      :account-id="accountId!"
      @close="publicHostnamesTunnel = null"
    />
  </div>
</template>
