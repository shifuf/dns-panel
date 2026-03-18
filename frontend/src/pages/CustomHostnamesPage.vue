<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useQuery, useMutation } from '@tanstack/vue-query';
import { NInput, NButton, NDataTable, NModal, NFormItem, NTag, NEmpty, NSpin, NPagination, useMessage } from 'naive-ui';
import { Plus, Settings, Search, Trash2, ArrowLeft } from 'lucide-vue-next';
import { getCustomHostnames, createCustomHostname, deleteCustomHostname, getFallbackOrigin, updateFallbackOrigin } from '@/services/hostnames';
import { useCredentialResolver } from '@/composables/useCredentialResolver';
import { useResponsive } from '@/composables/useResponsive';
import type { CustomHostname } from '@/types';
import { h } from 'vue';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const { credentialId } = useCredentialResolver();
const { isMobile } = useResponsive();

const zoneId = computed(() => route.params.zoneId as string);
const searchKeyword = ref('');
const showAdd = ref(false);
const showFallback = ref(false);
const newHostname = ref('');
const newOriginServer = ref('');
const fallbackOrigin = ref('');
const page = ref(1);
const pageSize = ref(parseInt(localStorage.getItem('dns_hostnames_page_size') || '20'));

// Hostnames query
const { data: hostnamesData, isLoading, refetch } = useQuery({
  queryKey: computed(() => ['hostnames', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getCustomHostnames(zoneId.value, credentialId.value);
    return res.data?.hostnames || [];
  },
  enabled: computed(() => !!zoneId.value),
});

const hostnames = computed(() => {
  const all = hostnamesData.value || [];
  if (!searchKeyword.value) return all;
  const q = searchKeyword.value.toLowerCase();
  return all.filter(h => h.hostname.toLowerCase().includes(q));
});

const paginatedHostnames = computed(() => {
  const start = (page.value - 1) * pageSize.value;
  return hostnames.value.slice(start, start + pageSize.value);
});

watch([searchKeyword, pageSize], () => { page.value = 1; });
watch(pageSize, (size) => {
  localStorage.setItem('dns_hostnames_page_size', String(size));
});

// Fallback origin query
const { data: fallbackData, refetch: refetchFallback } = useQuery({
  queryKey: computed(() => ['fallback-origin', zoneId.value, credentialId.value]),
  queryFn: async () => {
    const res = await getFallbackOrigin(zoneId.value, credentialId.value);
    return res.data?.origin || '';
  },
  enabled: computed(() => !!zoneId.value),
});

// Mutations
const createMutation = useMutation({
  mutationFn: () => createCustomHostname(zoneId.value, newHostname.value, { credentialId: credentialId.value, customOriginServer: newOriginServer.value || undefined }),
  onSuccess: () => { message.success('主机名已添加'); showAdd.value = false; newHostname.value = ''; newOriginServer.value = ''; refetch(); },
  onError: (err: any) => message.error(String(err)),
});

const deleteMutation = useMutation({
  mutationFn: (hostnameId: string) => deleteCustomHostname(zoneId.value, hostnameId, credentialId.value),
  onSuccess: () => { message.success('主机名已删除'); refetch(); },
  onError: (err: any) => message.error(String(err)),
});

const updateFallbackMutation = useMutation({
  mutationFn: () => updateFallbackOrigin(zoneId.value, fallbackOrigin.value, credentialId.value),
  onSuccess: () => { message.success('回退源已更新'); showFallback.value = false; refetchFallback(); },
  onError: (err: any) => message.error(String(err)),
});

function openFallbackDialog() {
  fallbackOrigin.value = fallbackData.value || '';
  showFallback.value = true;
}

const columns = computed(() => [
  { title: '主机名', key: 'hostname', minWidth: 200, ellipsis: { tooltip: true } },
  {
    title: 'SSL 状态', key: 'ssl', width: 120,
    render: (row: CustomHostname) => h(NTag, {
      type: row.ssl?.status === 'active' ? 'success' : row.ssl?.status === 'pending' ? 'warning' : 'default',
      size: 'small', bordered: false,
    }, () => row.ssl?.status || '-'),
  },
  {
    title: '状态', key: 'status', width: 100,
    render: (row: CustomHostname) => h(NTag, {
      type: row.status === 'active' ? 'success' : 'warning',
      size: 'small', bordered: false,
    }, () => row.status || '-'),
  },
  {
    title: '', key: 'actions', width: 50, fixed: 'right' as const,
    render: (row: CustomHostname) => h(NButton, {
      text: true, type: 'error', size: 'small',
      onClick: () => deleteMutation.mutate(row.id),
    }, { icon: () => h(Trash2, { size: 14 }) }),
  },
]);
</script>

<template>
  <div class="space-y-4">
    <section class="panel p-4">
      <div class="toolbar-row">
        <button
          v-if="isMobile"
          class="rounded-xl border border-panel-border bg-panel-surface p-1.5 text-slate-500"
          @click="router.back()"
          aria-label="返回"
        >
          <ArrowLeft :size="16" />
        </button>
        <div>
          <h1 class="page-title">Custom Hostnames</h1>
          <p class="page-subtitle">Cloudflare 自定义主机名与 fallback origin 管理</p>
        </div>
        <div class="flex-1" />
        <NInput v-model:value="searchKeyword" placeholder="搜索 hostname..." clearable size="small" class="!w-56">
          <template #prefix><Search :size="14" class="text-slate-500" /></template>
        </NInput>
        <NButton size="small" secondary @click="openFallbackDialog">
          <template #icon><Settings :size="14" /></template>
          回退源
        </NButton>
        <NButton size="small" type="primary" @click="showAdd = true">
          <template #icon><Plus :size="14" /></template>
          添加
        </NButton>
      </div>
    </section>

    <section class="panel p-4">
      <div v-if="isLoading" class="flex justify-center py-20"><NSpin size="large" /></div>
      <NEmpty v-else-if="hostnames.length === 0" description="暂无自定义主机名" class="py-10" />

      <div v-else-if="isMobile" class="space-y-4">
        <div v-for="hn in paginatedHostnames" :key="hn.id" class="panel-muted p-3">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-sm font-mono text-slate-700">{{ hn.hostname }}</span>
            <NButton text size="tiny" type="error" @click="deleteMutation.mutate(hn.id)">
              <template #icon><Trash2 :size="12" /></template>
            </NButton>
          </div>
          <div class="flex gap-4">
            <NTag :type="hn.ssl?.status === 'active' ? 'success' : 'warning'" size="small" :bordered="false">SSL: {{ hn.ssl?.status || '-' }}</NTag>
            <NTag :type="hn.status === 'active' ? 'success' : 'default'" size="small" :bordered="false">{{ hn.status || '-' }}</NTag>
          </div>
        </div>
      </div>

      <NDataTable
        v-else
        :columns="columns"
        :data="paginatedHostnames"
        :row-key="(r: CustomHostname) => r.id"
        :bordered="false"
        size="small"
        class="table-scrollable"
        :scroll-x="700"
        :max-height="560"
        :virtual-scroll="paginatedHostnames.length > 120"
      />

      <div v-if="hostnames.length > pageSize" class="mt-4 flex justify-end">
        <NPagination
          v-model:page="page"
          v-model:page-size="pageSize"
          :item-count="hostnames.length"
          :page-sizes="[20, 50, 100]"
          show-size-picker
          show-quick-jumper
          size="small"
        />
      </div>
    </section>

    <!-- Add dialog -->
    <NModal v-model:show="showAdd" preset="card" title="添加自定义主机名" :style="{ width: '440px' }">
      <div class="space-y-3">
        <NFormItem label="主机名" :show-feedback="false">
          <NInput v-model:value="newHostname" placeholder="custom.example.com" />
        </NFormItem>
        <NFormItem label="自定义源服务器（可选）" :show-feedback="false">
          <NInput v-model:value="newOriginServer" placeholder="origin.example.com" />
        </NFormItem>
        <div class="flex justify-end gap-4">
          <NButton @click="showAdd = false">取消</NButton>
          <NButton type="primary" :loading="createMutation.isPending.value" @click="createMutation.mutate()">添加</NButton>
        </div>
      </div>
    </NModal>

    <!-- Fallback dialog -->
    <NModal v-model:show="showFallback" preset="card" title="回退源设置" :style="{ width: '440px' }">
      <div class="space-y-3">
        <NFormItem label="回退源域名" :show-feedback="false">
          <NInput v-model:value="fallbackOrigin" placeholder="fallback.example.com" />
        </NFormItem>
        <div class="flex justify-end gap-4">
          <NButton @click="showFallback = false">取消</NButton>
          <NButton type="primary" :loading="updateFallbackMutation.isPending.value" @click="updateFallbackMutation.mutate()">保存</NButton>
        </div>
      </div>
    </NModal>
  </div>
</template>
