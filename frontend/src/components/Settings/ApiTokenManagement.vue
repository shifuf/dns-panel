<script setup lang="ts">
import { ref } from 'vue';
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query';
import { NButton, NInput, NEmpty, NTag, useMessage, useDialog } from 'naive-ui';
import { Plus, Trash2, KeyRound, Copy, Check } from 'lucide-vue-next';
import { getApiTokens, createApiToken, deleteApiToken, type ApiToken } from '@/services/apiTokens';

const message = useMessage();
const dialog = useDialog();
const queryClient = useQueryClient();

const { data: tokens, isLoading } = useQuery({
  queryKey: ['api-tokens'],
  queryFn: async () => {
    const res = await getApiTokens();
    return (res.data || []) as ApiToken[];
  },
});

const showCreate = ref(false);
const newName = ref('');
const newlyCreated = ref<{ token: string; name: string } | null>(null);
const copied = ref(false);

const createMutation = useMutation({
  mutationFn: () => createApiToken(newName.value.trim()),
  onSuccess: (res) => {
    showCreate.value = false;
    newName.value = '';
    queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    if (res.data?.token) {
      newlyCreated.value = { token: res.data.token, name: res.data.name };
    }
  },
  onError: (err: any) => message.error(String(err)),
});

function openCreate() {
  newName.value = '';
  showCreate.value = true;
}

function handleCreate() {
  if (!newName.value.trim()) {
    message.warning('请填写 Token 名称');
    return;
  }
  createMutation.mutate();
}

async function copyToken() {
  if (!newlyCreated.value) return;
  try {
    await navigator.clipboard.writeText(newlyCreated.value.token);
    copied.value = true;
    setTimeout(() => { copied.value = false; }, 2000);
    message.success('已复制到剪贴板');
  } catch {
    message.error('复制失败，请手动选择复制');
  }
}

function handleDelete(token: ApiToken) {
  dialog.warning({
    title: '删除 API Token',
    content: `确定删除 Token「${token.name}」吗？使用该 Token 的外部集成将立即失效。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteApiToken(token.id);
        message.success('Token 已删除');
        queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-sm font-semibold text-slate-700">API Token</h3>
        <p class="text-xs text-slate-500">用于外部系统（如宝塔 SSL 插件）通过固定 Token 访问本系统 API</p>
      </div>
      <NButton size="small" type="primary" @click="openCreate">
        <template #icon><Plus :size="14" /></template>
        新建 Token
      </NButton>
    </div>

    <!-- Newly created token (shown once) -->
    <div v-if="newlyCreated" class="rounded-xl border border-emerald-200 bg-emerald-50 p-4">
      <div class="flex items-center gap-2 mb-2">
        <Check :size="16" class="text-emerald-600" />
        <span class="text-sm font-semibold text-emerald-700">Token 已创建：{{ newlyCreated.name }}</span>
      </div>
      <p class="text-xs text-slate-500 mb-2">请立即复制保存，关闭后将不再显示完整 Token。</p>
      <div class="flex items-center gap-2">
        <code class="flex-1 break-all rounded-lg bg-white border border-slate-200 px-3 py-2 text-xs text-slate-700 select-all">
          {{ newlyCreated.token }}
        </code>
        <NButton size="small" @click="copyToken">
          <template #icon>
            <Check v-if="copied" :size="14" />
            <Copy v-else :size="14" />
          </template>
          {{ copied ? '已复制' : '复制' }}
        </NButton>
        <NButton size="small" quaternary @click="newlyCreated = null">关闭</NButton>
      </div>
    </div>

    <!-- Create form -->
    <div v-if="showCreate" class="rounded-xl border border-panel-border bg-panel-surface p-4">
      <div class="flex items-end gap-3">
        <div class="flex-1">
          <label class="mb-1 block text-xs text-slate-500">Token 名称</label>
          <NInput v-model:value="newName" placeholder="如：宝塔SSL插件" size="small" @keyup.enter="handleCreate" />
        </div>
        <NButton size="small" @click="showCreate = false">取消</NButton>
        <NButton size="small" type="primary" :loading="createMutation.isPending.value" @click="handleCreate">创建</NButton>
      </div>
    </div>

    <!-- Token list -->
    <div v-if="isLoading" class="py-8 text-center text-sm text-slate-400">加载中…</div>
    <NEmpty v-else-if="!tokens || !tokens.length" description="还没有 API Token" />
    <div v-else class="space-y-2">
      <div
        v-for="t in tokens"
        :key="t.id"
        class="flex items-center gap-3 rounded-xl border border-panel-border bg-panel-surface px-4 py-3"
      >
        <KeyRound :size="18" class="shrink-0 text-slate-400" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-medium text-slate-700 truncate">{{ t.name }}</span>
            <NTag size="tiny" :bordered="false" type="info">{{ t.prefix }}…</NTag>
          </div>
          <p class="text-xs text-slate-400">创建于 {{ t.createdAt }}<span v-if="t.lastUsedAt"> · 最近使用 {{ t.lastUsedAt }}</span></p>
        </div>
        <NButton text size="small" type="error" @click="handleDelete(t)">
          <template #icon><Trash2 :size="14" /></template>
        </NButton>
      </div>
    </div>
  </div>
</template>