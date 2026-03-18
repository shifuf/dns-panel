<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { NButton, NInput, NModal, NAlert, NEmpty, NSpin, useMessage, useDialog } from 'naive-ui';
import { Plus, Pencil, Trash2, Key } from 'lucide-vue-next';
import { createCredential, updateCredential, deleteCredential, verifyCredential } from '@/services/credentials';
import type { CfCredential } from '@/types';

const message = useMessage();
const dlg = useDialog();

const props = defineProps<{
  accounts: CfCredential[];
  loading: boolean;
}>();

const emit = defineEmits<{ refresh: [] }>();

// Dialog state
const dialogOpen = ref(false);
const editing = ref<CfCredential | null>(null);
const formName = ref('');
const formToken = ref('');
const submitError = ref('');
const submitting = ref(false);

function openAdd() {
  editing.value = null;
  formName.value = '';
  formToken.value = '';
  submitError.value = '';
  dialogOpen.value = true;
}

function openEdit(cred: CfCredential) {
  editing.value = cred;
  formName.value = cred.name;
  formToken.value = '';
  submitError.value = '';
  dialogOpen.value = true;
}

function closeDialog() {
  dialogOpen.value = false;
  editing.value = null;
}

async function handleSubmit() {
  if (!formName.value.trim()) { submitError.value = '请输入账户别名'; return; }
  if (!editing.value && !formToken.value.trim()) { submitError.value = '请输入 API Token'; return; }

  try {
    submitting.value = true;
    submitError.value = '';

    if (editing.value) {
      const data: any = { name: formName.value };
      if (formToken.value) data.apiToken = formToken.value;
      await updateCredential(editing.value.id, data);
    } else {
      await createCredential({ name: formName.value, apiToken: formToken.value });
    }

    emit('refresh');
    closeDialog();
    message.success(editing.value ? '已更新' : '已创建');
  } catch (err: any) {
    submitError.value = typeof err === 'string' ? err : (err?.message || '操作失败');
  } finally {
    submitting.value = false;
  }
}

function confirmDelete(cred: CfCredential) {
  dlg.warning({
    title: '确认删除',
    content: `确定要删除账户 ${cred.name} 吗？此操作不可恢复。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteCredential(cred.id);
        emit('refresh');
        message.success('已删除');
      } catch (err: any) {
        message.error(String(err));
      }
    },
  });
}
</script>

<template>
  <section class="bento-card">
    <div class="mb-4 flex items-center justify-between">
      <div class="flex items-center gap-4">
        <Key :size="18" class="text-accent" />
        <h3 class="text-base font-semibold text-slate-700">多账户管理</h3>
      </div>
      <NButton size="small" type="primary" @click="openAdd">
        <template #icon><Plus :size="14" /></template>
        新增账户
      </NButton>
    </div>
    <p class="text-xs text-slate-500 mb-4">管理您的 Cloudflare 账户凭证</p>

    <div v-if="loading" class="flex justify-center py-6"><NSpin size="small" /></div>

    <NEmpty v-else-if="accounts.length === 0" description="暂无账户" size="small" />

    <div v-else class="space-y-4">
      <div
        v-for="acc in accounts"
        :key="acc.id"
        class="flex items-center gap-4 rounded-xl border border-panel-border bg-panel-bg p-3"
      >
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm font-semibold text-slate-700">{{ acc.name }}</p>
          <p class="text-xs text-slate-500 font-mono">Token: **** ****</p>
        </div>
        <div class="flex gap-4">
          <NButton text size="tiny" @click="openEdit(acc)">
            <template #icon><Pencil :size="12" /></template>
          </NButton>
          <NButton text size="tiny" type="error" @click="confirmDelete(acc)">
            <template #icon><Trash2 :size="12" /></template>
          </NButton>
        </div>
      </div>
    </div>

    <!-- Add/Edit dialog -->
    <NModal
      :show="dialogOpen"
      preset="card"
      :title="editing ? '编辑账户' : '新增账户'"
      :style="{ width: '420px' }"
      @update:show="(v: boolean) => { if (!v) closeDialog(); }"
    >
      <div class="space-y-3">
        <NAlert v-if="submitError" type="error" :bordered="false">{{ submitError }}</NAlert>

        <NInput
          v-model:value="formName"
          placeholder="账户别名"
          size="small"
        />

        <NInput
          v-model:value="formToken"
          type="password"
          show-password-on="click"
          :placeholder="editing ? '新 API Token（留空则不修改）' : 'Cloudflare API Token'"
          size="small"
        />
        <p class="text-xs text-slate-500">
          请确保 Token 拥有 区域(Zone) 读取 和 区域.DNS(编辑) 权限
        </p>

        <div class="flex justify-end gap-4">
          <NButton size="small" @click="closeDialog">取消</NButton>
          <NButton size="small" type="primary" :loading="submitting" @click="handleSubmit">保存</NButton>
        </div>
      </div>
    </NModal>
  </section>
</template>
