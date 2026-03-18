<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { NAlert, NButton, NFormItem, NInput } from 'naive-ui';
import { KeyRound, Mail, ShieldCheck, UserRound, Wrench } from 'lucide-vue-next';
import { getSetupStatus, initializeSetup, saveAuthData } from '@/services/auth';
import { isStrongPassword, isValidEmail } from '@/utils/validators';

const router = useRouter();
const loading = ref(false);
const checking = ref(true);
const errorMsg = ref('');

const form = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
});

onMounted(async () => {
  try {
    const res = await getSetupStatus(true);
    if (res.data?.setupComplete) {
      router.replace('/login');
      return;
    }
  } catch {
    // Keep the wizard available even if status fetch fails temporarily.
  } finally {
    checking.value = false;
  }
});

async function handleSetup() {
  errorMsg.value = '';

  if (!form.value.username || form.value.username.trim().length < 3) {
    errorMsg.value = '用户名至少 3 个字符';
    return;
  }
  if (form.value.email && !isValidEmail(form.value.email)) {
    errorMsg.value = '请输入有效的邮箱地址';
    return;
  }
  if (!isStrongPassword(form.value.password)) {
    errorMsg.value = '密码至少 8 位，包含大小写字母和数字';
    return;
  }
  if (form.value.password !== form.value.confirmPassword) {
    errorMsg.value = '两次密码输入不一致';
    return;
  }

  try {
    loading.value = true;
    const res = await initializeSetup({
      username: form.value.username.trim(),
      email: form.value.email.trim() || undefined,
      password: form.value.password,
    });
    if (res.data.token && res.data.user) {
      saveAuthData(res.data.token, res.data.user);
      router.replace('/?scope=all');
    }
  } catch (err: any) {
    errorMsg.value = String(err) || '初始化失败，请重试';
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen bg-panel-bg p-4 sm:p-8">
    <div class="mx-auto grid min-h-[calc(100vh-2rem)] max-w-[1180px] grid-cols-1 gap-6 rounded-2xl border border-panel-border bg-panel-surface p-4 md:grid-cols-[1.1fr_0.9fr] md:p-6">
      <section class="panel-muted flex flex-col justify-between p-6 md:p-8">
        <div>
          <div class="mb-6 flex items-center gap-4">
            <div class="flex h-10 w-10 items-center justify-center rounded-xl border border-[#bfd6f5] bg-[#e8f2fe] text-[#2f6fbd]">
              <Wrench :size="18" />
            </div>
            <p class="text-sm font-bold tracking-wide text-slate-700">DNS PANEL INSTALLER</p>
          </div>
          <h1 class="text-3xl font-extrabold leading-tight text-slate-800">首次安装向导</h1>
          <p class="mt-3 max-w-[48ch] text-sm leading-6 text-slate-600">
            首次启动时创建管理员账户。公开注册已关闭，后续所有系统级操作都由该管理员账号进入控制台完成。
          </p>
        </div>

        <div class="mt-8 grid gap-3 sm:grid-cols-2">
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">01</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">创建管理员身份</p>
          </div>
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">02</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">关闭公开注册入口</p>
          </div>
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">03</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">启用审计与备份能力</p>
          </div>
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">04</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">完成后自动登录</p>
          </div>
        </div>
      </section>

      <section class="panel p-5 md:p-8">
        <div class="flex items-center gap-3">
          <ShieldCheck :size="20" class="text-emerald-600" />
          <div>
            <h2 class="text-2xl font-extrabold text-slate-800">管理员初始化</h2>
            <p class="mt-1 text-sm font-medium text-slate-500">设置系统首个管理员账号与密码</p>
          </div>
        </div>

        <NAlert v-if="errorMsg" type="error" class="mt-4" :bordered="false">
          {{ errorMsg }}
        </NAlert>

        <div v-if="checking" class="mt-8 text-sm text-slate-500">正在检查初始化状态...</div>

        <form v-else class="mt-5 space-y-4" @submit.prevent="handleSetup">
          <NFormItem label="管理员用户名" :show-feedback="false">
            <NInput v-model:value="form.username" placeholder="至少 3 个字符" size="large">
              <template #prefix><UserRound :size="16" /></template>
            </NInput>
          </NFormItem>

          <NFormItem label="邮箱（可选）" :show-feedback="false">
            <NInput v-model:value="form.email" placeholder="admin@example.com" size="large">
              <template #prefix><Mail :size="16" /></template>
            </NInput>
          </NFormItem>

          <NFormItem label="管理员密码" :show-feedback="false">
            <NInput v-model:value="form.password" type="password" show-password-on="click" placeholder="至少 8 位，含大小写和数字" size="large">
              <template #prefix><KeyRound :size="16" /></template>
            </NInput>
          </NFormItem>

          <NFormItem label="确认密码" :show-feedback="false">
            <NInput
              v-model:value="form.confirmPassword"
              type="password"
              show-password-on="click"
              placeholder="再次输入密码"
              size="large"
              @keydown.enter="handleSetup"
            />
          </NFormItem>

          <NButton type="primary" block size="large" :loading="loading" attr-type="submit" class="!h-12 !font-bold">
            <template #icon><ShieldCheck :size="18" /></template>
            创建管理员并进入控制台
          </NButton>
        </form>
      </section>
    </div>
  </div>
</template>
