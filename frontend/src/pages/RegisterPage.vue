<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { NFormItem, NInput, NButton, NAlert, useMessage } from 'naive-ui';
import { UserPlus, UserRound, Mail, KeyRound } from 'lucide-vue-next';
import { register } from '@/services/auth';
import { isValidEmail, isStrongPassword } from '@/utils/validators';

const router = useRouter();
const message = useMessage();

const loading = ref(false);
const errorMsg = ref('');

const form = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
});

async function handleRegister() {
  errorMsg.value = '';

  if (!form.value.username || form.value.username.length < 3) {
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
    await register({
      username: form.value.username,
      email: form.value.email || undefined,
      password: form.value.password,
    });
    message.success('注册成功，请登录');
    router.push('/login');
  } catch (err: any) {
    errorMsg.value = String(err) || '注册失败，请重试';
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen bg-panel-bg p-4 sm:p-8">
    <div class="mx-auto grid min-h-[calc(100vh-2rem)] max-w-[1180px] grid-cols-1 gap-4 rounded-2xl border border-panel-border bg-panel-surface p-4 md:grid-cols-[1.05fr_1.05fr] md:p-6">
      <section class="panel-muted p-6 md:p-8">
        <h1 class="text-3xl font-extrabold leading-tight text-slate-800">创建运维账户</h1>
        <p class="mt-3 max-w-[46ch] text-sm leading-6 text-slate-600">
          新账号默认进入总览视图，可在设置页继续配置 DNS 服务商凭证、2FA 与到期提醒。
        </p>

        <div class="mt-8 grid gap-3 sm:grid-cols-2">
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">01</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">建立账号身份</p>
          </div>
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">02</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">绑定 DNS 凭证</p>
          </div>
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">03</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">开启告警与审计</p>
          </div>
          <div class="panel bg-panel-surface p-3">
            <p class="text-xs font-bold uppercase tracking-wide text-slate-500">04</p>
            <p class="mt-1 text-sm font-semibold text-slate-700">开始管理域名</p>
          </div>
        </div>
      </section>

      <section class="panel p-5 md:p-8">
        <h2 class="text-2xl font-extrabold text-slate-800">注册</h2>
        <p class="mt-1 text-sm font-medium text-slate-500">填写基本信息创建账户</p>

        <NAlert v-if="errorMsg" type="error" class="mt-4" :bordered="false">
          {{ errorMsg }}
        </NAlert>

        <form class="mt-5 space-y-4" @submit.prevent="handleRegister">
          <NFormItem label="用户名" :show-feedback="false">
            <NInput v-model:value="form.username" placeholder="至少 3 个字符" size="large">
              <template #prefix><UserRound :size="16" /></template>
            </NInput>
          </NFormItem>

          <NFormItem label="邮箱（可选）" :show-feedback="false">
            <NInput v-model:value="form.email" placeholder="name@example.com" size="large">
              <template #prefix><Mail :size="16" /></template>
            </NInput>
          </NFormItem>

          <NFormItem label="密码" :show-feedback="false">
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
              @keydown.enter="handleRegister"
            />
          </NFormItem>

          <NButton type="primary" block size="large" :loading="loading" attr-type="submit" class="!h-12 !font-bold">
            <template #icon><UserPlus :size="18" /></template>
            创建账户
          </NButton>
        </form>

        <p class="mt-5 text-sm text-slate-600">
          已有账户？
          <router-link to="/login" class="font-bold text-accent hover:text-accent-hover">直接登录</router-link>
        </p>
      </section>
    </div>
  </div>
</template>
