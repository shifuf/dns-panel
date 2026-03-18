<script setup lang="ts">
import { ref } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { NFormItem, NInput, NButton, NAlert, NTag } from 'naive-ui';
import { ShieldCheck, LogIn, ArrowLeft, KeyRound, UserRound } from 'lucide-vue-next';
import { login, verify2FA, saveAuthData } from '@/services/auth';

const router = useRouter();
const route = useRoute();

const loading = ref(false);
const errorMsg = ref('');
const requires2FA = ref(false);
const tempToken = ref('');

const loginForm = ref({ username: '', password: '' });
const tfaCode = ref('');

async function handleLogin() {
  if (!loginForm.value.username || !loginForm.value.password) {
    errorMsg.value = '请填写用户名和密码';
    return;
  }

  try {
    loading.value = true;
    errorMsg.value = '';
    const res = await login(loginForm.value);

    if (res.data.requires2FA && res.data.tempToken) {
      requires2FA.value = true;
      tempToken.value = res.data.tempToken;
      return;
    }

    if (res.data.token && res.data.user) {
      saveAuthData(res.data.token, res.data.user);
      const redirect = route.query.redirect as string;
      router.push(redirect || '/?scope=all');
    }
  } catch (err: any) {
    errorMsg.value = String(err) || '登录失败，请重试';
  } finally {
    loading.value = false;
  }
}

async function handle2FA() {
  if (!tfaCode.value || !/^\d{6}$/.test(tfaCode.value)) {
    errorMsg.value = '验证码必须是 6 位数字';
    return;
  }

  try {
    loading.value = true;
    errorMsg.value = '';
    const res = await verify2FA({ tempToken: tempToken.value, code: tfaCode.value });
    if (res.data.token && res.data.user) {
      saveAuthData(res.data.token, res.data.user);
      router.push('/?scope=all');
    }
  } catch (err: any) {
    errorMsg.value = String(err) || '验证码错误，请重试';
  } finally {
    loading.value = false;
  }
}

function goBack() {
  requires2FA.value = false;
  tempToken.value = '';
  errorMsg.value = '';
  tfaCode.value = '';
}
</script>

<template>
  <div class="min-h-screen bg-panel-bg p-4 sm:p-8">
    <div class="mx-auto grid min-h-[calc(100vh-2rem)] max-w-[1180px] grid-cols-1 gap-6 rounded-2xl border border-panel-border bg-panel-surface p-4 md:grid-cols-[1.15fr_0.95fr] md:p-6">
      <section class="panel-muted flex flex-col justify-between p-6 md:p-8">
        <div>
          <div class="mb-6 flex items-center gap-4">
            <div class="flex h-9 w-9 items-center justify-center rounded-xl border border-[#bdd2ef] bg-[#e7f1fd] text-[#2f6fbd]">
              <ShieldCheck :size="18" />
            </div>
            <p class="text-sm font-bold tracking-wide text-slate-700">DNS CONTROL DESK</p>
          </div>
          <h1 class="text-3xl font-extrabold leading-tight text-slate-800">账号登录与访问控制</h1>
          <p class="mt-3 max-w-[46ch] text-sm leading-6 text-slate-600">
            在同一工作台中管理多服务商凭证、域名解析记录、Tunnel 与审计日志。面向高频运维场景，强调可追踪和可回滚。
          </p>
        </div>

        <div class="mt-8 space-y-4">
          <div class="flex items-center gap-4">
            <NTag :bordered="false" size="small" type="success">安全验证</NTag>
            <p class="text-xs font-medium text-slate-600">支持 2FA，避免凭证误用</p>
          </div>
          <div class="flex items-center gap-4">
            <NTag :bordered="false" size="small">审计追踪</NTag>
            <p class="text-xs font-medium text-slate-600">操作日志按行为与资源分类</p>
          </div>
        </div>
      </section>

      <section class="panel p-5 md:p-8">
        <template v-if="!requires2FA">
          <h2 class="text-2xl font-extrabold text-slate-800">登录</h2>
          <p class="mt-1 text-sm font-medium text-slate-500">输入账户信息进入控制台</p>

          <NAlert v-if="errorMsg" type="error" class="mt-4" :bordered="false">
            {{ errorMsg }}
          </NAlert>

          <form class="mt-5 space-y-4" @submit.prevent="handleLogin" autocomplete="on">
            <NFormItem label="用户名或邮箱" :show-feedback="false">
              <NInput v-model:value="loginForm.username" placeholder="请输入用户名或邮箱" size="large" autocomplete="username">
                <template #prefix><UserRound :size="16" /></template>
              </NInput>
            </NFormItem>
            <NFormItem label="密码" :show-feedback="false">
              <NInput
                v-model:value="loginForm.password"
                type="password"
                show-password-on="click"
                placeholder="请输入密码"
                autocomplete="current-password"
                size="large"
                @keydown.enter="handleLogin"
              >
                <template #prefix><KeyRound :size="16" /></template>
              </NInput>
            </NFormItem>
            <NButton type="primary" block size="large" :loading="loading" attr-type="submit" class="!mt-2 !h-12 !font-bold">
              <template #icon><LogIn :size="18" /></template>
              进入控制台
            </NButton>
          </form>
          <p class="mt-5 text-sm text-slate-600">
            首次安装请先完成初始化向导，后续使用管理员账户直接登录。
          </p>
        </template>

        <template v-else>
          <button class="mb-3 inline-flex items-center gap-4 text-sm font-semibold text-slate-600 hover:text-slate-800" @click="goBack">
            <ArrowLeft :size="16" />
            返回账号登录
          </button>

          <h2 class="text-2xl font-extrabold text-slate-800">两步验证</h2>
          <p class="mt-1 text-sm font-medium text-slate-500">请输入身份验证器中的 6 位数字</p>

          <NAlert v-if="errorMsg" type="error" class="mt-4" :bordered="false">
            {{ errorMsg }}
          </NAlert>

          <form class="mt-5 space-y-4" @submit.prevent="handle2FA" autocomplete="off">
            <NFormItem :show-feedback="false">
              <NInput
                v-model:value="tfaCode"
                placeholder="000000"
                size="large"
                :maxlength="6"
                autocomplete="one-time-code"
                :input-props="{ inputmode: 'numeric', pattern: '[0-9]*', style: 'text-align:center; letter-spacing:0.45em; font-size:1.35rem;' }"
                autofocus
                @keydown.enter="handle2FA"
              />
            </NFormItem>
            <NButton type="primary" block size="large" :loading="loading" attr-type="submit" class="!h-12 !font-bold">
              <template #icon><ShieldCheck :size="18" /></template>
              完成验证
            </NButton>
          </form>
        </template>
      </section>
    </div>
  </div>
</template>
