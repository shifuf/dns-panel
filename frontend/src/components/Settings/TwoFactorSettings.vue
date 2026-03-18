<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { NButton, NInput, NModal, NAlert, NTag, NSpin, useMessage } from 'naive-ui';
import { Shield, QrCode } from 'lucide-vue-next';
import { get2FAStatus, setup2FA, enable2FA, disable2FA } from '@/services/auth';

const message = useMessage();

const enabled = ref(false);
const hasSecret = ref(false);
const loading = ref(true);
const errorMsg = ref('');

// Setup dialog
const setupOpen = ref(false);
const setupStep = ref<'qr' | 'verify'>('qr');
const isRecovery = ref(false);
const qrCodeDataUrl = ref('');
const secret = ref('');
const verifyCode = ref('');
const enablePassword = ref('');
const setupLoading = ref(false);

// Disable dialog
const disableOpen = ref(false);
const disablePassword = ref('');
const disableLoading = ref(false);

onMounted(async () => {
  try {
    const res = await get2FAStatus();
    enabled.value = res.data?.enabled || false;
    hasSecret.value = res.data?.hasSecret || false;
  } catch (err: any) {
    errorMsg.value = String(err) || '获取 2FA 状态失败';
  } finally {
    loading.value = false;
  }
});

async function handleSetupStart() {
  try {
    setupLoading.value = true;
    errorMsg.value = '';
    const res = await setup2FA();
    if (res.data) {
      qrCodeDataUrl.value = res.data.qrCodeDataUrl;
      secret.value = res.data.secret;
      setupStep.value = 'qr';
      isRecovery.value = false;
      setupOpen.value = true;
    }
  } catch (err: any) {
    errorMsg.value = String(err) || '生成 2FA 密钥失败';
  } finally {
    setupLoading.value = false;
  }
}

function handleRecoverStart() {
  verifyCode.value = '';
  enablePassword.value = '';
  errorMsg.value = '';
  setupStep.value = 'verify';
  isRecovery.value = true;
  setupOpen.value = true;
}

async function handleEnable() {
  if (!verifyCode.value || verifyCode.value.length !== 6) {
    errorMsg.value = '请输入 6 位验证码';
    return;
  }
  if (!enablePassword.value) {
    errorMsg.value = '请输入密码';
    return;
  }
  try {
    setupLoading.value = true;
    errorMsg.value = '';
    await enable2FA(verifyCode.value, enablePassword.value);
    enabled.value = true;
    hasSecret.value = true;
    message.success('两步验证已成功启用');
    closeSetupDialog();
  } catch (err: any) {
    errorMsg.value = String(err) || '启用 2FA 失败';
  } finally {
    setupLoading.value = false;
  }
}

async function handleDisable() {
  if (!disablePassword.value) {
    errorMsg.value = '请输入密码';
    return;
  }
  try {
    disableLoading.value = true;
    errorMsg.value = '';
    await disable2FA(disablePassword.value);
    enabled.value = false;
    message.success('两步验证已禁用');
    closeDisableDialog();
  } catch (err: any) {
    errorMsg.value = String(err) || '禁用 2FA 失败';
  } finally {
    disableLoading.value = false;
  }
}

function closeSetupDialog() {
  setupOpen.value = false;
  verifyCode.value = '';
  enablePassword.value = '';
  qrCodeDataUrl.value = '';
  secret.value = '';
  setupStep.value = 'qr';
  isRecovery.value = false;
  errorMsg.value = '';
}

function closeDisableDialog() {
  disableOpen.value = false;
  disablePassword.value = '';
  errorMsg.value = '';
}

function onVerifyCodeInput(val: string) {
  verifyCode.value = val.replace(/\D/g, '').slice(0, 6);
}
</script>

<template>
  <section class="bento-card">
    <div v-if="loading" class="flex justify-center py-4">
      <NSpin size="small" />
    </div>

    <template v-else>
      <div class="mb-3 flex items-center justify-between">
        <div class="flex items-center gap-4">
          <Shield :size="18" class="text-accent" />
          <h3 class="text-base font-semibold text-slate-700">两步验证 (2FA)</h3>
        </div>
        <NTag :type="enabled ? 'success' : 'default'" size="small" :bordered="false">
          {{ enabled ? '已启用' : '未启用' }}
        </NTag>
      </div>

      <p class="mb-4 text-sm text-slate-400">
        启用两步验证后，登录时除了密码还需要输入身份验证器应用生成的验证码，大幅提升账户安全性。
      </p>

      <NAlert v-if="errorMsg" type="error" class="mb-3" closable @close="errorMsg = ''">
        {{ errorMsg }}
      </NAlert>

      <NButton
        v-if="enabled"
        size="small"
        type="error"
        secondary
        @click="disableOpen = true"
      >
        禁用两步验证
      </NButton>
      <template v-else>
        <div class="flex items-center gap-2">
          <NButton
            v-if="hasSecret"
            size="small"
            type="primary"
            @click="handleRecoverStart"
          >
            <template #icon><Shield :size="14" /></template>
            恢复两步验证
          </NButton>
          <NButton
            size="small"
            :type="hasSecret ? 'default' : 'primary'"
            :loading="setupLoading"
            @click="handleSetupStart"
          >
            <template #icon><QrCode :size="14" /></template>
            {{ hasSecret ? '重新设置' : '启用两步验证' }}
          </NButton>
        </div>
      </template>
    </template>

    <!-- Setup dialog -->
    <NModal
      :show="setupOpen"
      preset="card"
      :title="isRecovery ? '恢复两步验证' : '设置两步验证'"
      :style="{ width: '460px' }"
      @update:show="(v: boolean) => { if (!v) closeSetupDialog(); }"
    >
      <!-- Step 1: QR code -->
      <div v-if="setupStep === 'qr'" class="space-y-4">
        <p class="text-sm text-slate-500">请使用身份验证器应用扫描下方二维码：</p>

        <div v-if="qrCodeDataUrl" class="flex justify-center">
          <img
            :src="qrCodeDataUrl"
            alt="2FA QR Code"
            class="h-48 w-48 rounded-xl border border-panel-border"
          />
        </div>

        <NAlert type="info" :bordered="false">
          <p class="text-sm mb-1">推荐使用以下应用：</p>
          <ul class="text-sm list-disc pl-4 space-y-0.5">
            <li>Google Authenticator</li>
            <li>Microsoft Authenticator</li>
            <li>1Password</li>
            <li>Authy</li>
          </ul>
        </NAlert>

        <div>
          <p class="mb-1 text-xs text-slate-500">无法扫码？请手动输入密钥：</p>
          <NInput :value="secret" readonly size="small" class="font-mono" />
        </div>

        <NButton type="primary" block @click="setupStep = 'verify'">
          下一步：验证
        </NButton>
      </div>

      <!-- Step 2: Verify -->
      <div v-else class="space-y-4">
        <p class="text-sm text-slate-500">
          {{ isRecovery
            ? '检测到已有的两步验证密钥，请输入身份验证器应用中的验证码来恢复：'
            : '请输入身份验证器应用中显示的 6 位验证码，并确认您的账号密码：'
          }}
        </p>

        <NAlert v-if="errorMsg" type="error" :bordered="false">
          {{ errorMsg }}
        </NAlert>

        <div>
          <label class="mb-1 block text-sm font-medium text-slate-600">一次性验证码</label>
          <NInput
            :value="verifyCode"
            placeholder="输入 6 位验证码"
            size="large"
            :maxlength="6"
            :input-props="{ inputmode: 'numeric', style: 'text-align:center;letter-spacing:0.5em;font-size:1.2rem' }"
            @update:value="onVerifyCodeInput"
          />
          <p class="mt-1 text-xs text-slate-400">打开身份验证器应用，输入当前显示的 6 位数字</p>
        </div>

        <div>
          <label class="mb-1 block text-sm font-medium text-slate-600">账号密码</label>
          <NInput
            v-model:value="enablePassword"
            type="password"
            show-password-on="click"
            placeholder="输入您的登录密码"
            size="small"
          />
        </div>

        <div class="flex gap-4">
          <NButton v-if="isRecovery" class="flex-1" @click="closeSetupDialog">取消</NButton>
          <NButton v-else class="flex-1" @click="setupStep = 'qr'">返回</NButton>
          <NButton
            type="primary"
            class="flex-1"
            :loading="setupLoading"
            :disabled="verifyCode.length !== 6 || !enablePassword"
            @click="handleEnable"
          >
            {{ isRecovery ? '恢复' : '启用' }}
          </NButton>
        </div>
      </div>
    </NModal>

    <!-- Disable dialog -->
    <NModal
      :show="disableOpen"
      preset="card"
      title="禁用两步验证"
      :style="{ width: '400px' }"
      @update:show="(v: boolean) => { if (!v) closeDisableDialog(); }"
    >
      <div class="space-y-4">
        <NAlert type="warning" :bordered="false">
          禁用两步验证后，您的账户安全性将降低。
        </NAlert>

        <NAlert v-if="errorMsg" type="error" :bordered="false">
          {{ errorMsg }}
        </NAlert>

        <NInput
          v-model:value="disablePassword"
          type="password"
          show-password-on="click"
          placeholder="请输入密码确认"
          size="small"
        />

        <div class="flex justify-end gap-4">
          <NButton size="small" @click="closeDisableDialog">取消</NButton>
          <NButton
            size="small"
            type="error"
            :loading="disableLoading"
            :disabled="!disablePassword"
            @click="handleDisable"
          >
            确认禁用
          </NButton>
        </div>
      </div>
    </NModal>
  </section>
</template>
