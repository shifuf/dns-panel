<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { NCheckbox, NInput, NButton, NSwitch, NRadioGroup, NRadio, useMessage, NTabs, NTab } from 'naive-ui';
import { Save, Info, Download, Upload, Database, RefreshCw, ShieldCheck } from 'lucide-vue-next';
import { useQueryClient } from '@tanstack/vue-query';
import type { BackupPayload } from '@/types';
import { getStoredUser, updatePassword, updateDomainExpirySettings, saveAuthData, getSystemSettings, updateSystemSettings, exportBackup, restoreBackup } from '@/services/auth';
import { isStrongPassword } from '@/utils/validators';
import { TABLE_PAGE_SIZE } from '@/utils/constants';
import TwoFactorSettings from '@/components/Settings/TwoFactorSettings.vue';
import DnsCredentialManagement from '@/components/Settings/DnsCredentialManagement.vue';
import api from '@/services/api';
import { useProviderStore } from '@/stores/provider';

// Tab state
const activeTab = ref('general');

const message = useMessage();
const queryClient = useQueryClient();
const providerStore = useProviderStore();
const user = getStoredUser();
const isAdmin = computed(() => !user?.role || user.role === 'admin');
const APP_VERSION = ref('...');
const appVersionLabel = computed(() => {
  const version = APP_VERSION.value.trim() || '0.02';
  return version.startsWith('v') ? version : `v${version}`;
});

// System settings
const systemSettingsLoading = ref(false);
const logRetentionDays = ref('90');
const backupDns = ref(true);
const backupSsl = ref(true);
const restoreDns = ref(true);
const restoreSsl = ref(true);
const restoreOverwrite = ref(true);
const restoreLoading = ref(false);
const exportLoading = ref(false);
const selectedBackupFile = ref<File | null>(null);
const restoreFileInput = ref<HTMLInputElement | null>(null);
const dnsCredentialPanelKey = ref(0);

onMounted(async () => {
  try {
    const res = await api.get('/version');
    const data = res as any;
    APP_VERSION.value = data?.version || data?.data?.version || '0.02';
  } catch {
    APP_VERSION.value = '0.02';
  }
  try {
    const sysRes = await getSystemSettings();
    const sd = (sysRes as any)?.data || sysRes;
    logRetentionDays.value = String(sd?.logRetentionDays || 90);
  } catch { /* ignore */ }
});

async function saveSystemSettings() {
  systemSettingsLoading.value = true;
  try {
    const retention = parseInt(logRetentionDays.value, 10);
    if (Number.isNaN(retention) || retention < 1) {
      message.error('日志保留时长至少为 1 天');
      return;
    }
    await updateSystemSettings({ logRetentionDays: retention });
    message.success('系统设置已保存');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    systemSettingsLoading.value = false;
  }
}

// Password form
const oldPassword = ref('');
const newPassword = ref('');
const confirmPassword = ref('');
const pwdLoading = ref(false);

async function handlePasswordChange() {
  if (!oldPassword.value || !newPassword.value) { message.error('请填写密码'); return; }
  if (!isStrongPassword(newPassword.value)) { message.error('密码至少 8 位，包含大小写字母和数字'); return; }
  if (newPassword.value !== confirmPassword.value) { message.error('两次密码不一致'); return; }

  try {
    pwdLoading.value = true;
    await updatePassword({ oldPassword: oldPassword.value, newPassword: newPassword.value });
    message.success('密码已修改');
    oldPassword.value = '';
    newPassword.value = '';
    confirmPassword.value = '';
  } catch (err: any) {
    message.error(String(err));
  } finally {
    pwdLoading.value = false;
  }
}

// Domain settings
const expiryDisplayMode = ref<'date' | 'days'>('date');
const expiryThresholdDays = ref('7');
const expiryNotifyEnabled = ref(false);
const expiryWebhookUrl = ref('');
const expiryEmailEnabled = ref(false);
const expiryEmailTo = ref('');
const smtpHost = ref('');
const smtpPort = ref('587');
const smtpSecure = ref(false);
const smtpUser = ref('');
const smtpPass = ref('');
const smtpFrom = ref('');
const expirySaving = ref(false);

const profileScore = computed(() => {
  let score = 0;
  if (expiryNotifyEnabled.value) score += 1;
  if (expiryEmailEnabled.value) score += 1;
  if ((parseInt(expiryThresholdDays.value, 10) || 7) <= 14) score += 1;
  return score;
});

const profileLevel = computed(() => {
  if (profileScore.value >= 3) return '高';
  if (profileScore.value === 2) return '中';
  return '基础';
});

const selectedBackupName = computed(() => selectedBackupFile.value?.name || '未选择文件');
const backupScopeSummary = computed(() => getSelectedScopes('backup').map((scope) => scope.toUpperCase()));
const restoreScopeSummary = computed(() => getSelectedScopes('restore').map((scope) => scope.toUpperCase()));

onMounted(() => {
  if (user) {
    expiryDisplayMode.value = user.domainExpiryDisplayMode || 'date';
    expiryThresholdDays.value = String(user.domainExpiryThresholdDays || 7);
    expiryNotifyEnabled.value = user.domainExpiryNotifyEnabled || false;
    expiryWebhookUrl.value = user.domainExpiryNotifyWebhookUrl || '';
    expiryEmailEnabled.value = user.domainExpiryNotifyEmailEnabled || false;
    expiryEmailTo.value = user.domainExpiryNotifyEmailTo || '';
    smtpHost.value = user.smtpHost || '';
    smtpPort.value = String(user.smtpPort || 587);
    smtpSecure.value = user.smtpSecure || false;
    smtpUser.value = user.smtpUser || '';
    smtpFrom.value = user.smtpFrom || '';
  }
});

async function saveExpirySettings() {
  try {
    expirySaving.value = true;
    const res = await updateDomainExpirySettings({
      displayMode: expiryDisplayMode.value,
      thresholdDays: parseInt(expiryThresholdDays.value) || 7,
      notifyEnabled: expiryNotifyEnabled.value,
      webhookUrl: expiryWebhookUrl.value || null,
      notifyEmailEnabled: expiryEmailEnabled.value,
      emailTo: expiryEmailTo.value || null,
      smtpHost: smtpHost.value || null,
      smtpPort: parseInt(smtpPort.value) || null,
      smtpSecure: smtpSecure.value || null,
      smtpUser: smtpUser.value || null,
      smtpPass: smtpPass.value || null,
      smtpFrom: smtpFrom.value || null,
    });
    if (res.data?.user) {
      const token = localStorage.getItem('token');
      if (token) saveAuthData(token, res.data.user);
    }
    message.success('已保存');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    expirySaving.value = false;
  }
}

async function refreshRestoredData() {
  await Promise.allSettled([
    providerStore.loadData(),
    queryClient.invalidateQueries({ queryKey: ['domains'] }),
    queryClient.invalidateQueries({ queryKey: ['ssl-credentials'] }),
    queryClient.invalidateQueries({ queryKey: ['ssl-certificates'] }),
    queryClient.invalidateQueries({ queryKey: ['dns-credentials-for-ssl'] }),
    queryClient.invalidateQueries({ queryKey: ['managed-domains-for-ssl'] }),
    queryClient.invalidateQueries({ queryKey: ['dashboard-logs-24h'] }),
    queryClient.invalidateQueries({ queryKey: ['dashboard-audit-list'] }),
    queryClient.invalidateQueries({ queryKey: ['logs'] }),
  ]);
  dnsCredentialPanelKey.value += 1;
  window.dispatchEvent(new CustomEvent('dns-data-restored'));
}

function getSelectedScopes(type: 'backup' | 'restore') {
  const scopes: string[] = [];
  if ((type === 'backup' ? backupDns.value : restoreDns.value)) scopes.push('dns');
  if ((type === 'backup' ? backupSsl.value : restoreSsl.value)) scopes.push('ssl');
  return scopes;
}

async function handleExportBackup() {
  const scopes = getSelectedScopes('backup');
  if (scopes.length === 0) {
    message.error('至少选择一个备份范围');
    return;
  }

  try {
    exportLoading.value = true;
    const res = await exportBackup({ scopes });
    const backup = (res.data?.backup || {}) as BackupPayload;
    const filename = res.data?.filename || `dns-panel-backup-${Date.now()}.json`;
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    message.success('备份文件已导出');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    exportLoading.value = false;
  }
}

function handleBackupFileChange(event: Event) {
  const input = event.target as HTMLInputElement;
  selectedBackupFile.value = input.files?.[0] || null;
}

async function handleRestoreBackup() {
  const scopes = getSelectedScopes('restore');
  if (scopes.length === 0) {
    message.error('至少选择一个恢复范围');
    return;
  }
  if (!selectedBackupFile.value) {
    message.error('请先选择备份文件');
    return;
  }
  if (!window.confirm(`将恢复 ${scopes.join(' / ')} 数据，是否继续？`)) {
    return;
  }

  try {
    restoreLoading.value = true;
    const raw = await selectedBackupFile.value.text();
    const payload = JSON.parse(raw) as BackupPayload;
    const res = await restoreBackup({
      payload,
      scopes,
      overwrite: restoreOverwrite.value,
    });
    await refreshRestoredData();
    selectedBackupFile.value = null;
    if (restoreFileInput.value) {
      restoreFileInput.value.value = '';
    }
    const restored = res.data?.restored || {};
    message.success(`恢复完成：DNS ${restored.dnsCredentials || 0}，SSL 凭证 ${restored.sslCredentials || 0}，SSL 证书 ${restored.sslCertificates || 0}`);
  } catch (err: any) {
    message.error(String(err));
  } finally {
    restoreLoading.value = false;
  }
}
</script>

<template>
  <div class="settings-page">
    <div class="settings-header">
      <div class="section-badge">
        <span class="dot" />
        <span class="label">System Preferences</span>
      </div>
      <h1 class="page-title">
        系统设置
      </h1>
      <p class="page-subtitle">配置全局系统行为、重试策略和存储。</p>
    </div>

    <NTabs v-model:value="activeTab" type="line" class="settings-tabs">
      <NTab name="general" label="常规" />
      <NTab name="retry" label="重试" />
      <NTab name="storage" label="存储" />
      <NTab name="backup" label="备份" />
      <NTab name="about" label="关于" />
    </NTabs>

    <div class="settings-content">
      <!-- 常规选项卡 -->
      <div v-if="activeTab === 'general'" class="settings-tab-content">
        <!-- 统计卡片部分 -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          <article class="bento-card p-4 relative overflow-hidden">
            <div class="absolute -left-12 -bottom-12 w-36 h-36 rounded-full bg-gradient-to-br from-blue-500/15 to-indigo-500/15 blur-xl" />
            <div class="absolute left-3 bottom-3 w-12 h-12 rounded-full bg-gradient-to-br from-blue-400/25 to-indigo-400/25 blur-lg" />
            <div class="relative z-10">
              <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">域名分页</p>
              <p class="mt-2 text-3xl text-slate-700">{{ TABLE_PAGE_SIZE }} 条/页</p>
              <div class="mt-3 flex items-center gap-2">
                <span class="text-xs text-slate-500">统一默认</span>
                <span class="text-xs font-semibold text-blue-600">所有表格自动分页</span>
              </div>
            </div>
          </article>
          <article class="bento-card p-4 relative overflow-hidden">
            <div class="absolute -right-14 -top-14 w-40 h-40 rounded-full bg-gradient-to-br from-violet-500/15 to-purple-500/15 blur-xl" />
            <div class="absolute right-4 top-4 w-12 h-12 rounded-full bg-gradient-to-br from-violet-400/25 to-purple-400/25 blur-lg" />
            <div class="relative z-10">
              <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">到期展示</p>
              <p class="mt-2 text-3xl text-slate-700">{{ expiryDisplayMode === 'days' ? '剩余天数' : '日期' }}</p>
              <div class="mt-3 flex items-center gap-2">
                <span class="text-xs text-slate-500">提醒阈值</span>
                <span class="text-xs font-semibold text-violet-600">{{ expiryThresholdDays }} 天</span>
              </div>
            </div>
          </article>
          <article class="bento-card p-4 relative overflow-hidden">
            <div class="absolute -left-10 -top-10 w-32 h-32 rounded-full bg-gradient-to-br from-emerald-500/15 to-teal-500/15 blur-xl" />
            <div class="absolute left-3 top-3 w-10 h-10 rounded-full bg-gradient-to-br from-emerald-400/25 to-teal-400/25 blur-lg" />
            <div class="relative z-10">
              <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">日志保留</p>
              <p class="mt-2 text-3xl text-emerald-700">{{ logRetentionDays }} 天</p>
              <div class="mt-3 flex items-center gap-2">
                <span class="text-xs text-slate-500">自动清理</span>
                <span class="text-xs font-semibold text-emerald-600">{{ logRetentionDays }} 天</span>
              </div>
            </div>
          </article>
          <article class="bento-card p-4 relative overflow-hidden">
            <div class="absolute -right-10 -bottom-10 w-32 h-32 rounded-full bg-gradient-to-br from-amber-500/15 to-orange-500/15 blur-xl" />
            <div class="absolute right-3 bottom-3 w-10 h-10 rounded-full bg-gradient-to-br from-amber-400/25 to-orange-400/25 blur-lg" />
            <div class="relative z-10">
              <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">系统版本</p>
              <p class="mt-2 text-3xl bg-gradient-to-r from-amber-600 to-orange-600 bg-clip-text text-transparent">{{ appVersionLabel }}</p>
              <div class="mt-3 flex items-center gap-2">
                <span class="text-xs text-slate-500">当前版本</span>
                <span class="text-xs font-semibold text-amber-600">{{ appVersionLabel }}</span>
              </div>
            </div>
          </article>
        </div>

        <!-- 设置表单部分 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- 左侧表单 -->
          <div>
            <div class="bento-card">
              <p class="bento-section-title">账户安全</p>
              <p class="bento-section-meta">修改登录密码，建议配合 2FA 使用</p>
              <h3 class="mb-3 mt-2 text-base font-semibold text-slate-700">修改密码</h3>
              <div class="space-y-3">
                <div class="settings-subpanel">
                  <p class="settings-subpanel-label">当前密码</p>
                  <NInput v-model:value="oldPassword" type="password" show-password-on="click" placeholder="请输入当前密码" size="small" />
                </div>
                <div class="settings-subpanel">
                  <p class="settings-subpanel-label">新密码</p>
                  <NInput v-model:value="newPassword" type="password" show-password-on="click" placeholder="至少 8 位，含大小写和数字" size="small" />
                </div>
                <div class="settings-subpanel">
                  <p class="settings-subpanel-label">确认密码</p>
                  <NInput v-model:value="confirmPassword" type="password" show-password-on="click" placeholder="再次输入新密码" size="small" />
                </div>
                <NButton type="primary" size="small" :loading="pwdLoading" @click="handlePasswordChange">
                  <template #icon><Save :size="14" /></template>
                  修改密码
                </NButton>
              </div>
            </div>

            <div class="bento-card mt-6">
              <TwoFactorSettings />
            </div>
          </div>

          <!-- 右侧表单 -->
          <div>
            <div class="bento-card">
              <p class="bento-section-title">到期策略</p>
              <p class="bento-section-meta">统一设置展示与通知触发策略</p>
              <h3 class="mb-3 mt-2 text-base font-semibold text-slate-700">域名设置</h3>
              <div class="space-y-3">
                <div class="settings-subpanel">
                  <label class="mb-2 block text-sm text-slate-400">到期显示方式</label>
                  <NRadioGroup v-model:value="expiryDisplayMode" size="small">
                    <NRadio value="date">日期</NRadio>
                    <NRadio value="days">剩余天数</NRadio>
                  </NRadioGroup>
                </div>

                <div class="settings-subpanel">
                  <label class="mb-1 block text-sm text-slate-400">到期提醒阈值（天）</label>
                  <NInput v-model:value="expiryThresholdDays" type="number" size="small" class="!w-24" />
                </div>

                <div class="settings-subpanel">
                  <div class="flex items-center gap-4">
                    <NSwitch v-model:value="expiryNotifyEnabled" size="small" />
                    <span class="text-sm text-slate-600">Webhook 通知</span>
                  </div>
                  <NInput v-if="expiryNotifyEnabled" class="mt-3" v-model:value="expiryWebhookUrl" placeholder="Webhook URL" size="small" />
                </div>

                <div class="settings-subpanel">
                  <div class="flex items-center gap-4">
                    <NSwitch v-model:value="expiryEmailEnabled" size="small" />
                    <span class="text-sm text-slate-600">邮件通知</span>
                  </div>
                  <template v-if="expiryEmailEnabled">
                    <NInput class="mt-3" v-model:value="expiryEmailTo" placeholder="收件邮箱" size="small" />
                    <div class="mt-3 grid grid-cols-2 gap-4">
                      <NInput v-model:value="smtpHost" placeholder="SMTP 服务器" size="small" />
                      <NInput v-model:value="smtpPort" placeholder="端口" size="small" />
                    </div>
                    <div class="mt-3 grid grid-cols-2 gap-4">
                      <NInput v-model:value="smtpUser" placeholder="用户名" size="small" />
                      <NInput v-model:value="smtpPass" type="password" show-password-on="click" placeholder="密码" size="small" />
                    </div>
                    <NInput class="mt-3" v-model:value="smtpFrom" placeholder="发件人地址" size="small" />
                    <div class="mt-3 flex items-center gap-4">
                      <NSwitch v-model:value="smtpSecure" size="small" />
                      <span class="text-sm text-slate-400">SSL/TLS</span>
                    </div>
                  </template>
                </div>

                <NButton type="primary" size="small" :loading="expirySaving" @click="saveExpirySettings">
                  <template #icon><Save :size="14" /></template>
                  保存到期设置
                </NButton>
              </div>
            </div>
          </div>
        </div>

        <!-- DNS 凭证管理部分 -->
        <div class="mt-6">
          <div class="bento-card">
            <p class="bento-section-title">DNS 凭证仓库</p>
            <p class="bento-section-meta">按服务商维护账户，支持校验、编辑与删除</p>
            <div class="mt-4">
              <DnsCredentialManagement :key="dnsCredentialPanelKey" />
            </div>
          </div>
        </div>
      </div>



      <!-- 重试选项卡 -->
      <div v-if="activeTab === 'retry'" class="settings-tab-content">
        <div class="bento-card">
          <p class="bento-section-title">重试策略</p>
          <p class="bento-section-meta">配置 DNS 操作的重试机制</p>
          <div class="space-y-4">
            <div class="settings-subpanel">
              <p class="settings-subpanel-label">最大重试次数</p>
              <NInput type="number" placeholder="输入最大重试次数" size="small" />
            </div>
            <div class="settings-subpanel">
              <p class="settings-subpanel-label">重试间隔（秒）</p>
              <NInput type="number" placeholder="输入重试间隔" size="small" />
            </div>
            <NButton type="primary" size="small">
              <template #icon><Save :size="14" /></template>
              保存重试设置
            </NButton>
          </div>
        </div>
      </div>

      <!-- 存储选项卡 -->
      <div v-if="activeTab === 'storage'" class="settings-tab-content">
        <div class="bento-card">
          <p class="bento-section-title">存储设置</p>
          <p class="bento-section-meta">配置数据存储和日志保留策略</p>
          <div class="space-y-4">
            <div v-if="isAdmin" class="settings-subpanel">
              <p class="settings-subpanel-label">日志保留时长（天）</p>
              <div class="flex items-center gap-2">
                <NInput v-model:value="logRetentionDays" type="number" size="small" class="!w-20" />
                <span class="text-xs text-slate-400">天</span>
              </div>
              <NButton class="mt-3 w-full" size="small" :loading="systemSettingsLoading" @click="saveSystemSettings">保存日志策略</NButton>
            </div>
            <div class="settings-subpanel">
              <p class="settings-subpanel-label">存储路径</p>
              <NInput placeholder="输入存储路径" size="small" />
            </div>
          </div>
        </div>
      </div>

      <!-- 备份选项卡 -->
      <div v-if="activeTab === 'backup'" class="settings-tab-content">
        <div v-if="isAdmin" class="bento-card overflow-hidden">
          <div class="settings-workbench">
            <div class="settings-workbench-head">
              <div>
                <div class="section-badge">
                  <span class="dot" />
                  <span class="label">Backup Console</span>
                </div>
                <h2 class="mt-3 text-2xl font-extrabold text-slate-800">数据备份与恢复工作台</h2>
                <p class="mt-2 max-w-[62ch] text-sm leading-6 text-slate-500">备份导出与恢复导入拆成两条独立流程。恢复成功后会直接刷新 DNS、SSL、总览和日志相关缓存，不需要手动刷新页面。</p>
              </div>
              <div class="settings-workbench-stats">
                <div class="settings-stat-pill">
                  <Database :size="16" />
                  <span>可选范围 {{ backupScopeSummary.length }}/2</span>
                </div>
                <div class="settings-stat-pill">
                  <RefreshCw :size="16" />
                  <span>恢复后自动拉新</span>
                </div>
              </div>
            </div>

            <div class="grid gap-6 lg:grid-cols-[1.05fr_1.15fr]">
              <article class="settings-action-card export-card">
                <div class="settings-action-head">
                  <div class="settings-icon-wrap bg-[#ebf4ff] text-[#2563eb]">
                    <Download :size="18" />
                  </div>
                  <div>
                    <p class="settings-card-kicker">导出</p>
                    <h3 class="text-lg font-bold text-slate-800">生成备份快照</h3>
                  </div>
                </div>
                <p class="mt-3 text-sm leading-6 text-slate-500">导出当前管理员名下的 DNS 和 SSL 数据，生成一份结构化 JSON 文件，适合迁移、回滚和离线归档。</p>

                <div class="settings-chip-row mt-4">
                  <NCheckbox v-model:checked="backupDns">DNS 数据</NCheckbox>
                  <NCheckbox v-model:checked="backupSsl">SSL 数据</NCheckbox>
                </div>

                <div class="settings-mini-panel mt-4">
                  <p class="settings-subpanel-label">当前导出内容</p>
                  <div class="settings-tag-list">
                    <span v-for="scope in backupScopeSummary" :key="scope" class="settings-tag">{{ scope }}</span>
                    <span v-if="backupScopeSummary.length === 0" class="text-xs text-slate-400">未选择任何范围</span>
                  </div>
                </div>

                <NButton class="mt-5 !h-11 w-full !rounded-xl !font-semibold" type="primary" :loading="exportLoading" @click="handleExportBackup">
                  <template #icon><Download :size="16" /></template>
                  导出备份文件
                </NButton>
              </article>

              <article class="settings-action-card restore-card">
                <div class="settings-action-head">
                  <div class="settings-icon-wrap bg-[#fff3e8] text-[#ea580c]">
                    <Upload :size="18" />
                  </div>
                  <div>
                    <p class="settings-card-kicker">恢复</p>
                    <h3 class="text-lg font-bold text-slate-800">导入并替换数据</h3>
                  </div>
                </div>
                <p class="mt-3 text-sm leading-6 text-slate-500">从已有备份文件恢复选定范围。你可以选择覆盖当前数据，恢复完成后界面相关列表会自动重新取数。</p>

                <div class="settings-chip-row mt-4">
                  <NCheckbox v-model:checked="restoreDns">DNS 数据</NCheckbox>
                  <NCheckbox v-model:checked="restoreSsl">SSL 数据</NCheckbox>
                  <NCheckbox v-model:checked="restoreOverwrite">覆盖现有数据</NCheckbox>
                </div>

                <div class="settings-mini-panel mt-4">
                  <div class="flex items-start justify-between gap-4">
                    <div>
                      <p class="settings-subpanel-label">已选文件</p>
                      <p class="mt-1 break-all text-sm font-medium text-slate-700">{{ selectedBackupName }}</p>
                    </div>
                    <div class="settings-tag-list justify-end">
                      <span v-for="scope in restoreScopeSummary" :key="scope" class="settings-tag">{{ scope }}</span>
                    </div>
                  </div>
                  <div class="mt-4">
                    <label class="flex items-center justify-center w-full">
                      <span class="relative flex items-center justify-center w-full rounded-lg border-2 border-dashed border-slate-300 p-4 transition-all hover:border-blue-500 hover:bg-blue-50 cursor-pointer">
                        <div class="space-y-1 text-center">
                          <Upload :size="24" class="mx-auto text-slate-400" />
                          <div class="flex text-sm text-slate-600">
                            <span class="font-medium text-blue-600">点击上传</span>
                            <span class="pl-1">或拖放文件</span>
                          </div>
                          <p class="text-xs text-slate-500">仅支持 JSON 文件</p>
                        </div>
                        <input ref="restoreFileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" type="file" accept=".json,application/json" @change="handleBackupFileChange" />
                      </span>
                    </label>
                  </div>
                </div>

                <div class="mt-4 rounded-2xl border border-amber-200 bg-amber-50/70 px-4 py-3 text-xs leading-6 text-amber-700">
                  恢复后会无感刷新当前会话的 DNS、SSL、总览和日志缓存，避免导入完成后还看到旧数据。
                </div>

                <NButton class="mt-5 !h-11 w-full !rounded-xl !font-semibold" size="large" :loading="restoreLoading" @click="handleRestoreBackup">
                  <template #icon><Upload :size="16" /></template>
                  恢复并同步界面数据
                </NButton>
              </article>
            </div>
          </div>
        </div>
      </div>

      <!-- 关于选项卡 -->
      <div v-if="activeTab === 'about'" class="settings-tab-content">
        <div class="bento-card p-4 relative overflow-hidden">
          <div class="absolute -left-10 -top-10 w-32 h-32 rounded-full bg-gradient-to-br from-amber-500/15 to-orange-500/15 blur-xl" />
          <div class="absolute left-3 top-3 w-10 h-10 rounded-full bg-gradient-to-br from-amber-400/25 to-orange-400/25 blur-lg" />
          <div class="relative z-10">
            <div class="flex items-center gap-2 mb-2">
              <Info :size="14" class="text-amber-600" />
              <p class="text-xs font-semibold uppercase tracking-widest text-slate-500">系统版本</p>
            </div>
            <p class="mt-2 text-3xl bg-gradient-to-r from-amber-600 to-orange-600 bg-clip-text text-transparent">{{ appVersionLabel }}</p>
            <div class="mt-3 flex items-center gap-2">
              <span class="text-xs text-slate-500">当前版本</span>
              <span class="text-xs font-semibold text-amber-600">{{ appVersionLabel }}</span>
            </div>
          </div>
        </div>
        <div class="bento-card mt-4">
          <p class="bento-section-title">关于系统</p>
          <p class="bento-section-meta">DNS 管理系统</p>
          <div class="mt-4 space-y-3">
            <p class="text-sm text-slate-600">DNS 管理系统是一个功能强大的域名管理工具，支持多服务商集成、SSL 证书管理和域名到期监控。</p>
            <p class="text-sm text-slate-600">版本: {{ appVersionLabel }}</p>
            <p class="text-sm text-slate-600">版权所有 © {{ new Date().getFullYear() }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}

.settings-header {
  margin-bottom: 32px;
}

.settings-tabs {
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(148, 163, 184, 0.18);
}

/* 自定义选项卡样式 */
:deep(.n-tabs-line .n-tabs-tab) {
  padding: 12px 24px;
  font-size: 14px;
  font-weight: 600;
  color: rgb(100 116 139);
  transition: all 0.3s ease;
}

:deep(.n-tabs-line .n-tabs-tab:hover) {
  color: rgb(59 130 246);
}

:deep(.n-tabs-line .n-tabs-tab.n-tabs-tab--active) {
  color: rgb(37 99 235);
  font-weight: 700;
}

:deep(.n-tabs-line .n-tabs-rail) {
  background-color: rgb(37 99 235);
  height: 3px;
  border-radius: 1.5px;
}

.settings-content {
  min-height: 400px;
}

.settings-tab-content {
  animation: fadeIn 0.3s ease-in-out;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.settings-subpanel {
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(255, 255, 255, 0.72);
  border-radius: 18px;
  padding: 14px;
}

.settings-subpanel-label {
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: rgb(100 116 139);
  margin-bottom: 8px;
  font-weight: 700;
}

.settings-workbench {
  position: relative;
  padding: 8px;
}

.settings-workbench::before {
  content: "";
  position: absolute;
  inset: -20px -10px auto auto;
  width: 240px;
  height: 240px;
  background: radial-gradient(circle, rgba(37, 99, 235, 0.13), transparent 65%);
  pointer-events: none;
}

.settings-workbench::after {
  content: "";
  position: absolute;
  inset: auto auto -80px -60px;
  width: 280px;
  height: 280px;
  background: radial-gradient(circle, rgba(249, 115, 22, 0.12), transparent 68%);
  pointer-events: none;
}

.settings-workbench-head {
  position: relative;
  z-index: 1;
  display: flex;
  gap: 16px;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  margin-bottom: 24px;
}

.settings-workbench-stats {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.settings-stat-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border-radius: 999px;
  padding: 10px 14px;
  background: rgba(255, 255, 255, 0.78);
  border: 1px solid rgba(148, 163, 184, 0.16);
  color: rgb(51 65 85);
  font-size: 12px;
  font-weight: 700;
}

.settings-action-card {
  position: relative;
  z-index: 1;
  border-radius: 28px;
  padding: 24px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  overflow: hidden;
}

.export-card {
  background:
    linear-gradient(145deg, rgba(239, 246, 255, 0.96), rgba(255, 255, 255, 0.92));
}

.restore-card {
  background:
    linear-gradient(145deg, rgba(255, 247, 237, 0.96), rgba(255, 255, 255, 0.92));
}

.settings-action-head {
  display: flex;
  align-items: center;
  gap: 14px;
}

.settings-icon-wrap {
  width: 42px;
  height: 42px;
  border-radius: 14px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.55);
}

.settings-card-kicker {
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: rgb(100 116 139);
  font-weight: 800;
}

.settings-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
}

.settings-mini-panel {
  border-radius: 20px;
  padding: 16px;
  background: rgba(255, 255, 255, 0.74);
  border: 1px solid rgba(148, 163, 184, 0.18);
}

.settings-tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.settings-tag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 28px;
  padding: 0 12px;
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.06);
  color: rgb(30 41 59);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.04em;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .settings-page {
    padding: 16px;
  }
  
  .settings-tabs {
    overflow-x: auto;
    white-space: nowrap;
  }
  
  :deep(.n-tabs-line .n-tabs-tab) {
    padding: 10px 16px;
    font-size: 13px;
  }
  
  .settings-workbench-head {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
