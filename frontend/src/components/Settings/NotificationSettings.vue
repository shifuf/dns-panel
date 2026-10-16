<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { NButton, NInput, NSelect, NSwitch, useMessage } from 'naive-ui';
import { Plus, Save, Send, Trash2 } from 'lucide-vue-next';
import {
  getNotificationSettings,
  updateNotificationSettings,
  testNotification,
  scanDomainExpiry,
  type NotificationChannel,
  type NotificationChannelType,
} from '@/services/notifications';

const message = useMessage();
const loading = ref(false);
const saving = ref(false);
const testing = ref(false);
const scanning = ref(false);
const enabled = ref(true);
const channels = ref<NotificationChannel[]>([]);

const typeOptions = [
  { label: '邮件 SMTP', value: 'email' },
  { label: '通用 Webhook', value: 'webhook' },
  { label: '企业微信', value: 'wecom' },
  { label: '钉钉', value: 'dingtalk' },
  { label: '飞书', value: 'feishu' },
  { label: 'Telegram', value: 'telegram' },
  { label: '站内信', value: 'inapp' },
];

function emptyChannel(type: NotificationChannelType = 'webhook'): NotificationChannel {
  return { type, enabled: true, config: {} };
}

function configText(ch: NotificationChannel, key: string) {
  return String(ch.config?.[key] ?? '');
}

function setConfig(ch: NotificationChannel, key: string, value: string) {
  ch.config = { ...(ch.config || {}), [key]: value };
}

async function load() {
  loading.value = true;
  try {
    const res = await getNotificationSettings();
    enabled.value = res.data?.enabled !== false;
    channels.value = Array.isArray(res.data?.channels) ? res.data!.channels : [];
  } catch (err: any) {
    // Backend may not be ready yet during rollout
    channels.value = [];
  } finally {
    loading.value = false;
  }
}

function addChannel() {
  channels.value.push(emptyChannel('webhook'));
}

function removeChannel(idx: number) {
  channels.value.splice(idx, 1);
}

async function save() {
  saving.value = true;
  try {
    await updateNotificationSettings({ enabled: enabled.value, channels: channels.value });
    message.success('通知设置已保存');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    saving.value = false;
  }
}

async function test(ch: NotificationChannel) {
  testing.value = true;
  try {
    const res = await testNotification({
      channel: ch,
      title: 'DNS Panel 测试通知',
      content: '这是一条来自 DNS 面板的测试消息。',
    });
    const ok = (res.data?.results || []).some((r) => r.success);
    if (ok) message.success('测试发送成功');
    else message.warning((res.data?.results || [])[0]?.error || '测试发送失败');
  } catch (err: any) {
    message.error(String(err));
  } finally {
    testing.value = false;
  }
}

async function runScan() {
  scanning.value = true;
  try {
    const res = await scanDomainExpiry();
    message.success(
      `巡检完成：扫描 ${res.data?.scanned || 0}，跟踪 ${res.data?.tracked || 0}，通知 ${res.data?.notified || 0}`
    );
  } catch (err: any) {
    message.error(String(err));
  } finally {
    scanning.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h3 class="text-sm font-semibold text-slate-700">统一通知渠道</h3>
        <p class="text-xs text-slate-500">用于 SSL 续期、域名到期、同步失败等事件告警</p>
      </div>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2">
          <NSwitch v-model:value="enabled" size="small" />
          <span class="text-sm text-slate-600">启用通知</span>
        </div>
        <NButton size="small" secondary :loading="scanning" @click="runScan">立即巡检域名到期</NButton>
        <NButton size="small" secondary @click="addChannel">
          <template #icon><Plus :size="14" /></template>
          添加渠道
        </NButton>
        <NButton size="small" type="primary" :loading="saving" @click="save">
          <template #icon><Save :size="14" /></template>
          保存
        </NButton>
      </div>
    </div>

    <div v-if="loading" class="text-sm text-slate-400">加载中…</div>
    <div v-else-if="!channels.length" class="rounded-xl border border-dashed border-panel-border px-4 py-8 text-center text-sm text-slate-400">
      暂无通知渠道，点击「添加渠道」开始配置
    </div>

    <div v-for="(ch, idx) in channels" :key="idx" class="rounded-2xl border border-panel-border bg-panel-surface p-4">
      <div class="mb-3 flex flex-wrap items-center gap-3">
        <NSelect v-model:value="ch.type" :options="typeOptions" size="small" class="!w-44" />
        <div class="flex items-center gap-2">
          <NSwitch v-model:value="ch.enabled" size="small" />
          <span class="text-xs text-slate-500">启用</span>
        </div>
        <div class="ml-auto flex items-center gap-2">
          <NButton size="tiny" secondary :loading="testing" @click="test(ch)">
            <template #icon><Send :size="12" /></template>
            测试
          </NButton>
          <NButton size="tiny" tertiary type="error" @click="removeChannel(idx)">
            <template #icon><Trash2 :size="12" /></template>
          </NButton>
        </div>
      </div>

      <div v-if="ch.type === 'email'" class="grid gap-2 md:grid-cols-2">
        <NInput size="small" :value="configText(ch, 'to')" placeholder="收件人邮箱" @update:value="(v) => setConfig(ch, 'to', v)" />
        <NInput size="small" :value="configText(ch, 'from')" placeholder="发件人（可选，默认用 SMTP From）" @update:value="(v) => setConfig(ch, 'from', v)" />
      </div>
      <div v-else-if="ch.type === 'webhook'" class="grid gap-2">
        <NInput size="small" :value="configText(ch, 'url')" placeholder="Webhook URL" @update:value="(v) => setConfig(ch, 'url', v)" />
      </div>
      <div v-else-if="ch.type === 'wecom' || ch.type === 'dingtalk' || ch.type === 'feishu'" class="grid gap-2">
        <NInput size="small" :value="configText(ch, 'url')" placeholder="机器人 Webhook URL" @update:value="(v) => setConfig(ch, 'url', v)" />
        <NInput v-if="ch.type === 'dingtalk'" size="small" :value="configText(ch, 'secret')" placeholder="钉钉加签 secret（可选）" @update:value="(v) => setConfig(ch, 'secret', v)" />
      </div>
      <div v-else-if="ch.type === 'telegram'" class="grid gap-2 md:grid-cols-2">
        <NInput size="small" :value="configText(ch, 'botToken')" placeholder="Bot Token" @update:value="(v) => setConfig(ch, 'botToken', v)" />
        <NInput size="small" :value="configText(ch, 'chatId')" placeholder="Chat ID" @update:value="(v) => setConfig(ch, 'chatId', v)" />
      </div>
      <p v-else class="text-xs text-slate-400">站内信无需额外配置，消息将写入通知收件箱。</p>
    </div>
  </div>
</template>
