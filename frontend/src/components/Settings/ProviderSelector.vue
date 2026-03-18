<script setup lang="ts">
import type { ProviderConfig, ProviderType } from '@/types/dns';
import {
  Cloud, Globe, Flame, Server, Database, Rocket,
  HardDrive, Radio, Wifi, Zap, Shield, Layers, Network,
} from 'lucide-vue-next';
import { computed, type Component } from 'vue';

const props = defineProps<{
  providers: ProviderConfig[];
  selectedProvider: ProviderType | null;
}>();

const emit = defineEmits<{ select: [provider: ProviderType] }>();

const PROVIDER_COLORS: Record<string, string> = {
  cloudflare: '#4a8fe4',
  aliyun: '#5a99e6',
  dnspod: '#5f9ce3',
  dnspod_token: '#5f9ce3',
  huawei: '#5389d5',
  baidu: '#6f9fde',
  west: '#5f97db',
  huoshan: '#4d86ce',
  jdcloud: '#5e95dd',
  dnsla: '#7aa6e0',
  namesilo: '#689fdf',
  powerdns: '#7f95b4',
  spaceship: '#5f98e0',
};

const PROVIDER_ICONS: Record<string, Component> = {
  cloudflare: Cloud,
  aliyun: Database,
  dnspod: Globe,
  dnspod_token: Globe,
  huawei: HardDrive,
  baidu: Radio,
  west: Wifi,
  huoshan: Flame,
  jdcloud: Zap,
  dnsla: Server,
  namesilo: Layers,
  powerdns: Shield,
  spaceship: Rocket,
};

const filteredProviders = computed(() =>
  props.providers.filter(p => p.type !== 'dnspod_token')
);
</script>

<template>
  <div class="grid max-h-[50vh] grid-cols-3 gap-4 overflow-y-auto p-0.5 sm:grid-cols-4 md:grid-cols-5">
    <button
      v-for="provider in filteredProviders"
      :key="provider.type"
      class="flex cursor-pointer flex-col items-center gap-4 rounded-xl border p-3 transition-all duration-200 ease-out"
      :class="[
        selectedProvider === provider.type
          ? 'border-2'
          : 'border-panel-border hover:-translate-y-0.5 hover:shadow-md'
      ]"
      :style="{
        borderColor: selectedProvider === provider.type ? PROVIDER_COLORS[provider.type] : undefined,
        backgroundColor: selectedProvider === provider.type ? PROVIDER_COLORS[provider.type] + '0a' : undefined,
      }"
      @click="emit('select', provider.type)"
    >
      <div
        class="flex h-8 w-8 items-center justify-center rounded-xl"
        :style="{ backgroundColor: PROVIDER_COLORS[provider.type] + '1a' }"
      >
        <component
          :is="PROVIDER_ICONS[provider.type] || Network"
          :size="16"
          :style="{ color: PROVIDER_COLORS[provider.type] }"
        />
      </div>
      <span class="w-full truncate text-center text-xs font-semibold text-slate-500">
        {{ provider.name }}
      </span>
    </button>
  </div>
</template>
