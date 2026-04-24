<script setup lang="ts">
import { computed } from 'vue';
import type { ProviderConfig, ProviderType } from '@/types/dns';
import {
  Cloud, Server, Globe, CloudRain, CloudSun, Earth,
  Flame, CloudCog, Waypoints, Tag, Power, Rocket, HardDrive, Zap,
} from 'lucide-vue-next';

const props = defineProps<{
  provider: ProviderConfig;
  isSelected: boolean;
  count: number;
  isDragging: boolean;
}>();

defineEmits<{ click: [] }>();

const PROVIDER_COLORS: Record<string, string> = {
  cloudflare: '#F6821F',
  aliyun: '#FF6A00',
  dnspod: '#00A4FF',
  dnspod_token: '#00A4FF',
  huawei: '#FF2D20',
  baidu: '#2319DC',
  west: '#00C853',
  huoshan: '#FF4D4F',
  jdcloud: '#E4393C',
  dnsla: '#9C27B0',
  namesilo: '#00BCD4',
  powerdns: '#607D8B',
  spaceship: '#795548',
};

const PROVIDER_ICONS: Record<string, any> = {
  cloudflare: Cloud,
  aliyun: Server,
  dnspod: Globe,
  dnspod_token: Globe,
  huawei: CloudRain,
  baidu: CloudSun,
  west: Earth,
  huoshan: Flame,
  jdcloud: CloudCog,
  dnsla: Waypoints,
  namesilo: Tag,
  powerdns: Power,
  spaceship: Rocket,
};

const color = computed(() => PROVIDER_COLORS[props.provider.type] || '#6D88A8');
const iconComponent = computed(() => PROVIDER_ICONS[props.provider.type] || HardDrive);
</script>

<template>
  <button
    :data-provider-type="provider.type"
    class="provider-item"
    :class="[
      isSelected ? 'active' : '',
      isDragging ? 'opacity-70 cursor-grabbing' : '',
    ]"
    @click="$emit('click')"
  >
    <div
      class="provider-icon"
      :style="{
        borderColor: `${color}40`,
        backgroundColor: `${color}12`,
        color,
      }"
    >
      <component :is="iconComponent" :size="16" />
    </div>

    <span class="provider-name">{{ provider.name }}</span>

    <span
      v-if="count > 0"
      class="provider-count"
      :style="{
        backgroundColor: `${color}15`,
        color,
      }"
    >
      {{ count }}
    </span>
  </button>
</template>
