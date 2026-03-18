<script setup lang="ts">
import { computed } from 'vue';
import { NConfigProvider, NMessageProvider, NDialogProvider, NNotificationProvider, darkTheme } from 'naive-ui';
import { lightOverrides, darkOverrides } from './theme/naive-overrides';
import { useTheme } from './composables/useTheme';
import ErrorBoundary from './components/ErrorBoundary.vue';

const { isDark } = useTheme();
const currentTheme = computed(() => isDark.value ? darkTheme : undefined);
const currentOverrides = computed(() => isDark.value ? darkOverrides : lightOverrides);
</script>

<template>
  <NConfigProvider :theme="currentTheme" :theme-overrides="currentOverrides">
    <NMessageProvider>
      <NDialogProvider>
        <NNotificationProvider>
          <ErrorBoundary>
            <router-view />
          </ErrorBoundary>
        </NNotificationProvider>
      </NDialogProvider>
    </NMessageProvider>
  </NConfigProvider>
</template>
