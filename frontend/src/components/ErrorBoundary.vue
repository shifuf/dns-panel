<script setup lang="ts">
import { ref, onErrorCaptured } from 'vue';
import { useRouter } from 'vue-router';
import { AlertTriangle, RefreshCw, Home } from 'lucide-vue-next';

const error = ref<Error | null>(null);
const errorInfo = ref('');
const router = useRouter();

onErrorCaptured((err: Error, instance, info) => {
  error.value = err;
  errorInfo.value = info || '';
  console.error('[ErrorBoundary]', err, info);
  return false; // prevent propagation
});

function reload() {
  error.value = null;
  window.location.reload();
}

function goHome() {
  error.value = null;
  router.push('/');
}
</script>

<template>
  <div v-if="error" class="error-boundary">
    <div class="error-card">
      <div class="error-icon">
        <AlertTriangle :size="40" />
      </div>
      <h2 class="error-title">页面出现了问题</h2>
      <p class="error-message">{{ error.message }}</p>
      <p v-if="errorInfo" class="error-info">组件: {{ errorInfo }}</p>
      <div class="error-actions">
        <button class="error-btn error-btn-primary" @click="reload">
          <RefreshCw :size="16" />
          刷新页面
        </button>
        <button class="error-btn" @click="goHome">
          <Home :size="16" />
          返回首页
        </button>
      </div>
    </div>
  </div>
  <slot v-else />
</template>

<style scoped>
.error-boundary {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--ui-bg, #fafafa);
  padding: 24px;
}

.error-card {
  max-width: 420px;
  width: 100%;
  text-align: center;
  padding: 40px 32px;
  border-radius: 20px;
  border: 1px solid var(--ui-border, #e2e8f0);
  background: var(--ui-surface, #ffffff);
  box-shadow: 0 20px 60px -24px rgba(0, 0, 0, 0.15);
}

.error-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 72px;
  height: 72px;
  border-radius: 20px;
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(239, 68, 68, 0.15));
  color: #ef4444;
  margin-bottom: 20px;
}

.error-title {
  font-size: 20px;
  font-weight: 800;
  color: var(--ui-text-strong, #0f172a);
  margin: 0 0 8px;
}

.error-message {
  font-size: 14px;
  color: var(--ui-text-muted, #64748b);
  margin: 0 0 4px;
  word-break: break-word;
}

.error-info {
  font-size: 12px;
  color: var(--ui-text-muted, #94a3b8);
  margin: 0 0 24px;
  font-family: 'JetBrains Mono', monospace;
}

.error-actions {
  display: flex;
  gap: 10px;
  justify-content: center;
}

.error-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 12px;
  border: 1px solid var(--ui-border, #e2e8f0);
  background: transparent;
  color: var(--ui-text, #1e293b);
  font-size: 14px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all 200ms ease;
}

.error-btn:hover {
  background: var(--ui-surface-2, #f1f5f9);
  border-color: var(--ui-border-strong, #d3deeb);
}

.error-btn-primary {
  background: linear-gradient(135deg, var(--ui-accent, #0052ff), var(--ui-accent-secondary, #4d7cff));
  color: #ffffff;
  border: none;
}

.error-btn-primary:hover {
  filter: brightness(1.08);
  box-shadow: 0 8px 20px -8px rgba(0, 82, 255, 0.4);
}
</style>
