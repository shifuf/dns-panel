import { defineStore } from 'pinia';
import { ref } from 'vue';

export const useBreadcrumbStore = defineStore('breadcrumb', () => {
  const labels = ref<Record<string, string>>({});

  function setLabel(key: string, label: string) {
    if (labels.value[key] === label) return;
    labels.value = { ...labels.value, [key]: label };
  }

  return { labels, setLabel };
});
