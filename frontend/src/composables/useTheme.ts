import { ref, watch } from 'vue';

type ThemeMode = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'dns-panel-theme';

const mode = ref<ThemeMode>((localStorage.getItem(STORAGE_KEY) as ThemeMode) || 'system');
const isDark = ref(false);

function applyTheme() {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const dark = mode.value === 'dark' || (mode.value === 'system' && prefersDark);
  isDark.value = dark;
  document.documentElement.classList.toggle('dark', dark);
}

// Initialize immediately
applyTheme();

// Listen for system preference changes
const mql = window.matchMedia('(prefers-color-scheme: dark)');
mql.addEventListener('change', () => {
  if (mode.value === 'system') applyTheme();
});

watch(mode, (val: ThemeMode) => {
  localStorage.setItem(STORAGE_KEY, val);
  applyTheme();
});

export function useTheme() {
  function toggle() {
    mode.value = isDark.value ? 'light' : 'dark';
  }

  function setMode(m: ThemeMode) {
    mode.value = m;
  }

  return { mode, isDark, toggle, setMode };
}
