import { ref, onMounted, onUnmounted } from 'vue';

export function useResponsive(breakpoint = 640) {
  const mql = window.matchMedia(`(min-width: ${breakpoint}px)`);
  const isMobile = ref(!mql.matches);

  function update(e: MediaQueryListEvent) {
    isMobile.value = !e.matches;
  }

  onMounted(() => {
    mql.addEventListener('change', update);
  });

  onUnmounted(() => {
    mql.removeEventListener('change', update);
  });

  return { isMobile };
}
