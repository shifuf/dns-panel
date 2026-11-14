import { reactive } from 'vue';
import { isNavigationFailure, NavigationFailureType } from 'vue-router';
import type { RouteLocationRaw, Router } from 'vue-router';

/** Hover and navigation share the same import; a network failure can be retried. */
export function lazyRoute<T>(load: () => Promise<T>): () => Promise<T> {
  let pending: Promise<T> | undefined;
  return () => {
    pending ??= load().catch(error => {
      pending = undefined;
      throw error;
    });
    return pending;
  };
}

export function createNavigationController(router: Router) {
  const state = reactive({ pendingPath: '', error: '', failedPath: '' });
  let pendingRoute: object | null = null;

  function start(path: string) {
    pendingRoute = null;
    state.pendingPath = path;
    state.error = '';
    state.failedPath = '';
  }

  function fail(path: string) {
    if (state.pendingPath !== path) return;
    state.pendingPath = '';
    state.failedPath = path;
    state.error = '页面加载失败，请检查网络后重试';
  }

  router.beforeEach(to => { start(to.fullPath); pendingRoute = to; });
  router.afterEach((to, _from, failure) => {
    if (pendingRoute !== to) return;
    if (failure && isNavigationFailure(failure, NavigationFailureType.aborted)) {
      fail(to.fullPath);
      return;
    }
    state.pendingPath = '';
  });
  router.onError((_error, to) => { if (pendingRoute === to) fail(to.fullPath); });

  async function prefetch(to: RouteLocationRaw): Promise<boolean> {
    const connection = typeof navigator === 'undefined' ? undefined :
      (navigator as Navigator & { connection?: { saveData?: boolean; effectiveType?: string } }).connection;
    if (connection?.saveData || connection?.effectiveType?.includes('2g')) return false;
    try {
      const components = router.resolve(to).matched.flatMap(record => Object.values(record.components || {}));
      await Promise.all(components.filter(component => typeof component === 'function').map(load => (load as () => Promise<unknown>)()));
      return true;
    } catch {
      // A speculative failure must not interrupt the current page.
      return false;
    }
  }

  async function navigate(to: RouteLocationRaw): Promise<boolean> {
    const path = router.resolve(to).fullPath;
    start(path);
    try {
      const failure = await router.push(to);
      if (isNavigationFailure(failure, NavigationFailureType.duplicated)) {
        if (pendingRoute === null && state.pendingPath === path) state.pendingPath = '';
        return true;
      }
      return !failure;
    } catch {
      // onError owns failure feedback and knows which navigation failed.
      return false;
    }
  }

  return {
    state, prefetch, navigate,
    retry: () => state.failedPath ? navigate(state.failedPath) : Promise.resolve(false),
    dismissError: () => { state.error = ''; state.failedPath = ''; },
  };
}
