import { createRouter, createWebHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';
import { getSetupStatus, isAuthenticated, getCurrentUser } from '@/services/auth';
import { onUnauthorized } from '@/services/api';
import { logPageAccess } from '@/services/logs';
import { onSessionReset } from '@/services/session';
import { createNavigationController, lazyRoute } from './navigation';

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: lazyRoute(() => import('@/pages/LoginPage.vue')),
    meta: { public: true },
  },
  {
    path: '/setup',
    name: 'Setup',
    component: lazyRoute(() => import('@/pages/SetupPage.vue')),
    meta: { public: true },
  },
  {
    path: '/register',
    name: 'Register',
    component: lazyRoute(() => import('@/pages/RegisterPage.vue')),
    meta: { public: true },
  },
  {
    path: '/',
    component: lazyRoute(() => import('@/layouts/AppLayout.vue')),
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: lazyRoute(() => import('@/pages/DashboardPage.vue')),
      },
      {
        path: 'domain/:zoneId',
        name: 'DomainDetail',
        component: lazyRoute(() => import('@/pages/DomainDetailPage.vue')),
        props: true,
      },
      {
        path: 'hostnames/:zoneId',
        name: 'CustomHostnames',
        component: lazyRoute(() => import('@/pages/CustomHostnamesPage.vue')),
        props: true,
      },
      {
        path: 'tunnels',
        name: 'Tunnels',
        component: lazyRoute(() => import('@/pages/TunnelsPage.vue')),
      },
      {
        path: 'logs',
        name: 'Logs',
        component: lazyRoute(() => import('@/pages/LogsPage.vue')),
      },
      {
        path: 'settings',
        name: 'Settings',
        component: lazyRoute(() => import('@/pages/SettingsPage.vue')),
      },
      {
        path: 'ssl',
        name: 'SSLCertificates',
        component: lazyRoute(() => import('@/pages/SSLCertificatesPage.vue')),
      },
      {
        path: 'platform-deployments',
        name: 'PlatformDeployments',
        component: lazyRoute(() => import('@/pages/PlatformDeploymentsPage.vue')),
      },
      {
        // Legacy deep-link: Let's Encrypt is a channel tab inside the SSL page now.
        path: 'letsencrypt',
        redirect: (to) => ({ path: '/ssl', query: { ...to.query, channel: 'letsencrypt' } }),
      },
      {
        path: 'edgeone',
        name: 'EdgeOne',
        component: lazyRoute(() => import('@/pages/EdgeOnePage.vue')),
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: () => ({ path: '/', query: { scope: 'all' } }),
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});
export const navigation = createNavigationController(router);

// ── 唯一跳转方 ───────────────────────────────────────────────────────────
// axios 拦截器只负责清理会话并广播事件，跳转统一由路由完成。以前拦截器也会
// window.location.href = '/login'，与守卫互相弹跳：token 失效时 '/' 返回 401
// → 跳 /login → 守卫又放行 '/' → 再 401 …… 表现为页面无限刷新、一直白屏。
let loggingOut = false;
onUnauthorized(() => {
  if (loggingOut) return;
  const current = router.currentRoute.value;
  const name = String(current.name || '');
  if (name === 'Login' || name === 'Setup' || name === 'Register') return;
  loggingOut = true;
  const query = current.fullPath && current.fullPath !== '/' ? { redirect: current.fullPath } : {};
  router.replace({ name: 'Login', query }).finally(() => {
    window.setTimeout(() => {
      loggingOut = false;
    }, 300);
  });
});

// localStorage 里有 token 不等于会话有效（可能来自旧/别的数据库或已过期）。
// 每个会话只校验一次，避免守卫在 '/' 与 '/login' 之间来回弹跳。
let sessionVerifiedToken: string | null = null;
let sessionEpoch = 0;
let sessionProbe: { token: string; promise: Promise<boolean> } | null = null;
async function hasValidSession(): Promise<boolean> {
  const token = localStorage.getItem('token');
  if (!token) {
    sessionVerifiedToken = null;
    return false;
  }
  if (sessionVerifiedToken === token) return true;
  if (!sessionProbe || sessionProbe.token !== token) {
    const epoch = sessionEpoch;
    const promise = getCurrentUser()
      .then(() => {
        if (epoch !== sessionEpoch || localStorage.getItem('token') !== token) return false;
        sessionVerifiedToken = token;
        return true;
      })
      .catch(() => {
        if (epoch === sessionEpoch) sessionVerifiedToken = null;
        return false;
      })
      .finally(() => {
        if (sessionProbe?.promise === promise) sessionProbe = null;
      });
    sessionProbe = { token, promise };
  }
  return sessionProbe.promise;
}

export function resetSessionCache() {
  sessionEpoch += 1;
  sessionVerifiedToken = null;
  sessionProbe = null;
}
onSessionReset(resetSessionCache);

router.beforeEach(async (to) => {
  // Download this route while the setup/session checks run; only the guard
  // below decides whether its component is allowed to mount.
  void navigation.prefetch(to);
  try {
    const status = (await getSetupStatus()).data;
    if (!status?.setupComplete && to.name !== 'Setup') {
      return { name: 'Setup' };
    }
    if (status?.setupComplete && to.name === 'Setup') {
      return (await hasValidSession()) ? { path: '/', query: { scope: 'all' } } : { name: 'Login' };
    }
  } catch {
    if (to.name === 'Setup') return true;
  }

  if (to.meta.public) {
    if (to.name === 'Login' && (await hasValidSession())) {
      return { path: '/', query: { scope: 'all' } };
    }
    return true;
  }
  if (!(await hasValidSession())) {
    const query = to.fullPath && to.fullPath !== '/' ? { redirect: to.fullPath } : {};
    return { name: 'Login', query };
  }
  return true;
});

router.afterEach((to) => {
  if (to.meta.public || !isAuthenticated()) return;
  logPageAccess({
    path: to.fullPath,
    name: String(to.name || to.path || 'page'),
    title: document.title || undefined,
  }).catch(() => undefined);
});

export default router;
