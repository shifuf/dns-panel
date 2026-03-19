import { createRouter, createWebHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';
import { getSetupStatus, isAuthenticated } from '@/services/auth';
import { logPageAccess } from '@/services/logs';

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/pages/LoginPage.vue'),
    meta: { public: true },
  },
  {
    path: '/setup',
    name: 'Setup',
    component: () => import('@/pages/SetupPage.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('@/layouts/AppLayout.vue'),
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('@/pages/DashboardPage.vue'),
      },
      {
        path: 'domain/:zoneId',
        name: 'DomainDetail',
        component: () => import('@/pages/DomainDetailPage.vue'),
        props: true,
      },
      {
        path: 'hostnames/:zoneId',
        name: 'CustomHostnames',
        component: () => import('@/pages/CustomHostnamesPage.vue'),
        props: true,
      },
      {
        path: 'tunnels',
        name: 'Tunnels',
        component: () => import('@/pages/TunnelsPage.vue'),
      },
      {
        path: 'logs',
        name: 'Logs',
        component: () => import('@/pages/LogsPage.vue'),
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/pages/SettingsPage.vue'),
      },
      {
        path: 'ssl',
        name: 'SSLCertificates',
        component: () => import('@/pages/SSLCertificatesPage.vue'),
      },
      {
        path: 'accelerations',
        name: 'Accelerations',
        component: () => import('@/pages/AccelerationsPage.vue'),
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

router.beforeEach(async (to) => {
  try {
    const status = (await getSetupStatus()).data;
    if (!status?.setupComplete && to.name !== 'Setup') {
      return { name: 'Setup' };
    }
    if (status?.setupComplete && to.name === 'Setup') {
      return isAuthenticated() ? { path: '/', query: { scope: 'all' } } : { name: 'Login' };
    }
  } catch {
    if (to.name === 'Setup') return true;
  }

  if (to.meta.public) return true;
  if (!isAuthenticated()) {
    return { name: 'Login', query: { redirect: to.fullPath } };
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
