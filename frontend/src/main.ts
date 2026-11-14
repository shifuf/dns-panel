import { createApp } from 'vue';
import { createPinia } from 'pinia';
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query';
import { onSessionReset } from './services/session';
import App from './App.vue';
import router from './router';
import './main.scss';

const app = createApp(App);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Keep fetched data "fresh" for 5 minutes so navigating between the
      // dashboard, a provider tab and a domain's detail view reuses the
      // cached result instead of re-hitting the upstream APIs every time.
      staleTime: 5 * 60_000,
      // Retain inactive query data for 30 minutes so going back to a page
      // you visited recently renders instantly from cache.
      gcTime: 30 * 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
    },
  },
});
onSessionReset(() => queryClient.clear());
app.use(createPinia());
app.use(VueQueryPlugin, { queryClient });
app.use(router);

app.config.errorHandler = (err, _instance, info) => {
  console.error(`[Global Error] ${info}:`, err);
};

app.mount('#app');
