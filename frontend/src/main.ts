import { createApp } from 'vue';
import { createPinia } from 'pinia';
import { VueQueryPlugin } from '@tanstack/vue-query';
import App from './App.vue';
import router from './router';
import './main.scss';

const app = createApp(App);

app.use(createPinia());
app.use(router);
app.use(VueQueryPlugin, {
  queryClientConfig: {
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
  },
});

app.config.errorHandler = (err, _instance, info) => {
  console.error(`[Global Error] ${info}:`, err);
};

app.mount('#app');
