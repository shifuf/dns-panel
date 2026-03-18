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
        staleTime: 30_000,
        retry: 1,
      },
    },
  },
});

app.config.errorHandler = (err, _instance, info) => {
  console.error(`[Global Error] ${info}:`, err);
};

app.mount('#app');
