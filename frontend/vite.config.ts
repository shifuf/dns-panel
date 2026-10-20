import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'path';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    // Bind every interface (IPv4 + IPv6): with the default binding Vite only
    // listened on ::1, so http://127.0.0.1:5174 answered "connection refused"
    // even though the server was running.
    host: true,
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': {
        // 127.0.0.1 instead of localhost: on Windows "localhost" can resolve to
        // ::1 first, which the Python backend does not listen on.
        target: 'http://127.0.0.1:4001',
        changeOrigin: true,
      },
    },
  },
});
