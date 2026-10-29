import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 开发期 /api 代理到本机 api 容器映射；生产由 nginx 反代
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8081',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
