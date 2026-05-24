import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const backendTarget = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

export default defineConfig({
  root: 'frontend',
  base: '/static/admin/',
  plugins: [react()],
  server: {
    proxy: {
      '/accounts': backendTarget,
      '/emails': backendTarget,
      '/token-refresh': backendTarget,
      '/cache': backendTarget,
      '/web': backendTarget,
      '/api': backendTarget,
      '/openapi.json': backendTarget,
      '/admin': backendTarget,
    },
  },
  build: {
    outDir: '../static/admin',
    emptyOutDir: true,
    sourcemap: false,
  },
});
