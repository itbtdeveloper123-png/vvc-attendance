import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/admin_api.php': {
        target: 'https://app.vvc.asia/flutter',
        changeOrigin: true,
        secure: false,
      },
      '/api.php': {
        target: 'http://localhost/Vvc-Attendace',
        changeOrigin: true,
        secure: false,
      },
      '/flutter': {
        target: 'https://app.vvc.asia',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1000,
  },
});
