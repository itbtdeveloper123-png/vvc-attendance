import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/admin_api.php': {
        target: 'https://app.vvc.asia',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => `/flutter${path}`,
      },
      '/api.php': {
        target: 'https://app.vvc.asia',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => `/flutter${path}`,
      },
      '/flutter': {
        target: 'https://app.vvc.asia',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  esbuild: {
    drop: process.env.NODE_ENV === 'production' ? ['console', 'debugger'] : [],
    legalComments: 'none',
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'esbuild',
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: undefined,
      },
    },
  },
});
