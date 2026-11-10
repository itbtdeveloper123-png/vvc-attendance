import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
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
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router-dom')) {
              return 'vendor-react';
            }
            if (id.includes('lucide-react')) {
              return 'vendor-icons';
            }
            if (id.includes('html2canvas')) {
              return 'vendor-canvas';
            }
            if (id.includes('axios')) {
              return 'vendor-network';
            }
            return 'vendor-other';
          }
        },
      },
    },
  },
});
