import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Proxy API requests to backend
      // Frontend calls /api/flows → Proxied to localhost:3000/api/flows
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      // Proxy OAuth routes to backend
      // OAuth callbacks and API endpoints must go to backend
      '/oauth': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
})
