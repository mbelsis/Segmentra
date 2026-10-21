import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
// SEGMENTRA_API_URL points the dev proxy at another API, e.g. the Docker lab
// (SEGMENTRA_API_URL=http://127.0.0.1:18080 npm run dev -- --port 5174).
const apiTarget = process.env.SEGMENTRA_API_URL || 'http://localhost:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})
