import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Where the /api proxy sends requests. Local development targets the Nest
// watcher on localhost:3000; the Docker `web` service overrides this with
// PROXY_TARGET=http://api:3000 so it reaches the containerized backend.
// When running in Docker, also bind 0.0.0.0 so the port is reachable from
// outside the container (CLI --host flags don't survive nested npm scripts).
const proxyTarget = process.env.PROXY_TARGET ?? 'http://localhost:3000'
const inDocker = Boolean(process.env.PROXY_TARGET)

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: inDocker || 'localhost',
    proxy: {
      // NestJS exposes every route under /api (see apps/backend/src/main.ts).
      '/api': {
        target: proxyTarget,
        changeOrigin: true,
      },
    },
  },
})
