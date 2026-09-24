import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' ws://localhost:3000 http://localhost:8000",
  "frame-ancestors 'self'",
  "form-action 'self'",
].join('; ')

export default defineConfig({
  plugins: [react()],
  server: {
    headers: {
      'Content-Security-Policy': csp,
      'X-Content-Type-Options': 'nosniff',
    },
  },
})