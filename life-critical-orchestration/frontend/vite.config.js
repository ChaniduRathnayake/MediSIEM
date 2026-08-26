import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Workstream E: serve over HTTPS on the LAN (required for service workers /
// Web Push) and proxy the engine + sim so the whole app is same-origin.
//
// HTTPS is opt-in: drop an mkcert-generated key/cert into frontend/certs/ as
// dev-key.pem / dev-cert.pem and the dev server comes up on https. With no
// certs present it falls back to plain http, so existing localhost dev is
// unchanged. Generate them with:
//   mkcert -key-file frontend/certs/dev-key.pem -cert-file frontend/certs/dev-cert.pem localhost 127.0.0.1 <your-LAN-IP>
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const keyPath = path.join(__dirname, 'certs', 'dev-key.pem')
const certPath = path.join(__dirname, 'certs', 'dev-cert.pem')
const https =
  fs.existsSync(keyPath) && fs.existsSync(certPath)
    ? { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }
    : undefined

// Proxy targets — the engine and the Shuffle sim, forwarded server-side so
// the browser only ever talks to the (single, HTTPS) dev-server origin.
const proxy = {
  '/api/engine': {
    target: 'http://localhost:8000',
    changeOrigin: true,
    rewrite: (p) => p.replace(/^\/api\/engine/, ''),
  },
  '/api/sim': {
    target: 'http://localhost:8002',
    changeOrigin: true,
    rewrite: (p) => p.replace(/^\/api\/sim/, ''),
  },
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // listen on 0.0.0.0 so a phone on the same WiFi can reach it
    https,
    proxy,
  },
  preview: {
    host: true,
    https,
    proxy,
  },
})
