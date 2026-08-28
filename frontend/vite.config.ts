import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    proxy: {
      // /clinician's push/on-call controls talk to the Shuffle sim directly
      // (life-critical-orchestration/playbooks/shuffle_sim, :8002) — it has no
      // auth of its own and isn't proxied through the Express backend, unlike
      // the actual approve/deny decision (which goes through the authenticated,
      // role-gated /api/life-critical/clinician-decision instead so a stranger
      // can't submit a real containment decision). Registered before the
      // generic "/api" entry below — proxy matching is by string prefix, and
      // "/api/sim/..." also starts with "/api", so the more specific entry
      // must come first or the backend one would swallow it.
      "/api/sim": {
        target: "http://localhost:8002",
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api\/sim/, ""),
      },
      // Forward all other /api/* requests to the Express backend during development.
      // Without this, the browser sends /api/wazuh/ping to Vite (port 5173)
      // instead of Express (port 5050) → instant 404.
      "/api": {
        target: "http://localhost:5050",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
