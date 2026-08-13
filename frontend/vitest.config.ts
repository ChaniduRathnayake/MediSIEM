import path from "path";
import { fileURLToPath } from "url";
import { defineConfig } from "vitest/config";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Separate from vite.config.ts deliberately — that one carries
// vite-plugin-singlefile, a build-only concern with no reason to run
// during test collection.
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  test: {
    // 'node', not 'jsdom' — everything under test here is pure logic
    // (severity thresholds, CSV escaping, badge predicates), not React
    // component rendering, so no DOM shim is needed.
    environment: "node",
    globals: false,
  },
});
