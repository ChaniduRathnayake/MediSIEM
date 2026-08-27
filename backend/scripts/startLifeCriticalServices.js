#!/usr/bin/env node
// Boots the life-critical-orchestration engine/enrichment/shuffle_sim alongside
// MediSIEM's backend dev server. Only runs via `npm run dev:full` or
// `npm run dev:soar` (see package.json) — plain `npm run dev` is nodemon
// alone and skips this file entirely, so day-to-day backend work never pays
// its startup cost.
//
// Spawned services are detached + unref'd: they keep running independently of
// this script (which exits immediately after spawning) and of nodemon's own
// restarts. Re-running later just finds them already healthy and skips
// straight past — see checkHealth() in serviceLifecycle.js. If a previous run
// left a service wedged (port bound but not answering /health — observed in
// practice with the decision engine under Windows/WatchFiles), the stale
// process is killed before spawning a replacement, so repeated invocations
// can't pile up duplicate zombies on the same port.
//
// Deliberately excludes life-critical-orchestration's own standalone frontend:
// its UI is also ported into MediSIEM's Playbooks tab, and it defaults to the
// same Vite port (5173) MediSIEM's own frontend already uses. Start it
// separately with `life-critical-orchestration/scripts/start_all.sh` if you
// want it running side by side.

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureService, log, resolvePython } from './serviceLifecycle.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LCO_ROOT = path.resolve(__dirname, '..', '..', 'life-critical-orchestration');
// Shared with life-critical-orchestration/scripts/start_all.sh — one log
// location regardless of which of the two ways a service got started.
const LOG_DIR = path.join(LCO_ROOT, 'scripts', '.dev-logs');
const LOG_HINT = 'life-critical-orchestration/scripts/.dev-logs/';

// playbooks/shuffle_sim's VAPID keys are per-developer and gitignored
// (setenv.sh) — parsed here if present rather than hardcoded, since they're
// explicitly marked "do not commit" in that file. Push notifications simply
// stay disabled if there's no setenv.sh; the sim works fine either way.
function parseExports(shPath) {
  const env = {};
  if (!existsSync(shPath)) return env;
  const text = readFileSync(shPath, 'utf-8');
  for (const line of text.split('\n')) {
    const m = line.match(/^export\s+([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return env;
}

async function main() {
  if (!existsSync(LCO_ROOT)) {
    log(false, 'life-critical-orchestration not found next to MediSIEM — skipping engine/enrichment/shuffle_sim startup');
    return;
  }

  const enginePython = resolvePython(path.join(LCO_ROOT, 'engine', '.venv'));
  const enrichmentPython = resolvePython(path.join(LCO_ROOT, 'enrichment', '.venv'));
  // shuffle_sim shares the engine's venv, per its own setenv.sh.
  const simPython = enginePython;
  const simExtraEnv = parseExports(path.join(LCO_ROOT, 'playbooks', 'shuffle_sim', 'setenv.sh'));

  // Run all three checks concurrently — they're independent, and sequential
  // awaits meant one wedged service cost its full timeout budget before the
  // next check even started.
  await Promise.all([
    ensureService({
      name: 'Decision engine',
      healthUrl: 'http://localhost:8000/health',
      command: enginePython,
      args: ['-m', 'uvicorn', 'src.main:app', '--port', '8000', '--reload'],
      cwd: path.join(LCO_ROOT, 'engine'),
      env: { ...process.env, SHUFFLE_WEBHOOK_URL: 'http://localhost:8002/playbook/run' },
      logDir: LOG_DIR,
      logHint: LOG_HINT,
    }),
    ensureService({
      name: 'Enrichment shim',
      healthUrl: 'http://localhost:8001/health',
      command: enrichmentPython,
      args: ['-m', 'uvicorn', 'src.main:app', '--port', '8001', '--reload'],
      cwd: path.join(LCO_ROOT, 'enrichment'),
      env: process.env,
      logDir: LOG_DIR,
      logHint: LOG_HINT,
    }),
    ensureService({
      name: 'Shuffle sim',
      healthUrl: 'http://localhost:8002/health',
      command: simPython,
      args: ['-m', 'uvicorn', 'server:app', '--port', '8002', '--reload'],
      cwd: path.join(LCO_ROOT, 'playbooks', 'shuffle_sim'),
      env: { ...process.env, ...simExtraEnv },
      logDir: LOG_DIR,
      logHint: LOG_HINT,
    }),
  ]);
}

await main();
