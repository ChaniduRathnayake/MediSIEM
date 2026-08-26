#!/usr/bin/env node
// Boots the life-critical-orchestration engine/enrichment/shuffle_sim alongside
// MediSIEM's backend dev server. Chained BEFORE nodemon in package.json's "dev"
// script (see the end of this file's comment) — runs once per `npm run dev`
// invocation, never on nodemon's own file-triggered restarts of server.js, so
// it can never fight with itself or pile up duplicate processes.
//
// Spawned services are detached + unref'd: they keep running independently of
// this script (which exits immediately after spawning) and of nodemon's own
// restarts. Re-running `npm run dev` later just finds them already healthy
// and skips straight past — see checkHealth() below.
//
// Deliberately excludes life-critical-orchestration's own standalone frontend:
// its UI is also ported into MediSIEM's Playbooks tab, and it defaults to the
// same Vite port (5173) MediSIEM's own frontend already uses. Start it
// separately with `life-critical-orchestration/scripts/start_all.sh` if you
// want it running side by side.
//
// Uses only Node builtins (no extra dependency) since this must run before
// npm's own dependency tree is guaranteed relevant to it.

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, openSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LCO_ROOT = path.resolve(__dirname, '..', '..', 'life-critical-orchestration');
// Shared with life-critical-orchestration/scripts/start_all.sh — one log
// location regardless of which of the two ways a service got started.
const LOG_DIR = path.join(LCO_ROOT, 'scripts', '.dev-logs');

function log(ok, msg) {
  // Matches server.js's own startup log style exactly (two spaces after the emoji).
  console.log(`${ok ? '✅' : '⚠️'}  ${msg}`);
}

async function checkHealth(url, timeoutMs = 1000) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { signal: ctrl.signal });
    clearTimeout(t);
    return res.ok;
  } catch {
    return false;
  }
}

async function waitHealthy(url, attempts = 30, intervalMs = 1000) {
  for (let i = 0; i < attempts; i++) {
    if (await checkHealth(url)) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

// Falls back to whatever `python` resolves to on PATH if the service's own
// venv interpreter is missing or broken — e.g. a venv copied from a
// teammate's machine embeds an absolute path to THEIR python.exe, which
// won't resolve here. Confirmed necessary in practice on this checkout.
function resolvePython(venvDir) {
  const venvPython = path.join(venvDir, 'Scripts', 'python.exe');
  if (existsSync(venvPython)) {
    const probe = spawnSync(venvPython, ['--version']);
    if (probe.status === 0) return venvPython;
  }
  return 'python';
}

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

function spawnDetached(name, command, args, cwd, env) {
  mkdirSync(LOG_DIR, { recursive: true });
  const logFile = path.join(LOG_DIR, `${name}.log`);
  const out = openSync(logFile, 'a');
  const err = openSync(logFile, 'a');
  const child = spawn(command, args, {
    cwd,
    env,
    detached: true,
    stdio: ['ignore', out, err],
    windowsHide: true,
  });
  child.unref();
  return child.pid;
}

async function ensureService({ name, healthUrl, command, args, cwd, env }) {
  if (await checkHealth(healthUrl)) {
    log(true, `${name} already running (${healthUrl})`);
    return;
  }
  spawnDetached(name.toLowerCase().replace(/\s+/g, '_'), command, args, cwd, env);
  const healthy = await waitHealthy(healthUrl);
  if (healthy) {
    log(true, `${name} started (${healthUrl})`);
  } else {
    log(false, `${name} did not come up in time — check life-critical-orchestration/scripts/.dev-logs/`);
  }
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

  await ensureService({
    name: 'Decision engine',
    healthUrl: 'http://localhost:8000/health',
    command: enginePython,
    args: ['-m', 'uvicorn', 'src.main:app', '--port', '8000', '--reload'],
    cwd: path.join(LCO_ROOT, 'engine'),
    env: { ...process.env, SHUFFLE_WEBHOOK_URL: 'http://localhost:8002/playbook/run' },
  });

  await ensureService({
    name: 'Enrichment shim',
    healthUrl: 'http://localhost:8001/health',
    command: enrichmentPython,
    args: ['-m', 'uvicorn', 'src.main:app', '--port', '8001', '--reload'],
    cwd: path.join(LCO_ROOT, 'enrichment'),
    env: process.env,
  });

  await ensureService({
    name: 'Shuffle sim',
    healthUrl: 'http://localhost:8002/health',
    command: simPython,
    args: ['-m', 'uvicorn', 'server:app', '--port', '8002', '--reload'],
    cwd: path.join(LCO_ROOT, 'playbooks', 'shuffle_sim'),
    env: { ...process.env, ...simExtraEnv },
  });
}

await main();
