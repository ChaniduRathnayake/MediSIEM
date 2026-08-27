// Shared helpers for spawning/health-checking detached dev-only companion
// services (life-critical-orchestration's engine/enrichment/shuffle_sim,
// the IP Reputation FastAPI server). Extracted once a second caller needed
// the exact same spawn/health-check/stale-port-cleanup logic as
// startLifeCriticalServices.js — keeping one copy means the zombie-cleanup
// fix only has to exist in one place.
//
// Uses only Node builtins (no extra dependency) since these scripts must run
// before npm's own dependency tree is guaranteed relevant to them.

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, openSync } from 'node:fs';
import path from 'node:path';

export function log(ok, msg) {
  // Matches server.js's own startup log style exactly (two spaces after the emoji).
  console.log(`${ok ? '✅' : '⚠️'}  ${msg}`);
}

// 1000ms used to be the default, but ip_reputation_server's /api/health does
// a synchronous MongoDB ping (serverSelectionTimeoutMS=2500) and still
// returns 200 (degraded) when Mongo isn't running — a common dev-machine
// state. A 1000ms client-side abort meant every probe timed out before that
// response ever arrived, so waitHealthy below never observed the service as
// healthy, this file's killStalePort forcibly killed the about-to-succeed
// process before its next attempt, and dev:ip looped "did not come up in
// time" forever. 4000ms comfortably clears that worst case.
export async function checkHealth(url, timeoutMs = 4000) {
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

export async function waitHealthy(url, attempts = 20, intervalMs = 500) {
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
export function resolvePython(venvDir) {
  const venvPython = path.join(venvDir, 'Scripts', 'python.exe');
  if (existsSync(venvPython)) {
    const probe = spawnSync(venvPython, ['--version']);
    if (probe.status === 0) return venvPython;
  }
  return 'python';
}

export function spawnDetached(logDir, name, command, args, cwd, env) {
  mkdirSync(logDir, { recursive: true });
  const logFile = path.join(logDir, `${name}.log`);
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

// A port that's bound but unhealthy means a previous run's process is wedged
// there — spawning another one just adds a second zombie fighting for the
// same port. Kill whatever's listening first so each service ever has at
// most one live process.
export function killStalePort(port) {
  try {
    if (process.platform === 'win32') {
      const out = spawnSync('netstat', ['-ano', '-p', 'TCP'], { encoding: 'utf-8' }).stdout || '';
      const pids = new Set();
      for (const line of out.split('\n')) {
        const m = line.match(/^\s*TCP\s+\S*:(\d+)\s+\S+\s+(?:LISTENING|CLOSE_WAIT)\s+(\d+)/i);
        if (m && Number(m[1]) === port) pids.add(m[2]);
      }
      for (const pid of pids) spawnSync('taskkill', ['/PID', pid, '/F', '/T']);
    } else {
      const out = spawnSync('lsof', ['-ti', `:${port}`], { encoding: 'utf-8' }).stdout || '';
      for (const pid of out.split('\n').map((s) => s.trim()).filter(Boolean)) {
        spawnSync('kill', ['-9', pid]);
      }
    }
  } catch {
    // Best-effort cleanup — if this fails, spawnDetached below just adds
    // another contender for the port instead of a clean replacement.
  }
}

export async function ensureService({ name, healthUrl, command, args, cwd, env, logDir, logHint }) {
  if (await checkHealth(healthUrl)) {
    log(true, `${name} already running (${healthUrl})`);
    return;
  }
  killStalePort(Number(new URL(healthUrl).port));
  spawnDetached(logDir, name.toLowerCase().replace(/\s+/g, '_'), command, args, cwd, env);
  const healthy = await waitHealthy(healthUrl);
  if (healthy) {
    log(true, `${name} started (${healthUrl})`);
  } else {
    log(false, `${name} did not come up in time — check ${logHint}`);
  }
}
