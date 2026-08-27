#!/usr/bin/env node
// Boots the IP Reputation backend alongside MediSIEM's backend dev server.
// Only runs via `npm run dev:full` or `npm run dev:ip` (see package.json) —
// plain `npm run dev` is nodemon alone and skips this file entirely.
//
// Two modes, auto-detected:
//
//  - Leader-PC mode: when ip-reputation/ exists next to MediSIEM (this
//    machine's local-only, gitignored research environment — real venvs,
//    real Mongo Atlas/AbuseIPDB/VirusTotal creds, an actual Suricata capture
//    feeding live traffic), delegate entirely to
//    ip-reputation/scripts/Start-IP-Reputation.ps1, which brings up Final-89
//    ML (:8010), the IP Reputation/Correlation server (:8088), Suricata, and
//    the flow collector as one pipeline. That script self-elevates (UAC)
//    since Suricata's packet capture needs Administrator.
//  - Bundled mode: otherwise, just the lightweight, git-tracked
//    ip_reputation_server/ FastAPI service on :8088 — e.g. a teammate's
//    checkout without the research environment. No Suricata/ML/collector.
//
// Spawned detached + unref'd, same as startLifeCriticalServices.js: it keeps
// running independently of this script (which exits right after spawning).
// Re-running later just finds it already healthy and skips straight past.

import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureService, log, resolvePython } from './serviceLifecycle.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const LEADER_ROOT = path.join(REPO_ROOT, 'ip-reputation');
const LEADER_SCRIPT = path.join(LEADER_ROOT, 'scripts', 'Start-IP-Reputation.ps1');

function startLeaderStack() {
  log(true, 'ip-reputation/ found — starting the full pipeline (Final-89 ML :8010, IP Reputation :8088, Suricata, collector)');
  // Blocking on purpose: the script itself waits out each component's health
  // check (and, on first run, a UAC prompt) before it exits, so there's
  // nothing useful for us to do concurrently. stdio: 'inherit' surfaces its
  // colored progress in this same terminal when already elevated; the
  // elevated-relaunch case instead opens its own window (Windows won't let
  // a -Verb RunAs process share this console's handles), so nothing appears
  // here in that case beyond the exit code.
  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', LEADER_SCRIPT],
    { stdio: 'inherit' }
  );
  if (result.status === 0) {
    log(true, 'IP Reputation pipeline is up (Final-89 :8010, IP Reputation :8088, Suricata, collector)');
  } else {
    log(false, `IP Reputation pipeline startup failed (exit ${result.status}) — check ip-reputation/logs/`);
    // Without this, `npm run dev:full`'s `dev:soar && dev:ip && nodemon
    // server.js` chain kept going straight into nodemon on a real failure
    // here, since this process itself always exited 0 regardless of what
    // the pipeline script reported.
    process.exitCode = 1;
  }
}

async function startBundledService() {
  const IP_REP_ROOT = path.join(REPO_ROOT, 'ip_reputation_server');
  const LOG_DIR = path.join(IP_REP_ROOT, '.dev-logs');

  if (!existsSync(IP_REP_ROOT)) {
    log(false, 'ip_reputation_server not found next to MediSIEM — skipping IP Reputation service startup');
    return;
  }

  const python = resolvePython(path.join(IP_REP_ROOT, 'venv'));

  await ensureService({
    name: 'IP Reputation service',
    healthUrl: 'http://localhost:8088/api/health',
    command: python,
    // Loopback-only, deliberately: this service has no auth of its own (a
    // QA audit confirmed every route — cases, lists, verdicts — is reachable
    // with zero credentials). It's designed to be reached exclusively
    // through the Express proxy (routes/ipReputation.js, which does enforce
    // login), and that proxy runs on this same host — 0.0.0.0 here would
    // expose the entire unauthenticated service to the whole network.
    args: ['-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', '8088'],
    cwd: IP_REP_ROOT,
    env: process.env,
    logDir: LOG_DIR,
    logHint: 'ip_reputation_server/.dev-logs/',
  });
}

async function main() {
  if (existsSync(LEADER_ROOT) && existsSync(LEADER_SCRIPT)) {
    startLeaderStack();
    return;
  }
  await startBundledService();
}

await main();
