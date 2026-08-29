"""
Action log — shared append-only JSONL log of every simulated action.

Every workflow step records what it would do in production via this log.
The dashboard reads from /actions on the sim's HTTP server to render the
"Shuffle Actions" panel under each decision in real time.

Format (one JSON object per line):
  {
    "logged_at":   "2026-05-06T12:34:56+00:00",
    "decision_id": "dec-...",
    "asset_id":    "RAD-LINAC-001",
    "workflow":    "monitored_mode" | "tier3_dispatch",
    "step":        "deep_telemetry" | "shadow_auditing" | ...
    "status":      "triggered" | "dispatched" | "approved" | "denied" | ...
    "detail":      "Increased log verbosity to verbose+pcap on RAD-LINAC-001",
    "extra":       {... arbitrary per-step fields ...}
  }

This is the simulator equivalent of Shuffle's per-execution log. It's
in-memory + on-disk: in-memory for fast read (the dashboard polls), on-disk
JSONL for durability across restarts.
"""

from __future__ import annotations

import json
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional


# Default log location lives next to this module's data directory.
DEFAULT_LOG_PATH = Path(__file__).resolve().parent / "data" / "action_log.jsonl"


class ActionLog:
    """Append-only action recorder + in-memory ring for fast queries.

    Thread-safety: workflows may run concurrently (FastAPI is async), so the
    write path is guarded with a lock. Reads are unsynchronised — they yield
    a snapshot of the deque, which is safe under CPython's GIL for our
    simple shapes.
    """

    def __init__(self, log_path: str | Path | None = None, ring_size: int = 500):
        self.path = Path(log_path or os.getenv("SHUFFLE_ACTION_LOG_PATH", DEFAULT_LOG_PATH))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

        self._ring: Deque[Dict[str, Any]] = deque(maxlen=ring_size)
        self._lock = threading.Lock()

        # Re-hydrate the ring on startup so the dashboard sees prior actions
        # immediately after a sim restart. Bounded by ring_size.
        self._rehydrate()

    # ---------- Writing ----------

    def record(
        self,
        *,
        decision_id: str,
        asset_id: str,
        workflow: str,
        step: str,
        status: str,
        detail: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a single action entry. Returns the entry that was written."""
        entry = {
            "logged_at": datetime.now(timezone.utc).isoformat(),
            "decision_id": decision_id,
            "asset_id": asset_id,
            "workflow": workflow,
            "step": step,
            "status": status,
            "detail": detail,
            "extra": extra or {},
        }
        with self._lock:
            self._ring.append(entry)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    # ---------- Reading ----------

    def all(self) -> List[Dict[str, Any]]:
        """Return all in-ring entries, oldest first."""
        return list(self._ring)

    def by_decision(self, decision_id: str) -> List[Dict[str, Any]]:
        """Return entries belonging to a specific decision, oldest first."""
        return [e for e in self._ring if e.get("decision_id") == decision_id]

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return up to `limit` most recent entries, newest first."""
        items = list(self._ring)
        items.reverse()
        return items[: max(0, limit)]

    # ---------- Dev reset ----------

    def reset(self) -> None:
        """Dev-only: clear the in-memory ring and truncate the on-disk log
        (see MediSIEM's backend/routes/dev.js POST /api/dev/wipe-playbooks)."""
        with self._lock:
            self._ring.clear()
            self.path.write_text("", encoding="utf-8")

    # ---------- Internals ----------

    def _rehydrate(self) -> None:
        """Load existing log entries into the in-memory ring (bounded)."""
        if not self.path.exists():
            return
        # Read the whole file then take the tail; simpler than seeking
        # for the PP1 file sizes we'll see (kilobytes, not gigabytes).
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines[-self._ring.maxlen:]:
            line = line.strip()
            if not line:
                continue
            try:
                self._ring.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip malformed lines silently — the log is recovery,
                # not gospel. New entries will continue cleanly.
                continue


# Module-level shared instance. Fine for the sim — there's exactly one
# action log, and creating multiple instances pointing at the same file
# would just be confusing.
_default: Optional[ActionLog] = None


def get_log() -> ActionLog:
    global _default
    if _default is None:
        _default = ActionLog()
    return _default


def reset_default_for_tests(path: Path) -> ActionLog:
    """Hook for tests: replace the module-level log with one at `path`."""
    global _default
    _default = ActionLog(log_path=path)
    return _default
