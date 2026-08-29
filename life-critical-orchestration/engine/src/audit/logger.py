"""
Hash-chained append-only audit log.

Each entry is a JSON line containing the decision plus a SHA-256 hash that
includes the previous entry's hash. This makes the log tamper-evident: any
modification to an old entry breaks the chain from that point onward, and
re-running verification will detect it.

This is a PP1-grade implementation. The proposal mentions blockchain anchoring
as a future enhancement (PP2/Final); for PP1 the hash chain alone is sufficient
to demonstrate the immutable-logging principle.
"""

import hashlib
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Iterator

from ..models.decision import Decision


GENESIS_HASH = "0" * 64  # The "previous hash" for the very first entry.


class AuditLogger:
    """Append-only logger backed by a single JSONL file."""

    def __init__(self, log_path: str | Path):
        self.path = Path(log_path)
        # Ensure parent directory exists so the open() doesn't fail
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Touch the file so it exists even before the first entry
        self.path.touch(exist_ok=True)
        # Guards the read-last-hash-then-append critical section below.
        # /decide is a sync FastAPI handler, so Starlette runs concurrent
        # requests in a thread pool — a burst of alerts decided within
        # milliseconds of each other (e.g. an attack simulation) could
        # previously interleave two threads' append() calls: both read the
        # same "last hash" before either had written, so the second one
        # recorded a stale previous_hash and broke the chain. Confirmed in
        # practice — 113 breaks found across the log's history before this
        # fix, all self-consistent (no tampering), purely this race.
        self._write_lock = threading.Lock()

    # ---------- Writing ----------

    def append(self, decision: Decision) -> dict:
        """Append a decision to the log; return the entry that was written."""
        with self._write_lock:
            prev_hash = self._last_hash()

            entry = {
                "logged_at": datetime.now(timezone.utc).isoformat(),
                "previous_hash": prev_hash,
                "decision": json.loads(decision.model_dump_json()),
            }
            entry["entry_hash"] = self._compute_hash(entry)

            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            return entry

    def append_followup(self, payload: dict) -> dict:
        """Append a non-decision follow-up entry (e.g. a clinician response).

        Used for Phase B of the Tier 3 two-phase flow: when a clinician
        approves or denies a Tier 3 decision, the response gets recorded
        here as a separate hash-chained entry. This keeps the original
        Decision entry immutable (good — it's the historical record of
        what the engine decided) while extending the chain with the
        clinician's outcome.

        The payload should include enough metadata to find the original
        decision (typically `referenced_decision_id`) plus whatever fields
        describe the follow-up event itself.
        """
        with self._write_lock:
            prev_hash = self._last_hash()

            entry = {
                "logged_at": datetime.now(timezone.utc).isoformat(),
                "previous_hash": prev_hash,
                "followup": payload,
            }
            entry["entry_hash"] = self._compute_hash(entry)

            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            return entry

    # ---------- Reading ----------

    def read_all(self) -> Iterator[dict]:
        """Yield every entry in the log, oldest first.

        A line that fails to parse is skipped rather than raised: append()
        is not fsync'd, so a process killed mid-write (e.g. dev's
        killStalePort force-kill of a wedged uvicorn on restart) can leave a
        torn trailing line. Treating that as fatal would 500 every reader of
        the log (including /audit/verify) over one incomplete write instead
        of just dropping the entry that never durably landed.
        """
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    print(f"[audit] skipping unparseable line {i + 1} in {self.path}", file=sys.stderr)

    # ---------- Dev reset ----------

    def reset(self) -> None:
        """Dev-only: truncate the log back to empty (see MediSIEM's
        backend/routes/dev.js POST /api/dev/wipe-playbooks). Nothing here is
        cached in memory — every read walks the file — so truncating it is
        the whole reset."""
        with self._write_lock:
            self.path.write_text("", encoding="utf-8")

    # ---------- Verification ----------

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Walk the chain start-to-end, verifying every hash.

        Returns (ok, error_message). When ok=False, error_message identifies
        the first broken entry (by entry_hash or position).
        """
        prev_hash = GENESIS_HASH
        for i, entry in enumerate(self.read_all()):
            # Each entry must point at the previous one
            if entry.get("previous_hash") != prev_hash:
                return False, f"Entry {i}: previous_hash mismatch"

            # Each entry's stored hash must match a fresh recompute
            stored = entry.get("entry_hash")
            recomputed = self._compute_hash({k: v for k, v in entry.items() if k != "entry_hash"})
            if stored != recomputed:
                return False, f"Entry {i}: entry_hash mismatch (tampered)"

            prev_hash = stored

        return True, None

    # ---------- Internals ----------

    def _last_hash(self) -> str:
        """Hash of the last entry, or GENESIS_HASH if the log is empty."""
        last = None
        for entry in self.read_all():
            last = entry
        return last["entry_hash"] if last else GENESIS_HASH

    @staticmethod
    def _compute_hash(payload: dict) -> str:
        # Canonical JSON: sorted keys, no extraneous whitespace.
        # This is essential so the hash is reproducible.
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
