"""
Enforcement — the *real* side effect of an isolate_host decision.

This is the Workstream C piece that turns the ≤5% accidental-disruption
metric from *asserted* into *measured*. Where monitored_mode records a
Zero-Interference assertion (and does nothing to the device), isolate_host
actually cuts the device off — so the heartbeat-logger can measure the
resulting downtime.

Design decision (PP2): isolation happens at the NETWORK BOUNDARY, from
*outside* the device, not by reaching inside it.

  - `docker network disconnect <network> <container>` severs the device's
    link to the broker; its clinical telemetry stops reaching subscribers.
    The heartbeat-logger sees the stream go silent → measurable disruption.
  - `docker network connect` restores it → measurable recovery.

Why network-boundary and not an in-device firewall rule (iptables): a real
IoMT device is a closed, proprietary black box — you generally cannot log
in and add a firewall rule, and agentless / network-side control is the
documented production path. Isolating from the network edge (as a hospital
switch or firewall would) is therefore both the *more faithful* model of
production and the *zero-dependency* one (needs nothing installed on the
device). The emulator converges with a real device exactly at this network
boundary — the same layer the SIEM observes.

For assets that have no bound emulated container (the other registry
entries), isolation is *recorded as simulated* — same behaviour as the
PP1 marker, so nothing regresses. Only the real device (ICU-VENT-003)
gets a real network cut.

Every action here is fire-and-forget-safe: subprocess failures are caught,
recorded, and returned as structured results. Nothing in this module raises.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, Optional

from action_log import ActionLog, get_log


# --------------------------------------------------------------------------
# Config: which asset_ids map to a real, isolatable emulated container.
#
# Only ICU-VENT-003 is a live device-sim container today. Everything else
# falls through to "simulated" isolation. Override / extend via the
# SHUFFLE_ENFORCEMENT_MAP env var, e.g.:
#   SHUFFLE_ENFORCEMENT_MAP='{"RAD-LINAC-001": {"container": "iomt-orthanc"}}'
# --------------------------------------------------------------------------

_DEFAULT_MAP: Dict[str, Dict[str, str]] = {
    "ICU-VENT-003": {"container": "iomt-vitals-monitor"},
}

# Fallback network name if we can't discover one by inspection. This is the
# device-sim compose default (<project-dir>_default). We *prefer* to discover
# the live network at isolate time, so this is only a safety net.
DEFAULT_NETWORK = os.getenv("SHUFFLE_ENFORCEMENT_NETWORK", "device-sim_default")

WORKFLOW_NAME = "enforcement"

# Remember the network each container was on when we disconnected it, so we
# can reconnect to the *same* network on release even though inspection can
# no longer see it (a disconnected container reports no networks).
_last_network: Dict[str, str] = {}


def _load_map() -> Dict[str, Dict[str, str]]:
    """Merge the default asset→container map with any env override."""
    merged = dict(_DEFAULT_MAP)
    raw = os.getenv("SHUFFLE_ENFORCEMENT_MAP", "").strip()
    if raw:
        try:
            override = json.loads(raw)
            if isinstance(override, dict):
                merged.update(override)
        except json.JSONDecodeError:
            pass  # bad JSON → silently ignore, keep defaults
    return merged


def is_enforceable(asset_id: str) -> bool:
    """True if this asset maps to a real emulated container we can isolate."""
    return asset_id in _load_map()


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _run_docker(args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a docker command, capturing output. Never raises on non-zero exit."""
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _discover_network(container: str) -> Optional[str]:
    """Return the first docker network a container is attached to, or None."""
    try:
        proc = _run_docker([
            "inspect", "-f",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}",
            container,
        ])
    except (subprocess.SubprocessError, OSError):
        return None
    name = (proc.stdout or "").strip()
    return name or None


def isolate(
    asset_id: str,
    *,
    decision_id: str,
    reason: str = "isolate_host",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Isolate the device at the network boundary and record the outcome.

    Returns a structured result dict (also written to the action log):
        {ok, mode: real|simulated, asset_id, container, network, message, ...}
    """
    log = log or get_log()
    mapping = _load_map().get(asset_id)

    # --- No bound container → simulated isolation (parity with PP1 marker) ---
    if mapping is None:
        entry = log.record(
            decision_id=decision_id,
            asset_id=asset_id,
            workflow=WORKFLOW_NAME,
            step="network_isolation",
            status="simulated",
            detail=(
                f"Isolation recorded for {asset_id} (no emulated container bound). "
                "In production this asset would be cut at its network boundary."
            ),
            extra={"mode": "simulated", "reason": reason},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]

    if not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="network_isolation", status="simulated",
            detail=f"docker CLI unavailable; isolation of {container} simulated.",
            extra={"mode": "simulated", "container": container, "reason": reason},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    # Discover the live network so release can reconnect to the same one.
    network = mapping.get("network") or _discover_network(container) or _last_network.get(asset_id) or DEFAULT_NETWORK

    proc = _run_docker(["network", "disconnect", network, container])
    stderr = (proc.stderr or "").strip()
    already = "is not connected to network" in stderr.lower()
    ok = proc.returncode == 0 or already

    if ok:
        _last_network[asset_id] = network

    status_word = "enforced" if proc.returncode == 0 else ("already_isolated" if already else "failed")
    if ok:
        detail = (
            f"Isolated {asset_id} at the network boundary: disconnected "
            f"{container} from '{network}'. Clinical telemetry stream halts — "
            "this is the disruptive action, executed only after clinician approval."
        )
        if already:
            detail = f"{asset_id} already isolated ({container} not on '{network}')."
    else:
        detail = f"Isolation of {asset_id} FAILED: {stderr or 'unknown docker error'}"

    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="network_isolation", status=status_word, detail=detail,
        extra={
            "mode": "real",
            "mechanism": "docker network disconnect",
            "container": container,
            "network": network,
            "returncode": proc.returncode,
            "stderr": stderr,
            "reason": reason,
        },
    )
    return {
        "ok": ok, "mode": "real", "asset_id": asset_id, "container": container,
        "network": network, "message": detail, "entry": entry,
    }


def release(
    asset_id: str,
    *,
    decision_id: str = "manual-release",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Reconnect the device to its network and record recovery.

    Used to reset between scenario runs and by the FR-06 path if an isolation
    ever needs undoing. No-op-with-record for non-device assets.
    """
    log = log or get_log()
    mapping = _load_map().get(asset_id)

    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="network_restore", status="simulated",
            detail=f"Restore recorded for {asset_id} (simulated).",
            extra={"mode": "simulated"},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]
    network = mapping.get("network") or _last_network.get(asset_id) or DEFAULT_NETWORK

    proc = _run_docker(["network", "connect", network, container])
    stderr = (proc.stderr or "").strip()
    already = "already exists in network" in stderr.lower() or "endpoint with name" in stderr.lower()
    ok = proc.returncode == 0 or already

    status_word = "restored" if proc.returncode == 0 else ("already_connected" if already else "failed")
    if ok:
        detail = (
            f"Reconnected {container} to '{network}'. {asset_id} clinical stream "
            "resumes; heartbeat-logger will record recovery."
        )
        if already:
            detail = f"{asset_id} already connected to '{network}'."
    else:
        detail = f"Restore of {asset_id} FAILED: {stderr or 'unknown docker error'}"

    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="network_restore", status=status_word, detail=detail,
        extra={
            "mode": "real", "mechanism": "docker network connect",
            "container": container, "network": network,
            "returncode": proc.returncode, "stderr": stderr,
        },
    )
    return {"ok": ok, "mode": "real", "asset_id": asset_id, "message": detail, "entry": entry}


# --------------------------------------------------------------------------
# Workstream F / §J — graded, non-disruptive containment.
#
# F-1: selective_block — the surgical alternative to a full isolate. Instead
# of cutting the device off the network entirely, DROP only the malicious
# flow (a C2 dest, an exfil target, an exploited service port) while leaving
# the clinical protocols untouched: MQTT to the broker (1883) and HL7/MLLP to
# the clinical receiver (2575). The heartbeat keeps flowing → measured ~0
# clinical disruption while the threat's comms are contained.
#
# Mechanism: a scoped DROP rule applied to the device's network namespace via
# `docker exec`. This models an access-switch / NAC per-port ACL — an edge
# policy on the port the device connects to, not an agent inside the device's
# application/control plane. Same network-boundary layer as the docker-network
# cut above; a higher-fidelity future model is an inline L3 gateway container.
# Requires iptables in the device image (see vitals-monitor/Dockerfile) and
# NET_ADMIN (already granted in docker-compose).
# --------------------------------------------------------------------------

# Clinical destinations that must NEVER be blocked — the safety invariant that
# makes "graded containment" safe on a life-critical device.
CLINICAL_PORTS = {1883, 2575}  # MQTT broker, HL7/MLLP receiver
CLINICAL_HOSTS = {"broker", "iomt-broker", "clinical-receiver", "iomt-clinical-receiver"}

# All selective DROP rules live in one dedicated chain so restore is a clean
# flush that can't touch anything else in the device's tables.
_BLOCK_CHAIN = "LCA_BLOCK"


def _sanitize_dest(dest: str) -> Optional[str]:
    """Allow only host/IP-ish characters — defends the docker exec shell."""
    dest = (dest or "").strip()
    if not dest:
        return None
    if all(ch.isalnum() or ch in ".:-_" for ch in dest):
        return dest
    return None


def _docker_exec(container: str, script: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a /bin/sh script inside a container's namespace. Never raises."""
    return _run_docker(["exec", container, "sh", "-c", script], timeout=timeout)


def selective_block(
    asset_id: str,
    *,
    dest: str,
    dports: Optional[list[int]] = None,
    decision_id: str,
    reason: str = "selective_block",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Surgically DROP the device's traffic to `dest`, leaving clinical flows open.

    Args:
        dest: the malicious destination (IP or hostname) to cut off.
        dports: optional TCP/UDP dest ports to restrict; None blocks all traffic
                to `dest`.

    Safety invariant: refuses to block a clinical peer or clinical port, so a
    graded response can never accidentally silence patient telemetry.
    """
    log = log or get_log()

    # --- Safety invariant: never block clinical comms ---
    clean_dest = _sanitize_dest(dest)
    bad_ports = bool(dports) and bool(set(dports) & CLINICAL_PORTS)
    if clean_dest is None or clean_dest in CLINICAL_HOSTS or bad_ports:
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="selective_block", status="refused",
            detail=(
                f"Refused selective_block on {asset_id}: '{dest}' is a clinical "
                "destination/port or malformed. Clinical telemetry is never cut."
            ),
            extra={"reason": reason, "dest": dest, "dports": dports},
        )
        return {"ok": False, "refused": True, "asset_id": asset_id, "entry": entry}

    mapping = _load_map().get(asset_id)

    # --- No bound container / no docker → simulated (parity with isolate) ---
    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="selective_block", status="simulated",
            detail=(
                f"Selective block of {clean_dest} recorded for {asset_id} "
                "(no emulated container / docker). Clinical flows would stay open."
            ),
            extra={"mode": "simulated", "dest": clean_dest, "dports": dports, "reason": reason},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]

    # Build the iptables script: ensure the dedicated chain + a single OUTPUT
    # jump exist (idempotent), then append the scoped DROP(s).
    if dports:
        drops = []
        for p in dports:
            p = int(p)
            drops.append(f"iptables -A {_BLOCK_CHAIN} -d {clean_dest} -p tcp --dport {p} -j DROP")
            drops.append(f"iptables -A {_BLOCK_CHAIN} -d {clean_dest} -p udp --dport {p} -j DROP")
        drop_cmds = "; ".join(drops)
    else:
        drop_cmds = f"iptables -A {_BLOCK_CHAIN} -d {clean_dest} -j DROP"

    script = (
        f"iptables -N {_BLOCK_CHAIN} 2>/dev/null || true; "
        f"iptables -C OUTPUT -j {_BLOCK_CHAIN} 2>/dev/null || iptables -I OUTPUT 1 -j {_BLOCK_CHAIN}; "
        f"{drop_cmds}"
    )
    proc = _docker_exec(container, script)
    stderr = (proc.stderr or "").strip()
    ok = proc.returncode == 0

    if ok:
        detail = (
            f"Selective block on {asset_id}: dropped traffic to {clean_dest}"
            f"{(' ports ' + ','.join(map(str, dports))) if dports else ''} at the "
            "device's network edge. Clinical flows (MQTT 1883, HL7 2575) remain "
            "open — the heartbeat keeps flowing while the threat's path is cut."
        )
    else:
        detail = f"Selective block on {asset_id} FAILED: {stderr or 'unknown docker/iptables error'}"

    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="selective_block", status="enforced" if ok else "failed", detail=detail,
        extra={
            "mode": "real",
            "mechanism": "iptables DROP (device netns, edge ACL model)",
            "container": container,
            "dest": clean_dest,
            "dports": dports,
            "chain": _BLOCK_CHAIN,
            "returncode": proc.returncode,
            "stderr": stderr,
            "reason": reason,
        },
    )
    return {
        "ok": ok, "mode": "real", "asset_id": asset_id, "container": container,
        "dest": clean_dest, "dports": dports, "message": detail, "entry": entry,
    }


def restore_flows(
    asset_id: str,
    *,
    decision_id: str = "manual-restore",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Remove all selective blocks (flush the LCA_BLOCK chain). Reset between runs."""
    log = log or get_log()
    mapping = _load_map().get(asset_id)

    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="flows_restored", status="simulated",
            detail=f"Selective-block restore recorded for {asset_id} (simulated).",
            extra={"mode": "simulated"},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]
    proc = _docker_exec(container, f"iptables -F {_BLOCK_CHAIN} 2>/dev/null || true")
    stderr = (proc.stderr or "").strip()
    ok = proc.returncode == 0

    detail = (
        f"Cleared selective blocks on {asset_id} (flushed {_BLOCK_CHAIN}); all "
        "non-clinical flows restored."
        if ok else
        f"Restore of flows on {asset_id} FAILED: {stderr or 'unknown docker error'}"
    )
    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="flows_restored", status="restored" if ok else "failed", detail=detail,
        extra={"mode": "real", "mechanism": "iptables -F", "container": container,
               "chain": _BLOCK_CHAIN, "returncode": proc.returncode, "stderr": stderr},
    )
    return {"ok": ok, "mode": "real", "asset_id": asset_id, "message": detail, "entry": entry}


# --------------------------------------------------------------------------
# F-2: throttle — rate-limit a flagged flow instead of dropping it.
#
# The graded middle of the spectrum: where selective_block DROPs a known-bad
# destination outright, throttle SLOWS it — useful when a flow is suspicious
# but not confirmed malicious, or to strangle exfiltration / ransomware
# staging while preserving some connectivity. The throttle is scoped to the
# flagged destination only (a tc htb class + u32 dst filter), so clinical
# traffic to the broker/receiver stays in the full-speed default class — the
# heartbeat is structurally unaffected.
#
# Mechanism: tc (iproute2) on the device's interface, in its network namespace
# via docker exec — same edge model as selective_block. Requires iproute2 in
# the device image (see vitals-monitor/Dockerfile) and NET_ADMIN.
# --------------------------------------------------------------------------

import re as _re

# Device interface to shape (single-network container -> eth0).
THROTTLE_IFACE = os.getenv("SHUFFLE_ENFORCEMENT_IFACE", "eth0")

# Accept rates like "1mbit", "512kbit", "2gbit", "800000bit".
_RATE_RE = _re.compile(r"^\d+(?:bit|kbit|mbit|gbit)$", _re.IGNORECASE)


def _valid_rate(rate: str) -> bool:
    return bool(_RATE_RE.match((rate or "").strip()))


def throttle(
    asset_id: str,
    *,
    dest: str,
    rate: str = "1mbit",
    decision_id: str,
    reason: str = "throttle",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Rate-limit the device's traffic to `dest` at `rate`; clinical stays full-speed.

    Safety invariant: refuses to throttle a clinical peer. `dest` must be an IP
    (the detected dst_ip) — tc's u32 filter matches on address.
    """
    log = log or get_log()

    clean_dest = _sanitize_dest(dest)
    if clean_dest is None or clean_dest in CLINICAL_HOSTS:
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="throttle", status="refused",
            detail=f"Refused throttle on {asset_id}: '{dest}' is a clinical destination or malformed.",
            extra={"reason": reason, "dest": dest, "rate": rate},
        )
        return {"ok": False, "refused": True, "asset_id": asset_id, "entry": entry}

    if not _valid_rate(rate):
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="throttle", status="refused",
            detail=f"Refused throttle on {asset_id}: malformed rate '{rate}'.",
            extra={"reason": reason, "dest": clean_dest, "rate": rate},
        )
        return {"ok": False, "refused": True, "asset_id": asset_id, "entry": entry}

    mapping = _load_map().get(asset_id)
    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="throttle", status="simulated",
            detail=f"Throttle of {clean_dest} to {rate} recorded for {asset_id} (no container / docker).",
            extra={"mode": "simulated", "dest": clean_dest, "rate": rate, "reason": reason},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]
    dev = THROTTLE_IFACE
    script = (
        f"tc qdisc add dev {dev} root handle 1: htb default 10 2>/dev/null || true; "
        f"tc class add dev {dev} parent 1: classid 1:10 htb rate 1000mbit 2>/dev/null || true; "
        f"tc class replace dev {dev} parent 1: classid 1:20 htb rate {rate} ceil {rate}; "
        f"tc filter replace dev {dev} protocol ip parent 1: prio 1 u32 match ip dst {clean_dest}/32 flowid 1:20"
    )
    proc = _docker_exec(container, script)
    stderr = (proc.stderr or "").strip()
    ok = proc.returncode == 0
    if ok:
        detail = (
            f"Throttle on {asset_id}: traffic to {clean_dest} capped at {rate} on {dev}. "
            "Clinical flows (broker/receiver) stay in the full-speed default class — the "
            "heartbeat is unaffected while the flagged flow is strangled."
        )
    else:
        detail = f"Throttle on {asset_id} FAILED: {stderr or 'unknown tc error'}"
    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="throttle", status="enforced" if ok else "failed", detail=detail,
        extra={"mode": "real", "mechanism": "tc htb + u32 dst filter", "container": container,
               "iface": dev, "dest": clean_dest, "rate": rate, "returncode": proc.returncode,
               "stderr": stderr, "reason": reason},
    )
    return {"ok": ok, "mode": "real", "asset_id": asset_id, "container": container,
            "dest": clean_dest, "rate": rate, "message": detail, "entry": entry}


def unthrottle(
    asset_id: str,
    *,
    decision_id: str = "manual-unthrottle",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Remove all rate-limiting (delete the tc root qdisc). Reset between runs."""
    log = log or get_log()
    mapping = _load_map().get(asset_id)
    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="throttle_cleared", status="simulated",
            detail=f"Throttle-clear recorded for {asset_id} (simulated).",
            extra={"mode": "simulated"},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}
    container = mapping["container"]
    dev = THROTTLE_IFACE
    proc = _docker_exec(container, f"tc qdisc del dev {dev} root 2>/dev/null || true")
    stderr = (proc.stderr or "").strip()
    ok = proc.returncode == 0
    detail = (f"Cleared traffic shaping on {asset_id} ({dev}); all flows full-speed."
              if ok else f"Throttle-clear on {asset_id} FAILED: {stderr or 'unknown tc error'}")
    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="throttle_cleared", status="restored" if ok else "failed", detail=detail,
        extra={"mode": "real", "mechanism": "tc qdisc del", "container": container, "iface": dev,
               "returncode": proc.returncode, "stderr": stderr},
    )
    return {"ok": ok, "mode": "real", "asset_id": asset_id, "message": detail, "entry": entry}


# --------------------------------------------------------------------------
# F-3: quarantine — micro-segmentation (the "allow only clinical" response).
#
# The blunt end of the graded spectrum below a full isolate. Instead of
# dropping/slowing one flagged flow, quarantine WALLS the device onto a
# restricted "clinical-only" segment that contains just its essential clinical
# peers (the MQTT broker + the HL7 receiver). The clinical path survives; every
# other network path — lateral movement, unknown peers, the internet — is cut.
# Used when you don't know exactly what's malicious but must stop spread
# (worms, ransomware propagation, broad/unknown threats).
#
# Mechanism: reuses the docker-network primitive. We move the device from its
# general network onto a clinical-only network (created on demand, with the
# clinical peers attached under their service aliases). Connect-before-
# disconnect so there is no moment fully off-network. This is the faithful
# emulator model of a hospital moving a device to a locked-down clinical VLAN.
# --------------------------------------------------------------------------

# The restricted segment quarantined devices move onto.
CLINICAL_NETWORK = os.getenv("SHUFFLE_CLINICAL_NETWORK", "clinical-only")

# --------------------------------------------------------------------------
# Config: which OTHER containers a given asset needs to keep reaching when
# quarantined — its clinical peers. This is the "site-specific clinical-only
# segment definition" ENABLE_QUARANTINE's docstring (server.py) says quarantine
# needs before it's safe to turn on — previously that definition didn't
# exist: every quarantined device got the SAME hardcoded two peers regardless
# of which device it actually was. Two devices with different clinical
# dependencies must not share one blanket peer list, or quarantine either
# over-restricts (cuts a peer it actually needs) or under-restricts (grants
# reachability to a peer it never talks to).
#
# Keyed by asset_id — same key space as _DEFAULT_MAP above. Each value is
# {container_name: network_alias}; the alias is what the quarantined
# device's own DNS lookups for that peer resolve to on the clinical segment
# (e.g. MQTT_HOST=broker), so it must match what the device actually expects
# to reach that peer by.
#
# Only ICU-VENT-003 has a real emulated dependency today (the MQTT broker +
# HL7 receiver it publishes vitals to). Override / extend via the
# SHUFFLE_CLINICAL_PEERS_MAP env var, e.g.:
#   SHUFFLE_CLINICAL_PEERS_MAP='{"RAD-LINAC-001": {"iomt-orthanc": "pacs"}}'
# --------------------------------------------------------------------------

_DEFAULT_CLINICAL_PEERS: Dict[str, Dict[str, str]] = {
    "ICU-VENT-003": {"iomt-broker": "broker", "iomt-clinical-receiver": "clinical-receiver"},
}


def _load_clinical_peers() -> Dict[str, Dict[str, str]]:
    """Merge the default asset->clinical-peers map with any env override."""
    merged = dict(_DEFAULT_CLINICAL_PEERS)
    raw = os.getenv("SHUFFLE_CLINICAL_PEERS_MAP", "").strip()
    if raw:
        try:
            override = json.loads(raw)
            if isinstance(override, dict):
                merged.update(override)
        except json.JSONDecodeError:
            pass  # bad JSON -> silently ignore, keep defaults
    return merged


def clinical_peers_for(asset_id: str) -> Dict[str, str]:
    """{container_name: alias} this asset needs reachable when quarantined.

    Empty (not some shared fallback list) for an asset with no configured
    peers — quarantining an asset we have no dependency list for should wall
    it off from everything rather than silently granting it reachability to
    some OTHER device's peers.
    """
    return dict(_load_clinical_peers().get(asset_id, {}))


# Remember the general network we pulled the device off, to rejoin on release.
_last_general: Dict[str, str] = {}


def _list_networks(container: str) -> list:
    """Return every docker network a container is currently attached to."""
    proc = _run_docker([
        "inspect", "-f",
        "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        container,
    ])
    return (proc.stdout or "").split()


def _ensure_clinical_network(asset_id: str) -> None:
    """Create the clinical-only network (if absent) and attach asset_id's own
    configured clinical peers (see clinical_peers_for() above)."""
    inspect = _run_docker(["network", "inspect", CLINICAL_NETWORK])
    if inspect.returncode != 0:
        _run_docker(["network", "create", CLINICAL_NETWORK])
    for peer, alias in clinical_peers_for(asset_id).items():
        # Idempotent: ignores "already exists" / missing-peer errors.
        _run_docker(["network", "connect", "--alias", alias, CLINICAL_NETWORK, peer])


def quarantine(
    asset_id: str,
    *,
    decision_id: str,
    reason: str = "quarantine",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Move the device onto the clinical-only segment; block all non-clinical paths.

    Safety property by construction: the device is only ever moved *onto* the
    clinical segment (which carries the broker + receiver), so its clinical
    path is never severed — unlike isolate, which removes it from every network.
    """
    log = log or get_log()
    mapping = _load_map().get(asset_id)

    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="quarantine", status="simulated",
            detail=(
                f"Quarantine recorded for {asset_id} (no container / docker). In "
                "production the device would move to a clinical-only VLAN."
            ),
            extra={"mode": "simulated", "reason": reason},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]
    peers = clinical_peers_for(asset_id)

    # Which network are we pulling it off? The one that isn't clinical-only.
    nets = _list_networks(container)
    general = next((n for n in nets if n != CLINICAL_NETWORK), None) \
        or _last_general.get(asset_id) or DEFAULT_NETWORK

    _ensure_clinical_network(asset_id)

    # Connect to the clinical segment FIRST (no off-network gap), then drop the
    # general network so lateral paths disappear.
    conn = _run_docker(["network", "connect", CLINICAL_NETWORK, container])
    conn_err = (conn.stderr or "").strip()
    already_clinical = "already exists in network" in conn_err.lower() or "endpoint with name" in conn_err.lower()

    disc = _run_docker(["network", "disconnect", general, container])
    disc_err = (disc.stderr or "").strip()
    already_off = "is not connected to network" in disc_err.lower()

    ok = (conn.returncode == 0 or already_clinical) and (disc.returncode == 0 or already_off)
    if conn.returncode == 0 or already_clinical:
        _last_general[asset_id] = general

    if ok and peers:
        detail = (
            f"Quarantined {asset_id}: moved {container} onto '{CLINICAL_NETWORK}' "
            f"({', '.join(peers.values())} only) and off '{general}'. Clinical "
            "telemetry continues; lateral movement to non-clinical hosts is blocked."
        )
    elif ok:
        # No dependency list configured for this asset — nothing to grant it
        # reachability to, so this is functionally a full network cut, not
        # the gentler "clinical path survives" containment quarantine is
        # supposed to be. Say so plainly rather than letting the audit trail
        # claim clinical continuity that didn't happen.
        detail = (
            f"Quarantined {asset_id}: moved {container} onto '{CLINICAL_NETWORK}' "
            f"and off '{general}'. No clinical peers are configured for this asset "
            "(see SHUFFLE_CLINICAL_PEERS_MAP) — it has no reachable peers on the "
            "clinical segment, so this is equivalent to a full network cut, not a "
            "graded containment."
        )
    else:
        detail = f"Quarantine of {asset_id} FAILED: connect='{conn_err}' disconnect='{disc_err}'"

    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="quarantine", status="enforced" if ok else "failed", detail=detail,
        extra={
            "mode": "real",
            "mechanism": "docker network move -> clinical-only segment",
            "container": container,
            "clinical_network": CLINICAL_NETWORK,
            "general_network": general,
            "clinical_peers": peers,
            "reason": reason,
        },
    )
    return {"ok": ok, "mode": "real", "asset_id": asset_id, "container": container,
            "clinical_network": CLINICAL_NETWORK, "general_network": general,
            "clinical_peers": peers, "message": detail, "entry": entry}


def release_quarantine(
    asset_id: str,
    *,
    decision_id: str = "manual-unquarantine",
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Return the device to its general network (undo quarantine)."""
    log = log or get_log()
    mapping = _load_map().get(asset_id)

    if mapping is None or not _docker_available():
        entry = log.record(
            decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
            step="quarantine_released", status="simulated",
            detail=f"Quarantine-release recorded for {asset_id} (simulated).",
            extra={"mode": "simulated"},
        )
        return {"ok": True, "mode": "simulated", "asset_id": asset_id, "entry": entry}

    container = mapping["container"]
    general = _last_general.get(asset_id) or DEFAULT_NETWORK

    conn = _run_docker(["network", "connect", general, container])
    conn_err = (conn.stderr or "").strip()
    already = "already exists in network" in conn_err.lower() or "endpoint with name" in conn_err.lower()
    _run_docker(["network", "disconnect", CLINICAL_NETWORK, container])  # best-effort

    ok = conn.returncode == 0 or already
    detail = (f"Released {asset_id} from quarantine: rejoined '{general}', left "
              f"'{CLINICAL_NETWORK}'." if ok
              else f"Quarantine-release of {asset_id} FAILED: {conn_err or 'unknown docker error'}")
    entry = log.record(
        decision_id=decision_id, asset_id=asset_id, workflow=WORKFLOW_NAME,
        step="quarantine_released", status="restored" if ok else "failed", detail=detail,
        extra={"mode": "real", "mechanism": "docker network connect", "container": container,
               "general_network": general, "clinical_network": CLINICAL_NETWORK},
    )
    return {"ok": ok, "mode": "real", "asset_id": asset_id, "message": detail, "entry": entry}
