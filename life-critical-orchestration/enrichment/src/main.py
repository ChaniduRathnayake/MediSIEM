"""
Enrichment Shim — FastAPI entry point.

This service sits between Wazuh and the decision engine. It accepts
Wazuh-shaped alerts, enriches them with clinical context from the asset
registry, and forwards the enriched alert to the engine's /decide
endpoint. The engine's response (the Decision) is returned to the caller.

Endpoints:
  GET  /health        — liveness probe
  POST /wazuh-alert   — accept a Wazuh-shaped alert, enrich, forward
  GET  /registry      — peek at the loaded registry (useful for debugging)

Run locally:
    uvicorn src.main:app --reload --port 8001

Then visit http://localhost:8001/docs.

Why a shim and not a Wazuh integrator script: the shim makes the
Wazuh -> engine path testable without a running Wazuh manager. For PP1
we POST hand-crafted Wazuh JSON straight to the shim (see
scripts/post_wazuh_alert.sh). For PP2/Final the same shim accepts
real Wazuh alerts via the integrator path documented in
infra/wazuh/integrator-config.md.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import httpx
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from .mapper import map_wazuh_alert
from .registry import AssetRegistry


# ---------- Config ----------

ENGINE_URL = os.getenv("ENGINE_URL", "http://localhost:8000")
DECIDE_ENDPOINT = f"{ENGINE_URL}/decide"

REGISTRY_PATH = os.getenv(
    "REGISTRY_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "asset_registry.json"),
)

ENRICHER_VERSION = "stub-1.0.0"


# ---------- App + dependencies ----------

app = FastAPI(
    title="Life-Critical Enrichment Shim",
    description=(
        "Accepts Wazuh-shaped alerts, enriches them with clinical context "
        "from the asset registry, and forwards them to the decision engine."
    ),
    version="0.1.0",
)

# Permissive CORS for dev; the dashboard could call this directly during
# debugging even though the normal path goes via the engine.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

registry = AssetRegistry(REGISTRY_PATH)


# ---------- Endpoints ----------

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "enrichment-shim",
        "version": "0.1.0",
        "registry_size": len(registry),
        "engine_url": ENGINE_URL,
    }


@app.get("/registry")
def get_registry() -> Dict[str, Any]:
    """Read-only peek at what assets the shim knows about."""
    return {
        "size": len(registry),
        "hostnames": sorted(registry._by_hostname.keys()),  # noqa: SLF001
    }


@app.post("/wazuh-alert", status_code=status.HTTP_200_OK)
async def wazuh_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Receive a Wazuh-shape alert, enrich, forward to engine, return decision.

    Returns:
        {
          "enriched_alert": <engine v1.0 alert>,
          "decision":       <engine response>,
          "registry_hit":   true | false
        }
    """
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Wazuh alert payload must be a JSON object.",
        )

    enriched = map_wazuh_alert(payload, registry, enricher_version=ENRICHER_VERSION)
    registry_hit = enriched["enrichment_meta"]["confidence"] == 1.0

    # Forward to engine. Use a fresh client per-request to keep things simple;
    # PP1 traffic volumes don't justify a connection pool yet.
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(DECIDE_ENDPOINT, json=enriched)
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Could not reach decision engine at {DECIDE_ENDPOINT}: {exc}",
            ) from exc

    if resp.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Engine rejected enriched alert ({resp.status_code}): {resp.text}",
        )

    return {
        "enriched_alert": enriched,
        "decision": resp.json(),
        "registry_hit": registry_hit,
    }
