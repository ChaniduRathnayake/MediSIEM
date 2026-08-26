"""
Generate a VAPID keypair for Web Push (Workstream E).

Outputs the two keys in the exact base64url raw form each side expects:
  - VAPID_PUBLIC_KEY  → the browser's applicationServerKey (frontend subscribe)
  - VAPID_PRIVATE_KEY → what pywebpush signs with (sim, push.py)

Run once, then put the values in your environment (or the sim's .env). The
private key never leaves the server; the public key is safe to ship to the
browser.

    cd playbooks/shuffle_sim
    python generate_vapid.py

Copy the printed lines into a .env / your shell before starting the sim.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main() -> None:
    key = ec.generate_private_key(ec.SECP256R1())

    private_raw = key.private_numbers().private_value.to_bytes(32, "big")
    public_point = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,  # 65-byte 0x04||X||Y
    )

    print("# --- VAPID keypair (Web Push) — keep the private key secret ---")
    print(f"VAPID_PUBLIC_KEY={b64url(public_point)}")
    print(f"VAPID_PRIVATE_KEY={b64url(private_raw)}")
    print("VAPID_SUBJECT=mailto:oncall@hospital.local")


if __name__ == "__main__":
    main()
