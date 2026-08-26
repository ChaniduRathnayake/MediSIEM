"""Clinical HL7 receiver -- stands in for the EHR / central monitoring station.

A minimal MLLP server: receives HL7 ORU^R01 messages from the patient monitor,
parses the vitals, returns a proper MLLP-framed ACK, and logs each receipt. The
receipt log doubles as (a) the clinical-traffic record a SIEM ingests and (b) a
continuity signal for the disruption metric. Stdlib only.
"""
import json
import os
import socket
import threading
from datetime import datetime, timezone

SB, EB, CR = b"\x0b", b"\x1c", b"\x0d"
HOST = "0.0.0.0"
PORT = int(os.getenv("HL7_PORT", "2575"))          # 2575 = IANA-registered HL7/MLLP port
LOG_PATH = os.getenv("HL7_LOG_PATH", "/data/hl7_received.jsonl")


def _write(rec):
    rec["ts"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")


def parse(message):
    """Extract the control id, patient, and OBX values from an HL7 message."""
    out = {"obx": []}
    for line in message.split("\r"):
        f = line.split("|")
        if f[0] == "MSH":
            out["msg_id"] = f[9] if len(f) > 9 else "?"
            out["sending_app"] = f[2] if len(f) > 2 else "?"
        elif f[0] == "PID" and len(f) > 3:
            out["patient"] = f[3].split("^")[0]
        elif f[0] == "OBX" and len(f) > 5:
            name = f[3].split("^")[1] if "^" in f[3] else f[3]
            unit = f[6] if len(f) > 6 else ""
            out["obx"].append(f"{name}={f[5]}{unit}")
    return out


def build_ack(msg_id, code="AA"):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    msh = f"MSH|^~\\&|EHR|HOSPITAL|VITALS_MON|ICU|{ts}||ACK^R01|{msg_id}-ACK|P|2.5"
    msa = f"MSA|{code}|{msg_id}"
    return (msh + "\r" + msa).encode()


def handle(conn):
    try:
        conn.settimeout(5)
        data = b""
        while EB + CR not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        message = data.replace(SB, b"").replace(EB + CR, b"").decode(errors="replace")
        info = parse(message)
        conn.sendall(SB + build_ack(info.get("msg_id", "?")) + EB + CR)
        _write({"event": "hl7_received", "msg_id": info.get("msg_id"),
                "patient": info.get("patient"), "vitals": info.get("obx")})
        print(f"[receiver] ORU^R01 {info.get('msg_id')} from {info.get('sending_app')}: "
              f"{', '.join(info.get('obx', []))} -> ACK AA", flush=True)
    except Exception as e:
        print(f"[receiver] error: {e}", flush=True)
    finally:
        conn.close()


def main():
    _write({"event": "receiver_start", "port": PORT})
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(8)
    print(f"[receiver] MLLP listening on :{PORT}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
