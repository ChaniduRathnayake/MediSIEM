"""HL7 v2 ORU^R01 emitter over MLLP.

Real patient monitors report vitals to clinical systems as HL7 ORU^R01
("observation result") messages, framed by MLLP over TCP. Sending exactly that
makes the device emit standards-compliant clinical traffic -- the layer a SIEM
and the orchestration engine actually see -- instead of only toy JSON.

Hand-rolled (stdlib only) so every byte on the wire is explicit and auditable.
"""
import socket
from datetime import datetime, timezone

# MLLP framing bytes (HL7 over TCP)
SB, EB, CR = b"\x0b", b"\x1c", b"\x0d"   # start-block, end-block, carriage-return

# Real LOINC codes per vital sign (fidelity: these are the actual standard codes)
LOINC = {
    "heart_rate_bpm": ("8867-4", "Heart rate", "bpm"),
    "spo2_pct":       ("59408-5", "Oxygen saturation", "%"),
    "resp_rate_bpm":  ("9279-1", "Respiratory rate", "/min"),
}

_seq = 0


def _ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def build_oru_r01(vitals, device_id="ICU-VENT-003", patient_id="A001"):
    """Assemble an HL7 v2.5 ORU^R01 message. Segments are joined by CR per spec."""
    global _seq
    _seq += 1
    msg_id = f"{device_id}-{_seq}"
    ts = _ts()
    seg = [
        f"MSH|^~\\&|VITALS_MON|ICU|EHR|HOSPITAL|{ts}||ORU^R01|{msg_id}|P|2.5",
        f"PID|1||{patient_id}^^^HOSP^MR||DOE^JANE||19700101|F",
        f"PV1|1|I|ICU^BED03^{device_id}",
        f"OBR|1|||VITALS^Vital Signs^L|||{ts}",
    ]
    i = 0
    for key, (code, name, unit) in LOINC.items():
        if key in vitals:
            i += 1
            seg.append(f"OBX|{i}|NM|{code}^{name}^LN||{vitals[key]}|{unit}|||||F")
    if "bp_mmhg" in vitals and "/" in str(vitals["bp_mmhg"]):
        sys_, dia_ = str(vitals["bp_mmhg"]).split("/")
        i += 1; seg.append(f"OBX|{i}|NM|8480-6^Systolic blood pressure^LN||{sys_}|mmHg|||||F")
        i += 1; seg.append(f"OBX|{i}|NM|8462-4^Diastolic blood pressure^LN||{dia_}|mmHg|||||F")
    return "\r".join(seg), msg_id


def send(vitals, host, port, timeout=3.0):
    """MLLP-send one ORU^R01. Returns (ack_text|None, msg_id). Never raises."""
    message, msg_id = build_oru_r01(vitals)
    framed = SB + message.encode() + EB + CR
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(framed)
            resp = s.recv(4096)
        return resp.decode(errors="replace"), msg_id
    except OSError:
        return None, msg_id
