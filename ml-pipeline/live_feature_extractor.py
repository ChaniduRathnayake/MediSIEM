# Replaces CICFlowMeter, whose ~80-column schema has zero name overlap with the
# trained model's 45 CICIoT2023-schema columns (verified via verify_feature_cols.py).
# Sniffs live packets and computes those 45 columns directly, writing CSV rows into
# the folder flow_consumer.py already watches. Feature definitions: Neto et al.,
# "CICIoT2023", Sensors 2023, Table 4. Windows requires Npcap + an elevated shell.

import argparse
import csv
import os
import statistics
import time
from collections import defaultdict, deque

import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP

# statistics.fmean is Python 3.8+ only, but this script is meant to run on
# whatever Python a lab VM happens to ship (e.g. RHEL 8's stock python3.6) —
# fall back to a plain mean rather than crashing on the first packet.
if not hasattr(statistics, "fmean"):
    statistics.fmean = lambda data: sum(data) / len(data) if data else 0.0

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURE_COLS_PATH = os.path.join(SCRIPT_DIR, "..", "ai_server", "models", "feature_cols.pkl")

APP_PORT_MAP = {
    80: "HTTP", 8080: "HTTP",
    443: "HTTPS",
    53: "DNS",
    23: "Telnet",
    25: "SMTP",
    22: "SSH",
    194: "IRC", 6667: "IRC",
}
PROTO_NUMBER = {"ICMP": 1, "IGMP": 2, "TCP": 6, "UDP": 17}


def load_feature_columns():
    """Load the model's real column list so this script can never silently
    drift out of sync with ai_server/models/feature_cols.pkl."""
    if not os.path.exists(FEATURE_COLS_PATH):
        raise SystemExit(
            f"[live_feature_extractor] Can't find {FEATURE_COLS_PATH}. "
            "Run this from ml-pipeline/ with ai_server/ as a sibling directory, "
            "or edit FEATURE_COLS_PATH."
        )
    return list(joblib.load(FEATURE_COLS_PATH))


FEATURE_COLUMNS = load_feature_columns()


class FlowWindow:
    """Accumulates packets for one (src,dst) flow until --window is reached,
    then this whole object is handed to compute_features() and reset."""

    def __init__(self, first_src_ip):
        self.forward_ip = first_src_ip  # direction convention: first packet's src = "forward"
        self.timestamps = []
        self.lengths = []
        self.directions = []  # True = forward, False = backward
        self.protocols = []  # per-packet protocol number
        self.header_lengths = []
        self.ttls = []
        self.flags_seen = set()  # TCP flag letters seen anywhere in window
        self.flag_counts = defaultdict(int)  # per-flag packet counts
        self.app_protocols_seen = set()

    def add(self, pkt, ts):
        ip = pkt[IP]
        length = len(pkt)
        self.timestamps.append(ts)
        self.lengths.append(length)
        self.directions.append(ip.src == self.forward_ip)
        self.header_lengths.append(ip.ihl * 4)
        self.ttls.append(ip.ttl)

        proto_num = ip.proto
        self.protocols.append(proto_num)
        if proto_num == PROTO_NUMBER["ICMP"]:
            self.app_protocols_seen.add("ICMP")
        elif proto_num == PROTO_NUMBER["IGMP"]:
            self.app_protocols_seen.add("IGMP")
        elif proto_num == PROTO_NUMBER["TCP"]:
            self.app_protocols_seen.add("TCP")
        elif proto_num == PROTO_NUMBER["UDP"]:
            self.app_protocols_seen.add("UDP")

        sport = dport = None
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flag_str = str(tcp.flags)  # e.g. "SA" for SYN+ACK
            flag_letter_map = {
                "F": "fin", "S": "syn", "R": "rst", "P": "psh",
                "A": "ack", "E": "ece", "C": "cwr",
            }
            for letter, name in flag_letter_map.items():
                if letter in flag_str:
                    self.flags_seen.add(name)
                    if name in ("fin", "syn", "rst", "ack"):
                        self.flag_counts[name] += 1
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            if sport == 67 or dport == 67 or sport == 68 or dport == 68:
                self.app_protocols_seen.add("DHCP")
            if sport == 53 or dport == 53:
                self.app_protocols_seen.add("DNS")

        for port in (sport, dport):
            if port in APP_PORT_MAP:
                self.app_protocols_seen.add(APP_PORT_MAP[port])

    def __len__(self):
        return len(self.lengths)


def safe_var(xs):
    return statistics.pvariance(xs) if len(xs) > 1 else 0.0


def safe_std(xs):
    return statistics.pstdev(xs) if len(xs) > 1 else 0.0


def compute_features(win: FlowWindow, src_ip: str) -> dict:
    n = len(win)
    fwd_lengths = [l for l, d in zip(win.lengths, win.directions) if d]
    bwd_lengths = [l for l, d in zip(win.lengths, win.directions) if not d]
    fwd_count = len(fwd_lengths)
    bwd_count = len(bwd_lengths)

    span = max(win.timestamps) - min(win.timestamps) if n > 1 else 0.0
    span = span if span > 0 else 1e-6  # avoid div-by-zero on bursts faster than clock resolution
    iats = [t2 - t1 for t1, t2 in zip(win.timestamps, win.timestamps[1:])]

    avg_fwd = statistics.fmean(fwd_lengths) if fwd_lengths else 0.0
    avg_bwd = statistics.fmean(bwd_lengths) if bwd_lengths else 0.0
    var_fwd = safe_var(fwd_lengths) if fwd_lengths else 0.0
    var_bwd = safe_var(bwd_lengths) if bwd_lengths else 0.0

    pair_n = min(len(fwd_lengths), len(bwd_lengths))
    if pair_n > 1:
        fwd_p, bwd_p = fwd_lengths[:pair_n], bwd_lengths[:pair_n]
        mean_f, mean_b = statistics.fmean(fwd_p), statistics.fmean(bwd_p)
        covariance = sum((f - mean_f) * (b - mean_b) for f, b in zip(fwd_p, bwd_p)) / pair_n
    else:
        covariance = 0.0

    row = {
        "Header_Length": statistics.fmean(win.header_lengths) if win.header_lengths else 0.0,
        "Protocol Type": win.protocols[-1] if win.protocols else 0,
        "Duration": win.ttls[-1] if win.ttls else 0,  # per paper: TTL, not a time span
        "Rate": n / span,
        "Srate": fwd_count / span,
        "Drate": bwd_count / span,
        "fin_flag_number": int("fin" in win.flags_seen),
        "syn_flag_number": int("syn" in win.flags_seen),
        "rst_flag_number": int("rst" in win.flags_seen),
        "psh_flag_number": int("psh" in win.flags_seen),
        "ack_flag_number": int("ack" in win.flags_seen),
        "ece_flag_number": int("ece" in win.flags_seen),
        "cwr_flag_number": int("cwr" in win.flags_seen),
        "ack_count": win.flag_counts.get("ack", 0),
        "syn_count": win.flag_counts.get("syn", 0),
        "fin_count": win.flag_counts.get("fin", 0),
        "rst_count": win.flag_counts.get("rst", 0),
        "HTTP": int("HTTP" in win.app_protocols_seen),
        "HTTPS": int("HTTPS" in win.app_protocols_seen),
        "DNS": int("DNS" in win.app_protocols_seen),
        "Telnet": int("Telnet" in win.app_protocols_seen),
        "SMTP": int("SMTP" in win.app_protocols_seen),
        "SSH": int("SSH" in win.app_protocols_seen),
        "IRC": int("IRC" in win.app_protocols_seen),
        "TCP": int("TCP" in win.app_protocols_seen),
        "UDP": int("UDP" in win.app_protocols_seen),
        "DHCP": int("DHCP" in win.app_protocols_seen),
        "ARP": 0,  # ARP has no IP layer, so it never reaches this IP-keyed flow window
        "ICMP": int("ICMP" in win.app_protocols_seen),
        "IGMP": int("IGMP" in win.app_protocols_seen),
        "IPv": 1,  # scapy's IP layer here is always IPv4
        "LLC": 0,  # not observable without 802.2 framing — see module docstring
        "Tot sum": sum(win.lengths),
        "Min": min(win.lengths) if win.lengths else 0,
        "Max": max(win.lengths) if win.lengths else 0,
        "AVG": statistics.fmean(win.lengths) if win.lengths else 0.0,
        "Std": safe_std(win.lengths),
        "Tot size": win.lengths[-1] if win.lengths else 0,
        "IAT": statistics.fmean(iats) if iats else 0.0,
        "Number": n,
        "Magnitue": (avg_fwd + avg_bwd) ** 0.5,
        "Radius": (var_fwd + var_bwd) ** 0.5,
        "Covariance": covariance,
        "Variance": (var_fwd / var_bwd) if var_bwd else 0.0,
        "Weight": fwd_count * bwd_count,
    }

    result = {col: row.get(col, 0.0) for col in FEATURE_COLUMNS}
    result["Src IP"] = src_ip
    return result


class LiveExtractor:
    def __init__(self, out_dir: str, window: int, sequence_window_seconds: int = 300):
        self.window = window
        self.sequence_window_seconds = sequence_window_seconds
        self.flows: dict[frozenset, FlowWindow] = {}
        # Per-device (by its own src IP) timestamps of recently completed
        # flow-windows — see _record_and_count_recent_flow() below and the
        # SEQUENCE-AWARENESS section in this module's docstring.
        self.recent_flow_times: dict[str, deque] = defaultdict(deque)
        os.makedirs(out_dir, exist_ok=True)
        self.out_path = os.path.join(out_dir, "live_flows.csv")
        self._init_csv()
        self.row_count = 0

    def _init_csv(self):
        is_new = not os.path.exists(self.out_path)
        self._file = open(self.out_path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=FEATURE_COLUMNS + ["Src IP", "recent_flow_count"])
        if is_new:
            self._writer.writeheader()
            self._file.flush()

    def _record_and_count_recent_flow(self, src_ip: str) -> int:
        """Rolling count of this same device's own completed flow-windows in
        the last `sequence_window_seconds` — see the SEQUENCE-AWARENESS
        section of this module's docstring for what this is (and isn't)."""
        now = time.time()
        dq = self.recent_flow_times[src_ip]
        dq.append(now)
        while dq and now - dq[0] > self.sequence_window_seconds:
            dq.popleft()
        return len(dq)

    def handle_packet(self, pkt):
        if not pkt.haslayer(IP):
            return  # ARP and other non-IP traffic isn't part of an IP flow window
        ip = pkt[IP]
        flow_key = frozenset({ip.src, ip.dst})

        win = self.flows.get(flow_key)
        if win is None:
            win = FlowWindow(first_src_ip=ip.src)
            self.flows[flow_key] = win

        win.add(pkt, time.time())

        if len(win) >= self.window:
            row = compute_features(win, src_ip=win.forward_ip)
            row["recent_flow_count"] = self._record_and_count_recent_flow(win.forward_ip)
            self._writer.writerow(row)
            self._file.flush()  # flow_consumer.py's watchdog needs to see growth immediately
            self.row_count += 1
            print(f"[live_feature_extractor] wrote row #{self.row_count} for flow {tuple(flow_key)} ({self.window} pkts, recent_flow_count={row['recent_flow_count']})")
            del self.flows[flow_key]  # tumbling window — start fresh for this flow

    def close(self):
        self._file.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iface", required=True, help="Interface to sniff on (see scapy.all.get_if_list())")
    parser.add_argument("--out-dir", default="./cicflowmeter_output", help="Folder flow_consumer.py watches")
    parser.add_argument("--window", type=int, default=100, help="Packets per flow window (paper used 10 for light attacks, 100 for volumetric)")
    parser.add_argument("--bpf", default="ip", help="BerkeleyPacketFilter, default 'ip' (skip ARP/non-IP)")
    parser.add_argument("--sequence-window-seconds", type=int, default=300, help="Rolling window for the recent_flow_count sequence-awareness column (see module docstring)")
    args = parser.parse_args()

    print(f"[live_feature_extractor] {len(FEATURE_COLUMNS)} feature columns loaded from {FEATURE_COLS_PATH}")
    print(f"[live_feature_extractor] Sniffing on {args.iface!r}, window={args.window} packets/flow, writing to {args.out_dir}")
    print(f"[live_feature_extractor] recent_flow_count rolling window: {args.sequence_window_seconds}s (not yet scored by the deployed model — see docstring)")
    print("[live_feature_extractor] NOTE: this reconstructs CICIoT2023-schema features from first principles —")
    print("[live_feature_extractor] read the ASSUMPTIONS section in this file's docstring before trusting the numbers.")

    extractor = LiveExtractor(args.out_dir, args.window, args.sequence_window_seconds)
    try:
        sniff(iface=args.iface, filter=args.bpf, prn=extractor.handle_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        extractor.close()


if __name__ == "__main__":
    main()
