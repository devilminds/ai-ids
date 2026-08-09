"""
Live packet capture and flow aggregation.

This is real, runnable Scapy code — but it needs things a sandboxed chat
environment doesn't have: root/administrator privileges, a real NIC, and
libpcap/npcap installed. Run it on your own machine (or a VM) with:

    sudo python3 -m app.packet_capture.sniffer --iface eth0

It groups packets into flows by (src_ip, dst_ip, src_port, dst_port, protocol),
and every FLUSH_INTERVAL seconds sends each flow's aggregated stats to the
running API's /api/predict endpoint — the same pipeline /api/simulate uses,
just fed by real traffic instead of synthetic data.
"""
import argparse
import time
import threading
from collections import defaultdict

import requests
from scapy.all import sniff, IP, TCP, UDP

FLUSH_INTERVAL = 5  # seconds
API_BASE = "https://ai-ids-backend-0z72.onrender.com"

_flows = defaultdict(lambda: {"packet_count": 0, "total_bytes": 0, "start": None, "end": None})
_lock = threading.Lock()


def _flow_key(pkt):
    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
    sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
    dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
    return (pkt[IP].src, pkt[IP].dst, sport, dport, proto)


def _on_packet(pkt):
    if not pkt.haslayer(IP):
        return
    key = _flow_key(pkt)
    now = time.time()
    with _lock:
        flow = _flows[key]
        flow["packet_count"] += 1
        flow["total_bytes"] += len(pkt)
        flow["start"] = flow["start"] or now
        flow["end"] = now


def _flush_loop(token: str):
    while True:
        time.sleep(FLUSH_INTERVAL)
        with _lock:
            snapshot, _flows_local = dict(_flows), _flows.clear()
        for (src, dst, sport, dport, proto), flow in snapshot.items():
            duration = max(flow["end"] - flow["start"], 0.01)
            payload = {
                "source_ip": src, "dest_ip": dst,
                "source_port": sport, "dest_port": dport, "protocol": proto,
                "packet_count": flow["packet_count"], "total_bytes": flow["total_bytes"],
                "duration": duration,
            }
            try:
                requests.post(
                    f"{API_BASE}/api/predict", json=payload,
                    headers={"Authorization": f"Bearer {token}"}, timeout=3,
                )
            except requests.RequestException as e:
                print(f"[sniffer] failed to submit flow: {e}")


def get_token(username: str, password: str) -> str:
    res = requests.post(f"{API_BASE}/api/auth/login", json={"username": username, "password": password})
    res.raise_for_status()
    return res.json()["access_token"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live packet capture for AI-IDS")
    parser.add_argument("--iface", default=None, help="Network interface (default: scapy auto-detect)")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="Admin@12345")
    args = parser.parse_args()

    print("Authenticating with the API...")
    tok = get_token(args.username, args.password)

    print(f"Starting capture loop (flushing every {FLUSH_INTERVAL}s)... requires root/admin.")
    threading.Thread(target=_flush_loop, args=(tok,), daemon=True).start()
    sniff(iface=args.iface, prn=_on_packet, store=False)
