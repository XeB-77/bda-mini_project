#!/usr/bin/env python3
"""
Standalone live HTTP traffic monitor using Scapy.

This is a REAL, live packet-capture script — it genuinely sniffs traffic
on a network interface. It is NOT wired into the rest of this project's
pipeline: it does not read from or write to output/, it is not called by
run_all.py, and the Streamlit dashboard does not display anything from it.
Treat it as a separate, standalone demo of live monitoring, distinct from
the historical NASA-log analysis the rest of the project performs.

Limitations, stated plainly:
  - It only inspects plain, unencrypted HTTP on port 80. It cannot see
    HTTPS traffic (virtually everything today), so on a modern network it
    will typically see little or nothing.
  - It requires permission to capture packets: run as root, or grant the
    interpreter CAP_NET_RAW/CAP_NET_ADMIN (e.g. via `setcap`, or run with
    `sudo`). Without one of those, packet capture will fail immediately.
  - The "baseline" limits below are a rough heuristic derived from the
    static NASA dataset, not a statistically validated threshold.

Usage:
    python network_monitor.py [interface]
"""

import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, Raw
except ImportError:
    print(
        "scapy is not installed. Install it with "
        "`pip install scapy` to use this script."
    )
    sys.exit(1)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "ingested"
WINDOW = 60

# Baseline log line pattern: first whitespace-delimited token is the client
# (a dotted IP OR a hostname — the original version only matched numeric
# IPs, which silently ignored the majority of this dataset's rows, since
# most NASA-log clients are named hosts like "pipe6.nyc.pipeline.com").
BASELINE_PATTERN = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "[^"]*" (\d+) ')


def get_limits(data_dir=DATA_DIR):
    """
    Derive rough per-minute request/error baselines from the ingested NASA
    logs, purely to give the live monitor a starting threshold. This is a
    coarse heuristic, not a statistically fitted baseline.
    """
    requests = 0
    errors = 0

    if not data_dir.exists():
        print(
            f"[warn] {data_dir} not found — using default baseline limits."
        )
        return 10, 5

    for file in data_dir.rglob("*"):
        if not file.is_file():
            continue

        with file.open(errors="ignore") as f:
            for line in f:
                match = BASELINE_PATTERN.match(line)
                if not match:
                    continue

                _, status = match.groups()
                requests += 1
                if status == "404":
                    errors += 1

    request_limit = max(10, requests // 1000)
    error_limit = max(5, errors // 1000)

    return request_limit, error_limit


def clean_old(data, ip, now, window=WINDOW):
    while data[ip] and (now - data[ip][0]).total_seconds() > window:
        data[ip].popleft()


def make_packet_handler(request_limit, error_limit):
    requests = defaultdict(deque)
    errors = defaultdict(deque)

    def packet(pkt):
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            return

        try:
            data = bytes(pkt[Raw].load)
        except Exception:
            return

        now = datetime.now()

        # HTTP request
        if pkt[TCP].dport == 80:
            if re.match(rb"^(GET|POST|PUT|DELETE|HEAD) ", data):
                ip = pkt[IP].src
                requests[ip].append(now)
                clean_old(requests, ip, now)

                if len(requests[ip]) > request_limit:
                    print(
                        f"ALERT | {ip} | High request rate | "
                        f"{len(requests[ip])} requests/{WINDOW}s"
                    )

        # HTTP 404 response
        if pkt[TCP].sport == 80:
            if data.startswith(b"HTTP/") and b" 404 " in data[:20]:
                ip = pkt[IP].dst
                errors[ip].append(now)
                clean_old(errors, ip, now)

                if len(errors[ip]) > error_limit:
                    print(
                        f"ALERT | {ip} | High 404 rate | "
                        f"{len(errors[ip])} errors/{WINDOW}s"
                    )

    return packet


def main():
    interface = sys.argv[1] if len(sys.argv) > 1 else None

    print("Deriving baseline limits from the ingested NASA logs...")
    request_limit, error_limit = get_limits()

    print("NASA baseline loaded")
    print(f"Request limit : {request_limit}/{WINDOW}s")
    print(f"404 limit     : {error_limit}/{WINDOW}s")
    print(
        "Note: this monitor only sees plain HTTP (port 80). It cannot "
        "decode HTTPS traffic."
    )
    print("Monitoring HTTP traffic...")
    print("Press Ctrl+C to stop\n")

    handler = make_packet_handler(request_limit, error_limit)

    try:
        sniff(
            iface=interface,
            filter="tcp port 80",
            prn=handler,
            store=False,
        )
    except PermissionError:
        print(
            "\n[error] Permission denied opening the network interface.\n"
            "Packet capture needs elevated privileges. Try:\n"
            "  sudo python network_monitor.py\n"
            "or grant capture capability to the interpreter, e.g.:\n"
            "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
        )
        sys.exit(1)
    except OSError as exc:
        print(f"\n[error] Could not start packet capture: {exc}")
        if interface is None:
            print(
                "If this is an interface-selection problem, list interfaces "
                "with `ip link` (Linux) and rerun as:\n"
                "  python network_monitor.py <interface_name>"
            )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
