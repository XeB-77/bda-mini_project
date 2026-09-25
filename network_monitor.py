#!/usr/bin/env python3

import re
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime

from scapy.all import sniff, IP, TCP, Raw


DATA = "data/ingested"
WINDOW = 60


# Get simple limits from the NASA logs
def get_limits():
    requests = []
    errors = []

    for file in Path(DATA).rglob("*"):
        if not file.is_file():
            continue

        for line in file.open(errors="ignore"):
            match = re.search(
                r'(\d+\.\d+\.\d+\.\d+).*"[^"]*" (\d+) ',
                line
            )

            if not match:
                continue

            ip, status = match.groups()

            if status == "404":
                errors.append(ip)

            requests.append(ip)

    request_limit = max(10, len(requests) // 1000)
    error_limit = max(5, len(errors) // 1000)

    return request_limit, error_limit


REQUEST_LIMIT, ERROR_LIMIT = get_limits()

requests = defaultdict(deque)
errors = defaultdict(deque)


def clean_old(data, ip, now):
    while data[ip] and now - data[ip][0] > WINDOW:
        data[ip].popleft()


def packet(pkt):
    if IP not in pkt or TCP not in pkt or Raw not in pkt:
        return

    data = bytes(pkt[Raw].load)
    now = datetime.now()

    # HTTP request
    if pkt[TCP].dport == 80:
        if re.match(rb"^(GET|POST|PUT|DELETE|HEAD) ", data):
            ip = pkt[IP].src
            requests[ip].append(now)
            clean_old(requests, ip, now)

            if len(requests[ip]) > REQUEST_LIMIT:
                print(
                    f"ALERT | {ip} | High request rate | "
                    f"{len(requests[ip])} requests"
                )

    # HTTP 404 response
    if pkt[TCP].sport == 80:
        if data.startswith(b"HTTP/") and b" 404 " in data[:20]:
            ip = pkt[IP].dst
            errors[ip].append(now)
            clean_old(errors, ip, now)

            if len(errors[ip]) > ERROR_LIMIT:
                print(
                    f"ALERT | {ip} | High 404 rate | "
                    f"{len(errors[ip])} errors"
                )


print("NASA baseline loaded")
print(f"Request limit : {REQUEST_LIMIT}/minute")
print(f"404 limit     : {ERROR_LIMIT}/minute")
print("Monitoring HTTP traffic...")
print("Press Ctrl+C to stop\n")

sniff(
    filter="tcp port 80",
    prn=packet,
    store=False
)