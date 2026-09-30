import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

output = Path("data/synthetic_network_logs.csv")

destination_ip = "10.10.10.50"
destination_port = 443

normal_ips = [f"192.168.1.{i}" for i in range(10, 61)]
attacker_ips = [f"203.0.113.{i}" for i in range(1, 151)]

rows = []

start = datetime(2026, 9, 30, 10, 0, 0)

# NORMAL: 10 minutes
for second in range(600):
    timestamp = start + timedelta(seconds=second)

    rows.append([
        timestamp.isoformat(),
        random.choice(normal_ips),
        random.randint(40000, 50000),
        destination_ip,
        destination_port,
        "TCP",
        random.randint(900, 1600),
        random.randint(8, 15),
        random.randint(1, 3),
        random.choice([200, 200, 200, 304, 404]),
        "NORMAL"
    ])

# DDOS: 3 minutes
for second in range(600, 780):
    timestamp = start + timedelta(seconds=second)

    for _ in range(random.randint(20, 40)):
        rows.append([
            timestamp.isoformat(),
            random.choice(attacker_ips),
            random.randint(40000, 60000),
            destination_ip,
            destination_port,
            "TCP",
            random.randint(500, 900),
            random.randint(5, 10),
            random.randint(20, 50),
            random.choice([503, 503, 502, 429, 200]),
            "DDOS"
        ])

# RECOVERY: 5 minutes
for second in range(780, 1080):
    timestamp = start + timedelta(seconds=second)

    rows.append([
        timestamp.isoformat(),
        random.choice(normal_ips),
        random.randint(40000, 50000),
        destination_ip,
        destination_port,
        "TCP",
        random.randint(800, 1500),
        random.randint(8, 14),
        random.randint(1, 4),
        random.choice([200, 200, 200, 304, 503]),
        "RECOVERY"
    ])

output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "bytes",
        "packets",
        "request_count",
        "status_code",
        "scenario"
    ])

    writer.writerows(rows)

print(f"Created: {output}")
print(f"Records: {len(rows)}")
