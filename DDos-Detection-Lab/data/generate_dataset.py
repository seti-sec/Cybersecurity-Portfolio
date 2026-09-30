import pandas as pd


# ==========================================
# Configuration
# ==========================================

DATA_FILE = "data/synthetic_network_logs.csv"

TARGET_IP = "10.10.10.50"
TARGET_PORT = 443


# ==========================================
# Load dataset
# ==========================================

df = pd.read_csv(DATA_FILE)

df["timestamp"] = pd.to_datetime(df["timestamp"])


# ==========================================
# Filter normal traffic
# ==========================================

normal = df[df["scenario"] == "NORMAL"].copy()


# ==========================================
# Baseline metrics
# ==========================================

total_requests = normal["request_count"].sum()

unique_sources = normal["src_ip"].nunique()

total_bytes = normal["bytes"].sum()

total_packets = normal["packets"].sum()

five_xx = normal[
    normal["status_code"].between(500, 599)
]

five_xx_rate = (
    len(five_xx) / len(normal) * 100
    if len(normal) > 0
    else 0
)

duration_seconds = (
    normal["timestamp"].max()
    - normal["timestamp"].min()
).total_seconds()

requests_per_second = (
    total_requests / duration_seconds
    if duration_seconds > 0
    else 0
)


# ==========================================
# Target analysis
# ==========================================

target_traffic = normal[
    (normal["dst_ip"] == TARGET_IP)
    & (normal["dst_port"] == TARGET_PORT)
]


target_ratio = (
    len(target_traffic) / len(normal) * 100
    if len(normal) > 0
    else 0
)


# ==========================================
# Print results
# ==========================================

print("=" * 60)
print("DDoS Detection Lab - Baseline Traffic Analysis")
print("=" * 60)

print("\nDataset:")
print(f"Total records       : {len(normal):,}")

print("\nTraffic metrics:")
print(f"Total requests     : {total_requests:,}")
print(f"Requests/sec       : {requests_per_second:.2f}")
print(f"Unique source IPs  : {unique_sources}")
print(f"Total bytes        : {total_bytes:,}")
print(f"Total packets      : {total_packets:,}")

print("\nHTTP errors:")
print(f"5xx rate           : {five_xx_rate:.2f}%")

print("\nTarget analysis:")
print(f"Target             : {TARGET_IP}:{TARGET_PORT}")
print(f"Target traffic     : {target_ratio:.2f}%")

print("\nBaseline analysis completed.")
