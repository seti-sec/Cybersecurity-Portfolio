import pandas as pd

# Load dataset
df = pd.read_csv("../data/synthetic_network_logs.csv")

# Basic dataset information
print("Total logs:", len(df))
print("\nColumns:")
print(df.columns.tolist())

print("\nTraffic labels:")
print(df["label"].value_counts())

print("\nFirst 5 records:")
print(df.head())
