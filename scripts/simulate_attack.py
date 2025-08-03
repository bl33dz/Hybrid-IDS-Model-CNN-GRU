import pandas as pd
import requests
import time
import random

TARGET_HOST = "http://localhost:8080"
DELAY = 1
TOTAL_LIMIT = None

malicious_df = pd.read_csv("../data/sqlmap_uri_100.csv")
benign_df = pd.read_csv("../data/benign_uri_100.csv")

data = pd.concat([malicious_df, benign_df], ignore_index=True)
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

headers = {
    "User-Agent": "curl/8.14.1",
    "Accept": "*/*"
}

print(f"[INFO] Sending {len(data)} requests to {TARGET_HOST}")
for i, row in data.iterrows():
    uri = row["query"]
    full_url = f"{TARGET_HOST}{uri}"

    try:
        res = requests.get(full_url, headers=headers, timeout=2, allow_redirects=False)

        print(f"[{row['label']}] {uri} -> {res.status_code}")
    except Exception as e:
        print(f"[ERROR] Failed: {full_url} — {e}")

    time.sleep(DELAY)
    if TOTAL_LIMIT and i + 1 >= TOTAL_LIMIT:
        break

print("[INFO] Simulation done.")

