import csv
import json
import random
import os

# ---------------- CONFIG ----------------

INPUT_CSV = "dvwa_benign_200k.csv"   # change if needed
OUTPUT_JSON = "train.json"
TARGET_SAMPLES = 20_000
RANDOM_SEED = 42

random.seed(RANDOM_SEED)

# ---------------- SAFETY CHECK ----------------

if not os.path.exists(INPUT_CSV):
    raise FileNotFoundError(f"CSV file not found: {INPUT_CSV}")

# ---------------- STEP 1: LOAD + FILTER BENIGN ----------------

benign_rows = []
skipped_rows = 0

with open(INPUT_CSV, newline="", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)

    for row in reader:
        category = row.get("category")

        # Skip rows with missing / empty category
        if not category:
            skipped_rows += 1
            continue

        if category.strip().lower() == "benign":
            benign_rows.append(row)

print(f"Total benign rows found: {len(benign_rows)}")
print(f"Rows skipped due to missing category: {skipped_rows}")

if len(benign_rows) < TARGET_SAMPLES:
    raise ValueError(
        f"Not enough benign samples ({len(benign_rows)}) "
        f"to sample {TARGET_SAMPLES}"
    )

# ---------------- STEP 2: RANDOM SAMPLE ----------------

sampled_rows = random.sample(benign_rows, TARGET_SAMPLES)

# ---------------- STEP 3: FORMAT FOR RECONSTRUCTION ----------------

def safe(val, default="None"):
    if val is None:
        return default
    val = str(val).strip()
    return val if val else default

def extract_headers(headers_str):
    if not headers_str:
        return "None"
    keep = ["User-Agent", "Referer", "Origin", "Cookie", "Content-Type"]
    found = [k for k in keep if k in headers_str]
    return ", ".join(found) if found else "None"

dataset = []

for row in sampled_rows:
    request_text = f"""
[CORE]
Method: {safe(row.get('method'))}
Path: {safe(row.get('path'))}
Protocol: {safe(row.get('protocol'))}

[STATE]
Status: {safe(row.get('status'))}

[CONTEXT]
Headers: {extract_headers(row.get('headers'))}
Body: {safe(row.get('request_body'))}
""".strip()

    dataset.append({
        "instruction": "Reconstruct the following benign HTTP request exactly.",
        "input": request_text,
        "output": request_text
    })

# ---------------- STEP 4: SAVE ----------------

with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(dataset, f, indent=2)

print(f"Successfully saved {len(dataset)} samples to {OUTPUT_JSON}")
