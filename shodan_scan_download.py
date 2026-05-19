#!/usr/bin/env python3

import argparse
import gzip
import json
import os
import sys
from shodan import Shodan
from shodan.exception import APIError

# =========================================================
# Load API key from apikey.txt
# =========================================================
API_KEY_FILE = "apikey.txt"

if not os.path.exists(API_KEY_FILE):
    print(f"[!] File {API_KEY_FILE} tidak ditemukan")
    sys.exit(1)

with open(API_KEY_FILE, "r") as f:
    API_KEY = f.read().strip()

if not API_KEY:
    print("[!] API key kosong")
    sys.exit(1)

# =========================================================
# Argument parser
# =========================================================
parser = argparse.ArgumentParser(
    description="Download hasil scan Shodan berdasarkan Scan ID"
)

parser.add_argument(
    "--scan-id",
    required=True,
    help="ID scan Shodan (contoh: R2XRT5HH6X67PFAB)"
)

args = parser.parse_args()

# =========================================================
# Setup API
# =========================================================
api = Shodan(API_KEY)

scan_id = args.scan_id
query = f"scan:{scan_id}"

output_file = f"{scan_id}.json.gz"

print(f"[+] Mengambil hasil scan: {scan_id}")
print(f"[+] Output file: {output_file}")

count = 0

try:
    with gzip.open(output_file, "wt", encoding="utf-8") as gzfile:

        # otomatis paging semua hasil
        for banner in api.search_cursor(query):
            gzfile.write(json.dumps(banner) + "\n")
            count += 1

            if count % 100 == 0:
                print(f"[+] Downloaded {count} results...")

    print(f"[+] Selesai")
    print(f"[+] Total results: {count}")
    print(f"[+] Saved: {output_file}")

except APIError as e:
    print(f"[!] Shodan API Error: {e}")
    sys.exit(1)

except KeyboardInterrupt:
    print("\n[!] Dibatalkan user")
    sys.exit(1)
