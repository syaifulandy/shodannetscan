#!/usr/bin/env python3

import argparse
import os
import sys
from shodan import Shodan
from shodan.exception import APIError

# =========================================================
# Load API Key
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
# Argument Parser
# =========================================================
parser = argparse.ArgumentParser(
    description="Check progress/status scan Shodan"
)

parser.add_argument(
    "--scan-id",
    required=True,
    help="ID scan Shodan"
)

args = parser.parse_args()

scan_id = args.scan_id

# =========================================================
# Init API
# =========================================================
api = Shodan(API_KEY)

try:
    status = api.scan_status(scan_id)

    print("=" * 50)
    print(f"SCAN ID : {scan_id}")
    print(f"STATUS  : {status.get('status')}")
    print(f"COUNT   : {status.get('count')}")
    print("=" * 50)

    # status tambahan
    if status.get("status") == "DONE":
        print("[+] Scan selesai")

    elif status.get("status") == "PROCESSING":
        print("[*] Scan masih berjalan")

    elif status.get("status") == "QUEUE":
        print("[*] Scan masih dalam antrean")

    else:
        print("[*] Status tidak diketahui")

except APIError as e:
    print(f"[!] Shodan API Error: {e}")
    sys.exit(1)

except KeyboardInterrupt:
    print("\n[!] Dibatalkan user")
    sys.exit(1)
