#!/usr/bin/env python3
"""
shodan_scan.py
- Baca daftar IP/CIDR dari listip.txt
- Baca API key dari apikey.txt
- Submit scan request ke Shodan

Usage:
  python3 shodan_scan.py --ips ip.txt --apikey apikey.txt
"""

import os
import argparse
from shodan import Shodan
from shodan.exception import APIError

def read_api_key(path="apikey.txt"):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None

def read_ips(path="ip.txt"):
    ips = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
    return ips

def main():
    ap = argparse.ArgumentParser(description="Submit Shodan scan jobs from file")
    ap.add_argument("--ips", default="listip.txt", help="File berisi IP/CIDR (tiap baris)")
    ap.add_argument("--apikey", default="apikey.txt", help="File berisi Shodan API key")
    args = ap.parse_args()

    api_key = read_api_key(args.apikey)
    if not api_key:
        raise SystemExit("API key tidak ditemukan (apikey.txt).")

    targets = read_ips(args.ips)
    if not targets:
        raise SystemExit("File IP kosong atau tidak ditemukan.")

    api = Shodan(api_key)

    try:
        print(f"[INFO] Submit scan untuk {len(targets)} target...")
        scan = api.scan(targets)
        print("[DONE] Scan request terkirim.")
        print("Job ID:", scan.get("id"))
        print("Status:", scan.get("status"))
    except APIError as e:
        print(f"[ERROR] Gagal submit scan: {e}")

if __name__ == "__main__":
    main()
