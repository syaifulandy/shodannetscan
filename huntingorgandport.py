#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import time
import csv
from typing import List

from shodan import Shodan
from shodan.client import APIError


def load_list(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [x.strip() for x in f if x.strip() and not x.startswith("#")]
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {path}", file=sys.stderr)
        sys.exit(1)


def load_apikey(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if not key:
                raise ValueError("API key kosong")
            return key
    except Exception as e:
        print(f"[!] Gagal baca API key: {e}", file=sys.stderr)
        sys.exit(1)


def backoff(attempt: int):
    time.sleep(min(60, 2 ** attempt))


def iter_search(api: Shodan, query: str):
    attempt = 0
    while True:
        try:
            for r in api.search_cursor(query):
                yield r
            return
        except APIError as e:
            attempt += 1
            if attempt > 5:
                print(f"[!] APIError stop: {e}", file=sys.stderr)
                return
            print(f"[!] APIError retry: {e}", file=sys.stderr)
            backoff(attempt)


def main():
    parser = argparse.ArgumentParser(
        description="Shodan scan multi-org & multi-port → CSV output"
    )
    parser.add_argument("-org", default="org.txt", help="File daftar organisasi")
    parser.add_argument("-port", default="port.txt", help="File daftar port")
    parser.add_argument("--apikey", default="apikey.txt", help="File API key")
    parser.add_argument("--out", default="shodan_org_port.csv", help="Output CSV file")
    args = parser.parse_args()

    orgs = load_list(args.org)
    ports = load_list(args.port)

    if not orgs or not ports:
        print("[!] org.txt atau port.txt kosong", file=sys.stderr)
        sys.exit(1)

    api = Shodan(load_apikey(args.apikey))

    port_query = "port:" + ",".join(ports)
    org_query = "org:" + ",".join([f'"{o}"' for o in orgs])
    query = f"{port_query} {org_query}"

    print(f"[+] Query digunakan:\n{query}\n")

    with open(args.out, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "ip",
            "port",
            "org",
            "asn",
            "country",
            "city",
            "product",
            "version",
            "timestamp",
            "shodan_url",
        ])

        total = 0
        for m in iter_search(api, query):
            ip = m.get("ip_str")
            loc = m.get("location") or {}

            writer.writerow([
                ip,
                m.get("port"),
                m.get("org"),
                m.get("asn"),
                loc.get("country_name"),
                loc.get("city"),
                m.get("product"),
                m.get("version"),
                m.get("timestamp"),
                f"https://www.shodan.io/host/{ip}" if ip else None,
            ])
            total += 1

    print(f"[OK] Total services : {total}")
    print(f"[OK] Output CSV    : {args.out}")


if __name__ == "__main__":
    main()
