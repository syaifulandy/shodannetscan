#!/usr/bin/env python3
"""
shodan_cidr_scrape_enriched.py
- Baca cidrs.txt (tiap baris = CIDR)
- Query Shodan per CIDR: net:<CIDR>
- Stream semua hasil (search_cursor) -> 1 search credit per CIDR
- Enrich output: http.title, http.server, http.host, favicon mmh3,
  SSL subject CN, issuer CN, SAN, hostnames/domains, product, dsb.
- Output CSV: shodan_results.csv (default)

Usage:
  python3 shodan_cidr_scrape_enriched.py --cidrs cidrs.txt --out hasil.csv
Opsional:
  python3 shodan_cidr_scrape_enriched.py --cidrs cidrs.txt --out hasil.csv --extra 'port:80 http'
  python3 shodan_cidr_scrape_enriched.py --cidrs cidrs.txt --apikey mykey.txt
"""

import os, csv, time, argparse
from shodan import Shodan
from shodan.exception import APIError

def read_api_key(path="apikey.txt"):
    return open(path, "r", encoding="utf-8").read().strip() if os.path.exists(path) else None

def read_cidrs(path):
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

def join_list(x):
    if not x: return ""
    if isinstance(x, list): return ",".join(str(i) for i in x)
    return str(x)

def get(d, *path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def flatten(m, cidr):
    # HTTP fields
    http_title   = get(m, "http", "title")
    http_server  = get(m, "http", "server")
    http_host    = get(m, "http", "host")
    http2_title  = get(m, "http2", "title")   # kadang response ada di http2
    http2_server = get(m, "http2", "server")
    favicon_mmh3 = get(m, "http", "favicon", "mmh3")
    # SSL fields
    ssl_subj_cn  = get(m, "ssl", "cert", "subject", "CN")
    ssl_issuer   = get(m, "ssl", "cert", "issuer", "CN")
    ssl_altnames = get(m, "ssl", "cert", "alt") or get(m, "ssl", "cert", "subjectAltName")
    # Location
    loc = m.get("location") or {}
    # CPE / tags
    cpes = m.get("cpe") or []
    tags = m.get("tags") or []

    return {
        "cidr": cidr,
        "ip_str": m.get("ip_str"),
        "port": m.get("port"),
        "transport": m.get("transport"),
        "product": m.get("product"),
        "version": m.get("version"),
        "org": m.get("org"),
        "isp": m.get("isp"),
        "asn": m.get("asn"),
        "os": m.get("os"),
        "hostnames": join_list(m.get("hostnames")),
        "domains": join_list(m.get("domains")),
        "country": loc.get("country_name"),
        "city": loc.get("city"),
        "latitude": loc.get("latitude"),
        "longitude": loc.get("longitude"),
        "timestamp": m.get("timestamp"),

        # Web-like fields:
        "http.title": http_title or http2_title,
        "http.server": http_server or http2_server,
        "http.host_header": http_host,
        "http.favicon_mmh3": favicon_mmh3,

        # SSL info:
        "ssl.subject.CN": ssl_subj_cn,
        "ssl.issuer.CN": ssl_issuer,
        "ssl.SAN": join_list(ssl_altnames),

        # Extras:
        "shodan.module": get(m, "_shodan", "module"),
        "vulns": ",".join(sorted(m.get("vulns", {}).keys())) if isinstance(m.get("vulns"), dict) else "",
        "tags": join_list(tags),
        "cpe": join_list(cpes),
    }

def fetch_all(api, query):
    rows = []
    backoff = 5
    while True:
        try:
            # search_cursor -> minify=False secara implisit; stream semua hasil
            for m in api.search_cursor(query):
                rows.append(m)
            break
        except APIError as e:
            msg = str(e).lower()
            if any(k in msg for k in ["rate limit", "too many requests", "exceeded", "bandwidth"]):
                wait = min(backoff, 60)
                print(f"[WARN] rate-limited. tidur {wait}s...")
                time.sleep(wait)
                backoff = min(backoff * 2, 120)
                continue
            elif "invalid search query" in msg or "no information available" in msg:
                print(f"[WARN] query invalid/kosong: {e}")
                break
            else:
                print(f"[ERROR] {e}")
                break
    return rows

def write_csv(path, rows):
    if not rows:
        print("[INFO] tidak ada hasil untuk ditulis.")
        return
    # kumpulkan semua kunci agar header lengkap
    keys = []
    seen = set()
    for r in rows:
        for k in r.keys():
            if k not in seen:
                keys.append(k)
                seen.add(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)

def main():
    ap = argparse.ArgumentParser(description="Shodan CIDR scraper (enriched)")
    ap.add_argument("--cidrs", required=True, help="File berisi list CIDR (tiap baris)")
    ap.add_argument("--out", default="shodan_results.csv", help="Output CSV")
    ap.add_argument("--extra", default="", help="Filter tambahan (mis. 'http port:80' atau 'product:\"OpenShift\"')")
    ap.add_argument("--apikey", default="apikey.txt", help="File API key Shodan (default apikey.txt)")
    ap.add_argument("--peek", action="store_true", help="Tampilkan perkiraan total hits (butuh 1 credit ekstra)")
    args = ap.parse_args()

    api_key = read_api_key(args.apikey) or os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("API key tidak ditemukan (apikey.txt / env SHODAN_API_KEY).")

    api = Shodan(api_key)
    cidrs = read_cidrs(args.cidrs)

    all_rows = []
    for cidr in cidrs:
        base_q = f"net:{cidr}"
        query = f"({base_q}) ({args.extra})" if args.extra else base_q
        print(f"[INFO] querying: {query}")

        # Hanya lakukan "peek" kalau user pakai --peek
        if args.peek:
            try:
                peek = api.search(query, page=1, minify=True)
                print(f"[INFO] {cidr}: total (approx) = {peek.get('total', 0)}")
            except APIError as e:
                print(f"[WARN] gagal ambil total {cidr}: {e}")

        matches = fetch_all(api, query)
        flat = [flatten(m, cidr) for m in matches]
        print(f"[INFO] {cidr}: didapat {len(flat)} items")
        all_rows.extend(flat)
        time.sleep(1)

    write_csv(args.out, all_rows)
    print(f"[DONE] total {len(all_rows)} baris -> {args.out}")

if __name__ == "__main__":
    main()

