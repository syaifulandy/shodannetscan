#!/usr/bin/env python3
import os, csv, time, argparse
from collections import defaultdict
from shodan import Shodan
from shodan.exception import APIError

def read_api_key(path="apikey.txt"):
    return open(path, "r", encoding="utf-8").read().strip() if os.path.exists(path) else None

def read_cidrs(path):
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

def join_list(x):
    if not x: return ""
    if isinstance(x, list): return ";".join(str(i) for i in x)
    return str(x)

def get(d, *path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def severity_from_cvss(score):
    if score is None: return ""
    try:
        s = float(score)
    except Exception:
        return ""
    if s >= 9.0: return "Critical"
    if s >= 7.0: return "High"
    if s >= 4.0: return "Medium"
    if s > 0:    return "Low"
    return ""

def make_asset_id(ip, port, transport):
    return f"{ip}:{port}/{transport or 'tcp'}"

def flatten_asset(m, cidr):
    loc = m.get("location") or {}
    http_title   = get(m, "http", "title") or get(m, "http2", "title")
    http_server  = get(m, "http", "server") or get(m, "http2", "server")
    http_host    = get(m, "http", "host")
    favicon_mmh3 = get(m, "http", "favicon", "mmh3")

    return {
        "cidr": cidr,
        "ip_str": m.get("ip_str"),
        "port": m.get("port"),
        "transport": m.get("transport"),
        "asset_id": make_asset_id(m.get("ip_str"), m.get("port"), m.get("transport")),
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
        "http.title": http_title,
        "http.server": http_server,
        "http.host_header": http_host,
        "http.favicon_mmh3": favicon_mmh3,
        "ssl.subject.CN": get(m, "ssl", "cert", "subject", "CN"),
        "ssl.issuer.CN": get(m, "ssl", "cert", "issuer", "CN"),
        "ssl.SAN": join_list(get(m, "ssl", "cert", "alt") or get(m, "ssl", "cert", "subjectAltName")),
        "shodan.module": get(m, "_shodan", "module"),
        "tags": join_list(m.get("tags") or []),
        "cpe": join_list(m.get("cpe") or []),
        # Ringkasan vuln (akan diisi kemudian)
        "vuln_count_total": 0,
        "vuln_count_critical": 0,
        "vuln_count_high": 0,
        "vuln_count_medium": 0,
        "vuln_count_low": 0,
        "max_cvss": "",
        "worst_severity": "",
        "cves_concat": "",
        "max_epss": "",
        "max_ranking_epss": "",
    }

def fetch_all(api, query):
    rows = []
    backoff = 5
    while True:
        try:
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

def write_csv(path, rows, header=None):
    if not rows:
        print(f"[INFO] tidak ada hasil untuk {path}.")
        return
    # Header: pakai urutan yang diberikan jika ada; sisanya append
    if header:
        keys = list(header)
        seen = set(keys)
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    keys.append(k); seen.add(k)
    else:
        keys, seen = [], set()
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    keys.append(k); seen.add(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Shodan CIDR scraper -> assets.csv & vulns.csv (dengan CVSS/EPSS)")
    ap.add_argument("--cidrs", required=True, help="File berisi list CIDR")
    ap.add_argument("--assets", default="assets.csv", help="Output assets CSV")
    ap.add_argument("--vulns", default="vulns.csv", help="Output vulns CSV")
    ap.add_argument("--extra", default="", help="Filter tambahan (mis. 'http port:80')")
    ap.add_argument("--apikey", default="apikey.txt", help="File API key Shodan (default apikey.txt)")
    ap.add_argument("--peek", action="store_true", help="Tampilkan perkiraan total hits (butuh 1 credit ekstra)")
    args = ap.parse_args()

    api_key = read_api_key(args.apikey) or os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("API key tidak ditemukan (apikey.txt / env).")

    api = Shodan(api_key)
    cidrs = read_cidrs(args.cidrs)

    # Kolektor
    assets_map = {}                       # asset_id -> asset_row
    vuln_rows = []                        # list of vuln rows (asset_id + CVE)
    seen_asset_cve = set()                # dedup (asset_id, cve)

    for cidr in cidrs:
        base_q = f"net:{cidr}"
        query = f"({base_q}) ({args.extra})" if args.extra else base_q
        print(f"[INFO] querying: {query}")

        if args.peek:
            try:
                peek = api.search(query, page=1, minify=True)
                print(f"[INFO] {cidr}: total (approx) = {peek.get('total', 0)}")
            except APIError as e:
                print(f"[WARN] gagal ambil total {cidr}: {e}")

        matches = fetch_all(api, query)
        print(f"[INFO] {cidr}: didapat {len(matches)} matches")

        for m in matches:
            asset = flatten_asset(m, cidr)
            aid = asset["asset_id"]
            # simpan/merge asset
            if aid not in assets_map:
                assets_map[aid] = asset

            # proses vulns
            vulns = m.get("vulns") or {}
            # struktur bisa dict {CVE: meta} atau list of CVE
            if isinstance(vulns, dict):
                iterable = vulns.items()
            elif isinstance(vulns, list):
                iterable = [(cve, {}) for cve in vulns]
            else:
                iterable = []

            max_cvss = assets_map[aid]["max_cvss"] or None
            max_epss = assets_map[aid]["max_epss"] or None
            max_rank_epss = assets_map[aid]["max_ranking_epss"] or None
            cvelist = set(assets_map[aid]["cves_concat"].split(";")) if assets_map[aid]["cves_concat"] else set()

            for cve, meta in iterable:
                # ambil data yang kamu minta
                cvss = meta.get("cvss")
                epss = meta.get("epss")
                ranking_epss = meta.get("ranking_epss")
                cvss_version = meta.get("cvss_version")
                verified = meta.get("verified")
                summary = meta.get("summary")
                references = meta.get("references")

                sev = severity_from_cvss(cvss)

                key = (aid, cve)
                if key not in seen_asset_cve:
                    vuln_rows.append({
                        "asset_id": aid,
                        "ip_str": asset["ip_str"],
                        "port": asset["port"],
                        "transport": asset["transport"],
                        "cve": cve,
                        "cvss": cvss,
                        "severity": sev,
                        "cvss_version": cvss_version,
                        "epss": epss,
                        "ranking_epss": ranking_epss,
                        "verified": verified,
                        "summary": summary,
                        "references": join_list(references),
                        "timestamp": asset["timestamp"],
                    })
                    seen_asset_cve.add(key)

                    # update ringkasan di asset
                    assets_map[aid]["vuln_count_total"] += 1
                    if sev == "Critical": assets_map[aid]["vuln_count_critical"] += 1
                    elif sev == "High":   assets_map[aid]["vuln_count_high"] += 1
                    elif sev == "Medium": assets_map[aid]["vuln_count_medium"] += 1
                    elif sev == "Low":    assets_map[aid]["vuln_count_low"] += 1

                    # max cvss / epss / ranking_epss
                    try:
                        if cvss is not None:
                            max_cvss = max(float(max_cvss) if max_cvss not in ("", None) else 0.0, float(cvss))
                    except Exception:
                        pass
                    try:
                        if epss is not None:
                            max_epss = max(float(max_epss) if max_epss not in ("", None) else 0.0, float(epss))
                    except Exception:
                        pass
                    try:
                        if ranking_epss is not None:
                            max_rank_epss = max(float(max_rank_epss) if max_rank_epss not in ("", None) else 0.0, float(ranking_epss))
                    except Exception:
                        pass

                    cvelist.add(cve)

            # tulis balik ringkasan
            if max_cvss is not None: assets_map[aid]["max_cvss"] = max_cvss
            if max_epss is not None: assets_map[aid]["max_epss"] = max_epss
            if max_rank_epss is not None: assets_map[aid]["max_ranking_epss"] = max_rank_epss
            # worst severity dari urutan prioritas
            for level in ["Critical", "High", "Medium", "Low"]:
                if assets_map[aid][f"vuln_count_{level.lower()}"] > 0:
                    assets_map[aid]["worst_severity"] = level
                    break
            assets_map[aid]["cves_concat"] = ";".join(sorted(cvelist))

        time.sleep(1)

    # output
    assets_rows = list(assets_map.values())
    assets_header = [
        "asset_id","ip_str","port","transport","cidr","product","version",
        "org","isp","asn","os","hostnames","domains",
        "country","city","latitude","longitude","timestamp",
        "http.title","http.server","http.host_header","http.favicon_mmh3",
        "ssl.subject.CN","ssl.issuer.CN","ssl.SAN",
        "shodan.module","tags","cpe",
        "vuln_count_total","vuln_count_critical","vuln_count_high","vuln_count_medium","vuln_count_low",
        "max_cvss","worst_severity","cves_concat","max_epss","max_ranking_epss",
    ]
    write_csv(args.assets, assets_rows, header=assets_header)

    vulns_header = [
        "asset_id","ip_str","port","transport","cve","cvss","severity","cvss_version",
        "epss","ranking_epss","verified","summary","references","timestamp"
    ]
    write_csv(args.vulns, vuln_rows, header=vulns_header)

    print(f"[DONE] assets -> {args.assets} (rows: {len(assets_rows)})")
    print(f"[DONE] vulns  -> {args.vulns} (rows: {len(vuln_rows)})")

if __name__ == "__main__":
    main()
