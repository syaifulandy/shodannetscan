#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shodan_ip_lookup_shodan_only.py
- Input  : listip.txt (satu IP per baris, komentar diawali '#')
- Output : ${OUT_DIR:-Output_shodan_ips}/
    - summary_per_ip.csv
    - details_per_port_cve.csv
    - raw_json/<IP>.json

API Key:
- 1) file apikey.txt (baris pertama), atau
- 2) env SHODAN_API_KEY

Catatan:
- HANYA pakai data dari Shodan (host().vulns + banner.vulns).
- Serial + rate limit default 1.1s/req agar aman (ubah via env RATE_LIMIT_SEC).
"""

import csv
import json
import os
import sys
import time
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional

try:
    import shodan
except ImportError:
    print("Module 'shodan' belum terpasang. Jalankan: pip install shodan")
    sys.exit(1)

# ===== Konfigurasi =====
OUT_DIR = Path(os.getenv("OUT_DIR", "Output_shodan_ips"))
RAW_DIR = OUT_DIR / "raw_json"
SUMMARY_CSV = OUT_DIR / "summary_per_ip.csv"
DETAILS_CSV = OUT_DIR / "details_per_port_cve.csv"

RATE_LIMIT_SEC = float(os.getenv("RATE_LIMIT_SEC", "1.1"))
RETRY_MAX = 3
RETRY_BACKOFF = 2.0

# ===== Util =====
def read_api_key() -> str:
    f = Path("apikey.txt")
    if f.exists():
        key = f.read_text(encoding="utf-8").strip()
        if key:
            return key
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if key:
        return key
    print("ERROR: API key tidak ditemukan. Buat 'apikey.txt' atau set env SHODAN_API_KEY.")
    sys.exit(1)

def load_ips(path="listip.txt") -> List[str]:
    p = Path(path)
    if not p.exists():
        print(f"ERROR: File {path} tidak ditemukan.")
        sys.exit(1)
    ips: List[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            ipaddress.ip_address(s)
            ips.append(s)
        except ValueError:
            print(f"[SKIP] Bukan IP valid: {s}")
    if not ips:
        print("ERROR: Tidak ada IP valid di listip.txt")
        sys.exit(1)
    return ips

def ensure_dirs():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

def human_secs(s: float) -> str:
    m, sec = divmod(int(max(s, 0)), 60)
    h, m = divmod(m, 60)
    if h: return f"{h}h{m:02d}m{sec:02d}s"
    if m: return f"{m}m{sec:02d}s"
    return f"{sec}s"

def g(d: dict, *keys, default=""):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur if cur is not None else default

# ===== Shodan helpers =====
def fetch_host(api: shodan.Shodan, ip: str) -> Optional[dict]:
    for attempt in range(1, RETRY_MAX + 1):
        try:
            return api.host(ip, minify=False)
        except shodan.exception.APIError as e:
            msg = str(e).lower()
            if any(x in msg for x in ["rate limit", "too many requests", "timeout", "gateway", "server error"]):
                sleep_for = RETRY_BACKOFF * attempt
                print(f"[{ip}] Rate-limit/server error, attempt {attempt}/{RETRY_MAX} -> sleep {sleep_for:.1f}s")
                time.sleep(sleep_for)
                continue
            if any(x in msg for x in ["no information available", "not found"]):
                print(f"[{ip}] Tidak ada informasi di Shodan.")
                return None
            print(f"[{ip}] APIError: {e}")
            return None
        except Exception as e:
            sleep_for = RETRY_BACKOFF * attempt
            print(f"[{ip}] ERROR {attempt}/{RETRY_MAX}: {e} -> sleep {sleep_for:.1f}s")
            time.sleep(sleep_for)
    return None

def norm_vuln_meta(meta: dict) -> Dict[str, str]:
    if not isinstance(meta, dict):
        return {"severity": "", "cvss": "", "epss": "", "epss_percentile": ""}
    def pick(*keys, default=""):
        for k in keys:
            if k in meta and meta[k] is not None:
                return meta[k]
        return default
    severity = str(pick("severity", "sev", default="")).lower()
    cvss_val = pick("cvss", "cvss_score", default="")
    try:
        cvss = f"{float(cvss_val):.1f}"
    except:
        cvss = str(cvss_val) if cvss_val else ""
    epss = str(pick("epss", "epssScore", default=""))
    epss_pct = str(pick("epss_percentile", "epssPercentile", "epss_rank", "epssRank", default=""))
    return {"severity": severity, "cvss": cvss, "epss": epss, "epss_percentile": epss_pct}

def merge_meta(a: Dict[str, str], b: Dict[str, str]) -> Dict[str, str]:
    out = {
        "severity": a.get("severity", "") or b.get("severity", ""),
        "cvss": a.get("cvss", "") or b.get("cvss", ""),
        "epss": a.get("epss", "") or b.get("epss", ""),
        "epss_percentile": a.get("epss_percentile", "") or b.get("epss_percentile", "")
    }
    try:
        av = float(a.get("cvss", "")); bv = float(b.get("cvss", ""))
        out["cvss"] = f"{max(av, bv):.1f}"
    except: pass
    try:
        av = float(a.get("epss", "")); bv = float(b.get("epss", ""))
        out["epss"] = f"{max(av, bv):.4f}"
    except: pass
    try:
        av = float(a.get("epss_percentile", "")); bv = float(b.get("epss_percentile", ""))
        out["epss_percentile"] = f"{max(av, bv)}"
    except: pass
    return out

def collect_vulns(host: dict) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    # top-level
    vulns = host.get("vulns") or {}
    if isinstance(vulns, dict):
        for k, meta in vulns.items():
            cve = str(k).upper()
            if cve.startswith("CVE-"):
                out[cve] = norm_vuln_meta(meta if isinstance(meta, dict) else {})
    # banners
    for b in host.get("data", []) or []:
        b_v = b.get("vulns") or {}
        if isinstance(b_v, dict):
            for k, meta in b_v.items():
                cve = str(k).upper()
                if not cve.startswith("CVE-"): continue
                nm = norm_vuln_meta(meta if isinstance(meta, dict) else {})
                out[cve] = merge_meta(out.get(cve, {}), nm) if cve in out else nm
    return out

def extract_country_city(host: dict) -> (str, str):
    country = str(host.get("country_name") or "").strip()
    city = str(host.get("city") or "").strip()
    if country or city: return country, city
    loc = host.get("location") if isinstance(host.get("location"), dict) else {}
    if loc:
        country = str(g(host, "location","country_name","",default="")).strip() or country
        city = str(g(host, "location","city","",default="")).strip() or city
        if country or city: return country, city
    for b in host.get("data", []) or []:
        loc = b.get("location") if isinstance(b.get("location"), dict) else {}
        if loc:
            return str(loc.get("country_name") or ""), str(loc.get("city") or "")
    return "", ""

def write_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows: w.writerow(r)

def summarize_host_row(host: dict, cve_meta: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    ip = host.get("ip_str") or host.get("ip") or ""
    org = host.get("org") or ""
    isp = host.get("isp") or ""
    asn = host.get("asn") or ""
    osname = host.get("os") or ""
    country, city = extract_country_city(host)
    hostnames = ";".join(host.get("hostnames") or [])
    tags = ";".join(host.get("tags") or [])
    last_update = host.get("last_update") or ""
    open_ports = ";".join(str(p) for p in sorted(set(host.get("ports") or [])))

    cves = sorted(cve_meta.keys())
    total_vulns = str(len(cves))

    max_cvss, max_cvss_cve = "", ""
    max_epss, max_epss_cve = "", ""
    try:
        best = max(((float(m["cvss"]), c) for c,m in cve_meta.items() if m.get("cvss")), default=None)
        if best: max_cvss, max_cvss_cve = f"{best[0]:.1f}", best[1]
    except: pass
    try:
        best = max(((float(m["epss"]), c) for c,m in cve_meta.items() if m.get("epss")), default=None)
        if best: max_epss, max_epss_cve = f"{best[0]:.4f}", best[1]
    except: pass

    ranked = []
    for c,m in cve_meta.items():
        try: ranked.append((float(m.get("epss") or 0.0), c))
        except: ranked.append((0.0, c))
    ranked.sort(reverse=True)
    top5_cves_by_epss = ";".join([c for _,c in ranked[:5]])

    return {
        "ip": ip, "org": org, "asn": asn, "isp": isp, "country": country, "city": city,
        "hostnames": hostnames, "tags": tags, "os": osname, "open_ports": open_ports,
        "total_vulns": total_vulns,
        "max_epss": max_epss, "max_cvss": max_cvss,
        "max_epss_cve": max_epss_cve, "max_cvss_cve": max_cvss_cve,
        "cves": ";".join(cves), "top5_cves_by_epss": top5_cves_by_epss,
        "last_update": last_update
    }

def build_detail_rows(host: dict, cve_meta: Dict[str, Dict[str, str]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    ip = host.get("ip_str") or host.get("ip") or ""
    for b in host.get("data", []) or []:
        port = b.get("port"); transport = b.get("transport","")
        product = b.get("product","") or (b.get("_shodan",{}) or {}).get("module","")
        version = str(b.get("version","") or "")
        cpe = b.get("cpe"); cpe_str = ";".join(cpe) if isinstance(cpe,list) else (cpe or "")
        b_v = b.get("vulns") or {}
        cves = sorted({k.upper() for k in b_v.keys()}) if isinstance(b_v,dict) else []
        if not cves:
            rows.append({"ip":ip,"port":str(port or ""),"transport":transport,"product":product,
                         "version":version,"cpe":cpe_str,"cve":"","severity":"","cvss":"","epss":"","epss_percentile":""})
            continue
        for cve in cves:
            meta = norm_vuln_meta(b_v.get(cve,{})) if isinstance(b_v.get(cve),dict) else cve_meta.get(cve,{})
            rows.append({"ip":ip,"port":str(port or ""),"transport":transport,"product":product,"version":version,
                         "cpe":cpe_str,"cve":cve,"severity":meta.get("severity",""),
                         "cvss":meta.get("cvss",""),"epss":meta.get("epss",""),"epss_percentile":meta.get("epss_percentile","")})
    return rows

# ===== Main =====
def main():
    ensure_dirs()
    api = shodan.Shodan(read_api_key())
    ips = load_ips("listip.txt")
    total = len(ips)
    print(f"[INFO] Ambil data Shodan untuk {total} IP (rate ~{RATE_LIMIT_SEC}s/req)...")

    host_results: Dict[str, Optional[dict]] = {}
    start_all = time.time()
    for idx, ip in enumerate(ips,1):
        t0 = time.time()
        host = fetch_host(api, ip); host_results[ip] = host
        if host:
            try: (RAW_DIR/f"{ip}.json").write_text(json.dumps(host,indent=2,ensure_ascii=False),encoding="utf-8")
            except Exception as e: print(f"[{ip}] Gagal tulis raw JSON: {e}")
        elapsed = time.time()-start_all
        per_item = elapsed/idx if idx else RATE_LIMIT_SEC
        remaining = max(total-idx,0)*max(per_item,RATE_LIMIT_SEC)
        print(f"[{idx}/{total}] {ip} -> {'OK' if host else 'NO-DATA'} | ETA ~{human_secs(remaining)}")
        spent = time.time()-t0; sleep_need = RATE_LIMIT_SEC-spent
        if idx<total and sleep_need>0: time.sleep(sleep_need)

    summary_rows, detail_rows = [], []
    for ip, host in host_results.items():
        if not host:
            summary_rows.append({"ip":ip,"org":"","asn":"","isp":"","country":"","city":"",
                                 "hostnames":"","tags":"","os":"","open_ports":"",
                                 "total_vulns":"0","max_epss":"","max_cvss":"",
                                 "max_epss_cve":"","max_cvss_cve":"","cves":"","top5_cves_by_epss":"","last_update":""})
            continue
        cve_meta = collect_vulns(host)
        summary_rows.append(summarize_host_row(host,cve_meta))
        detail_rows.extend(build_detail_rows(host,cve_meta))

    write_csv(SUMMARY_CSV, summary_rows, [
        "ip","org","asn","isp","country","city","hostnames","tags","os","open_ports",
        "total_vulns","max_epss","max_cvss","max_epss_cve","max_cvss_cve",
        "cves","top5_cves_by_epss","last_update"
    ])
    write_csv(DETAILS_CSV, detail_rows, [
        "ip","port","transport","product","version","cpe",
        "cve","severity","cvss","epss","epss_percentile"
    ])
    print(f"[DONE] Output di {OUT_DIR.resolve()}")
    print(f"  - {SUMMARY_CSV.name}")
    print(f"  - {DETAILS_CSV.name}")
    print("  - raw_json/<IP>.json")

if __name__=="__main__": main()
