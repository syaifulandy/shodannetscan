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
- HANYA pakai data dari Shodan (host().vulns) termasuk severity, cvss, epss, epss_percentile jika tersedia.
- Serial + rate limit default 1.1s/req agar aman untuk plan 1 req/detik (ubah via env RATE_LIMIT_SEC).
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

RATE_LIMIT_SEC = float(os.getenv("RATE_LIMIT_SEC", "1.1"))  # patuhi 1 req/detik (sedikit buffer)
RETRY_MAX = 3
RETRY_BACKOFF = 2.0  # detik dasar backoff untuk rate-limit/server error

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

# ===== Shodan helpers =====
def fetch_host(api: shodan.Shodan, ip: str) -> Optional[dict]:
    for attempt in range(1, RETRY_MAX + 1):
        try:
            # Shodan SDK tidak menerima arg timeout di host()
            return api.host(ip, minify=False)
        except shodan.exception.APIError as e:
            msg = str(e)
            low = msg.lower()
            if any(x in low for x in ["rate limit", "too many requests", "timeout", "gateway", "server error"]):
                sleep_for = RETRY_BACKOFF * attempt
                print(f"[{ip}] APIError attempt {attempt}/{RETRY_MAX}: {msg} -> sleep {sleep_for:.1f}s")
                time.sleep(sleep_for)
                continue
            if any(x in low for x in ["no information available", "not found"]):
                print(f"[{ip}] Tidak ada informasi di Shodan.")
                return None
            print(f"[{ip}] APIError: {msg}")
            return None
        except Exception as e:
            sleep_for = RETRY_BACKOFF * attempt
            print(f"[{ip}] ERROR attempt {attempt}/{RETRY_MAX}: {e} -> sleep {sleep_for:.1f}s")
            time.sleep(sleep_for)
    return None

def norm_vuln_meta(meta: dict) -> Dict[str, str]:
    """
    Normalisasi field meta CVE dari Shodan (yang tersedia saja).
    Kunci yang dicoba: severity, cvss, epss, epss_percentile (dengan variasi nama umum).
    """
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
    except Exception:
        cvss = str(cvss_val) if cvss_val is not None else ""

    epss = str(pick("epss", "epssScore", default=""))
    epss_pct = str(pick("epss_percentile", "epssPercentile", "epss_rank", "epssRank", default=""))

    return {"severity": severity, "cvss": cvss, "epss": epss, "epss_percentile": epss_pct}

def severity_rank(s: str) -> int:
    s = (s or "").lower()
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get(s, 0)

def merge_meta(a: Dict[str, str], b: Dict[str, str]) -> Dict[str, str]:
    """Gabung dua meta CVE: severity lebih tinggi, cvss/epss maksimum, isi kosong diisi yang ada."""
    out = {
        "severity": a.get("severity", "") or b.get("severity", ""),
        "cvss": a.get("cvss", "") or b.get("cvss", ""),
        "epss": a.get("epss", "") or b.get("epss", ""),
        "epss_percentile": a.get("epss_percentile", "") or b.get("epss_percentile", "")
    }
    # severity: pilih rank tertinggi
    if severity_rank(b.get("severity", "")) > severity_rank(out.get("severity", "")):
        out["severity"] = b.get("severity", "")
    # cvss/epss: ambil angka terbesar jika dua-duanya ada nilai numeric
    try:
        av = float(a.get("cvss", ""))
        bv = float(b.get("cvss", ""))
        out["cvss"] = f"{max(av, bv):.1f}"
    except:
        pass
    try:
        av = float(a.get("epss", ""))
        bv = float(b.get("epss", ""))
        out["epss"] = f"{max(av, bv):.4f}"
    except:
        pass
    # percentile: maksimum
    try:
        av = float(a.get("epss_percentile", ""))
        bv = float(b.get("epss_percentile", ""))
        out["epss_percentile"] = f"{max(av, bv)}"
    except:
        pass
    return out

def collect_top_level_vulns(host: dict) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    vulns = host.get("vulns") or {}
    if isinstance(vulns, dict):
        for k, meta in vulns.items():
            cve = str(k).upper()
            if not cve.startswith("CVE-"):
                continue
            out[cve] = norm_vuln_meta(meta if isinstance(meta, dict) else {})
    return out

def collect_banner_vulns(host: dict) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for banner in host.get("data", []) or []:
        b_v = banner.get("vulns") or {}
        if not isinstance(b_v, dict):
            continue
        for k, meta in b_v.items():
            cve = str(k).upper()
            if not cve.startswith("CVE-"):
                continue
            nm = norm_vuln_meta(meta if isinstance(meta, dict) else {})
            out[cve] = merge_meta(out.get(cve, {}), nm) if cve in out else nm
    return out

def collect_all_cves_with_meta(host: dict) -> Dict[str, Dict[str, str]]:
    """Gabungkan CVE dari host['vulns'] dan setiap banner['vulns']."""
    top = collect_top_level_vulns(host)
    ban = collect_banner_vulns(host)
    merged = dict(top)
    for cve, meta in ban.items():
        merged[cve] = merge_meta(merged.get(cve, {}), meta) if cve in merged else meta
    return merged

def write_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def summarize_host_row(host: dict, cve_meta_map: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    ip = host.get("ip_str") or host.get("ip") or ""
    org = host.get("org") or ""
    isp = host.get("isp") or ""
    asn = host.get("asn") or ""
    osname = host.get("os") or ""
    country = (host.get("location") or {}).get("country_name", "") if isinstance(host.get("location"), dict) else ""
    city = (host.get("location") or {}).get("city", "") if isinstance(host.get("location"), dict) else ""
    hostnames = ";".join(host.get("hostnames") or [])
    tags = ";".join(host.get("tags") or [])
    last_update = host.get("last_update") or ""
    open_ports = ";".join(str(p) for p in sorted(set(host.get("ports") or [])))

    total_vulns = str(len(cve_meta_map))

    # cari max cvss & max epss
    max_cvss = ""
    max_epss = ""
    try:
        cvss_vals = [float(m["cvss"]) for m in cve_meta_map.values() if m.get("cvss")]
        if cvss_vals:
            max_cvss = f"{max(cvss_vals):.1f}"
    except Exception:
        pass
    try:
        epss_vals = [float(m["epss"]) for m in cve_meta_map.values() if m.get("epss")]
        if epss_vals:
            max_epss = f"{max(epss_vals):.4f}"
    except Exception:
        pass

    return {
        "ip": ip, "org": org, "asn": asn, "isp": isp, "country": country, "city": city,
        "hostnames": hostnames, "tags": tags, "os": osname, "open_ports": open_ports,
        "total_vulns": total_vulns, "max_epss": max_epss, "max_cvss": max_cvss,
        "last_update": last_update
    }

def build_detail_rows(host: dict, cve_meta_map: Dict[str, Dict[str, str]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    ip = host.get("ip_str") or host.get("ip") or ""

    for banner in host.get("data", []) or []:
        port = banner.get("port")
        transport = banner.get("transport", "")
        product = banner.get("product", "") or (banner.get("_shodan", {}) or {}).get("module", "")
        version = str(banner.get("version", "") or "")
        cpe = banner.get("cpe")
        cpe_str = ";".join(cpe) if isinstance(cpe, list) else (cpe or "")

        b_vulns = banner.get("vulns") or {}
        if isinstance(b_vulns, dict) and b_vulns:
            cves = sorted({k.upper() for k in b_vulns.keys() if str(k).upper().startswith("CVE-")})
        else:
            cves = []

        if not cves:
            rows.append({
                "ip": ip, "port": str(port or ""), "transport": transport,
                "product": product, "version": version, "cpe": cpe_str,
                "cve": "", "severity": "", "cvss": "", "epss": "", "epss_percentile": ""
            })
            continue

        for cve in cves:
            # meta dari banner (kalau ada), kalau kosong fallback ke gabungan map
            meta = {}
            m = b_vulns.get(cve)
            if isinstance(m, dict):
                meta = norm_vuln_meta(m)
            elif cve in cve_meta_map:
                meta = cve_meta_map[cve]
            else:
                meta = {"severity": "", "cvss": "", "epss": "", "epss_percentile": ""}

            rows.append({
                "ip": ip, "port": str(port or ""), "transport": transport,
                "product": product, "version": version, "cpe": cpe_str,
                "cve": cve,
                "severity": meta.get("severity", ""),
                "cvss": meta.get("cvss", ""),
                "epss": meta.get("epss", ""),
                "epss_percentile": meta.get("epss_percentile", "")
            })
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

    for idx, ip in enumerate(ips, 1):
        t0 = time.time()
        host = fetch_host(api, ip)
        host_results[ip] = host
        if host:
            try:
                (RAW_DIR / f"{ip}.json").write_text(
                    json.dumps(host, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            except Exception as e:
                print(f"[{ip}] Gagal tulis raw JSON: {e}")

        # progress + ETA
        elapsed_all = time.time() - start_all
        per_item = elapsed_all / idx if idx else RATE_LIMIT_SEC
        remaining = max(total - idx, 0) * max(per_item, RATE_LIMIT_SEC)
        print(f"[{idx}/{total}] {ip} -> {'OK' if host else 'NO-DATA'} | ETA ~{human_secs(remaining)}")

        # patuhi rate limit antar panggilan (kecuali item terakhir)
        spent = time.time() - t0
        sleep_need = RATE_LIMIT_SEC - spent
        if idx < total and sleep_need > 0:
            time.sleep(sleep_need)

    summary_rows: List[Dict[str, str]] = []
    detail_rows: List[Dict[str, str]] = []

    for ip, host in host_results.items():
        if not host:
            summary_rows.append({
                "ip": ip, "org": "", "asn": "", "isp": "", "country": "", "city": "",
                "hostnames": "", "tags": "", "os": "", "open_ports": "",
                "total_vulns": "0", "max_epss": "", "max_cvss": "", "last_update": ""
            })
            continue

        combined_cve_meta = collect_all_cves_with_meta(host)
        summary_rows.append(summarize_host_row(host, combined_cve_meta))
        detail_rows.extend(build_detail_rows(host, combined_cve_meta))

    # tulis CSV
    write_csv(SUMMARY_CSV, summary_rows, [
        "ip","org","asn","isp","country","city","hostnames","tags","os",
        "open_ports","total_vulns","max_epss","max_cvss","last_update"
    ])
    write_csv(DETAILS_CSV, detail_rows, [
        "ip","port","transport","product","version","cpe",
        "cve","severity","cvss","epss","epss_percentile"
    ])

    print(f"[DONE] Output di: {OUT_DIR.resolve()}")
    print(f"  - {SUMMARY_CSV.name}")
    print(f"  - {DETAILS_CSV.name}")
    print("  - raw_json/<IP>.json")

if __name__ == "__main__":
    main()

