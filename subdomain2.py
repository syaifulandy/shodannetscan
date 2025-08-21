#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shodan export: hostname:"*.abc.co.id"
- Output 1 (summary per IP):   Output_subdomain/shodan_summary.csv
- Output 2 (detail per port/CVE): Output_subdomain/shodan_detail.csv
- Optional JSONL raw detail:   Output_subdomain/shodan_detail.jsonl

Contoh:
  python shodan_export_dual.py \
    --query 'hostname:"*.abc.co.id"' \
    --apikey-file apikey.txt \
    --max 0
"""
import os
import sys
import csv
import json
import time
import argparse
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

from shodan import Shodan
from shodan.client import APIError


# ==========================
# Util & normalizers
# ==========================

def backoff_sleep(attempt: int) -> None:
    time.sleep(min(60, (2 ** attempt)))


def load_api_key(path: str = "apikey.txt") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if not key:
                raise ValueError("API key kosong.")
            return key
    except FileNotFoundError:
        print(f"[!] File {path} tidak ditemukan", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Gagal membaca API key: {e}", file=sys.stderr)
        sys.exit(1)


def normalize_vulns(vulns_field: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not vulns_field:
        return out
    if isinstance(vulns_field, list):
        for cve in vulns_field:
            out.append({"cve": cve})
        return out
    if isinstance(vulns_field, dict):
        for cve, meta in vulns_field.items():
            row: Dict[str, Any] = {"cve": cve}
            if isinstance(meta, dict):
                for k in ("cvss", "cvss_v2", "cvss_version", "summary", "verified", "epss", "ranking_epss", "references"):
                    if k in meta:
                        row[k] = meta.get(k)
            out.append(row)
        return out
    return out


def get_ssl_subject_issuer(match: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    ssl = match.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subj = cert.get("subject") or {}
    issr = cert.get("issuer") or {}

    def join_dn(d: Dict[str, Any]) -> str:
        parts = []
        for k in ("CN", "O", "OU", "C", "L", "ST"):
            v = d.get(k)
            if v:
                parts.append(f"{k}={v}")
        return ", ".join(parts) if parts else ""

    return (join_dn(subj) or None, join_dn(issr) or None)


def get_http_title(match: Dict[str, Any]) -> Optional[str]:
    http = match.get("http") or {}
    title = http.get("title")
    return title.strip() if title else None


def get_product_version_cpe(match: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    product = match.get("product")
    version = match.get("version")
    cpe = None
    if "cpe" in match:
        c = match["cpe"]
        if isinstance(c, list) and c:
            cpe = ";".join([str(x) for x in c])
        elif isinstance(c, str):
            cpe = c
    return product, version, cpe


def iter_shodan(api: Shodan, query: str, max_results: int = 0) -> Iterable[Dict[str, Any]]:
    count = 0
    attempt = 0
    while True:
        try:
            for match in api.search_cursor(query):
                yield match
                count += 1
                if max_results and count >= max_results:
                    return
            return
        except APIError as e:
            attempt += 1
            if attempt > 6:
                print(f"[!] Shodan APIError (giving up): {e}", file=sys.stderr)
                return
            print(f"[!] Shodan APIError: {e} -> retry (backoff)", file=sys.stderr)
            backoff_sleep(attempt)


# ==========================
# Row builders (detail + summary)
# ==========================

DETAIL_FIELDS = [
    "ip", "port", "transport",
    "hostnames", "domains",
    "org", "asn",
    "country", "city", "latitude", "longitude",
    "product", "version", "cpe",
    "ssl_subject", "ssl_issuer",
    "http_title",
    "tags",
    "cve", "cvss", "cvss_v2", "cvss_version", "vuln_verified",
    "epss", "ranking_epss",
    "vuln_summary", "vuln_references",
    "timestamp", "shodan_host_link"
]

SUMMARY_FIELDS = [
    "ip",
    "hostnames", "domains",
    "org", "asn",
    "country", "city", "latitude", "longitude",
    "ports", "transports",
    "products",
    "cves",
    "max_epss", "max_ranking_epss",
    "services_count", "cve_count",
    "tags",
    "first_seen", "last_seen",
    "shodan_host_link"
]


def build_detail_rows(match: Dict[str, Any]) -> List[Dict[str, Any]]:
    ip = match.get("ip_str") or match.get("ip")
    port = match.get("port")
    transport = match.get("transport")
    tags = ",".join(match.get("tags", [])) if match.get("tags") else None
    hostnames = ",".join(match.get("hostnames", [])) if match.get("hostnames") else None
    domains = ",".join(match.get("domains", [])) if match.get("domains") else None
    asn = match.get("asn")
    org = match.get("org")
    product, version, cpe = get_product_version_cpe(match)
    ssl_subject, ssl_issuer = get_ssl_subject_issuer(match)
    http_title = get_http_title(match)
    location = match.get("location") or {}
    country = location.get("country_name")
    city = location.get("city")
    latitude = location.get("latitude")
    longitude = location.get("longitude")
    timestamp = match.get("timestamp")
    host_link = f"https://www.shodan.io/host/{ip}" if ip else None

    vulns = normalize_vulns(match.get("vulns"))
    base = {
        "ip": ip,
        "port": port,
        "transport": transport,
        "hostnames": hostnames,
        "domains": domains,
        "org": org,
        "asn": asn,
        "country": country,
        "city": city,
        "latitude": latitude,
        "longitude": longitude,
        "product": product,
        "version": version,
        "cpe": cpe,
        "ssl_subject": ssl_subject,
        "ssl_issuer": ssl_issuer,
        "http_title": http_title,
        "tags": tags,
        "timestamp": timestamp,
        "shodan_host_link": host_link,
    }

    rows: List[Dict[str, Any]] = []
    if vulns:
        for v in vulns:
            row = dict(base)
            row.update({
                "cve": v.get("cve"),
                "cvss": v.get("cvss"),
                "cvss_v2": v.get("cvss_v2"),
                "cvss_version": v.get("cvss_version"),
                "vuln_verified": v.get("verified"),
                "epss": v.get("epss"),
                "ranking_epss": v.get("ranking_epss"),
                "vuln_summary": v.get("summary"),
                "vuln_references": ";".join(v.get("references", [])) if isinstance(v.get("references"), list) else (v.get("references") or None),
            })
            rows.append(row)
    else:
        row = dict(base)
        row.update({
            "cve": None,
            "cvss": None,
            "cvss_v2": None,
            "cvss_version": None,
            "vuln_verified": None,
            "epss": None,
            "ranking_epss": None,
            "vuln_summary": None,
            "vuln_references": None,
        })
        rows.append(row)

    return rows


class IpAccumulator:
    def __init__(self) -> None:
        self.hostnames: Set[str] = set()
        self.domains: Set[str] = set()
        self.tags: Set[str] = set()
        self.ports: Set[int] = set()
        self.transports: Set[str] = set()
        self.products: Set[str] = set()
        self.cves: Set[str] = set()
        self.max_epss: Optional[float] = None
        self.max_ranking_epss: Optional[float] = None
        self.services_count: int = 0
        self.cve_count: int = 0
        self.first_seen: Optional[str] = None
        self.last_seen: Optional[str] = None
        self.asn: Optional[str] = None
        self.org: Optional[str] = None
        self.country: Optional[str] = None
        self.city: Optional[str] = None
        self.latitude: Optional[float] = None
        self.longitude: Optional[float] = None

    def update_from_match(self, match: Dict[str, Any]) -> None:
        self.services_count += 1
        for h in match.get("hostnames", []) or []:
            self.hostnames.add(str(h))
        for d in match.get("domains", []) or []:
            self.domains.add(str(d))
        for t in match.get("tags", []) or []:
            self.tags.add(str(t))
        port = match.get("port")
        if isinstance(port, int):
            self.ports.add(port)
        tr = match.get("transport")
        if tr:
            self.transports.add(str(tr))
        product = match.get("product")
        version = match.get("version")
        if product:
            self.products.add(f"{product} {version}" if version else str(product))
        self.asn = self.asn or match.get("asn")
        self.org = self.org or match.get("org")
        loc = match.get("location") or {}
        self.country = self.country or loc.get("country_name")
        self.city = self.city or loc.get("city")
        self.latitude = self.latitude if self.latitude is not None else loc.get("latitude")
        self.longitude = self.longitude if self.longitude is not None else loc.get("longitude")
        ts = match.get("timestamp")
        if ts:
            if not self.first_seen or ts < self.first_seen:
                self.first_seen = ts
            if not self.last_seen or ts > self.last_seen:
                self.last_seen = ts
        for v in normalize_vulns(match.get("vulns")):
            cve = v.get("cve")
            if cve:
                self.cves.add(cve)
                self.cve_count += 1
            try:
                epss = v.get("epss")
                if epss is not None:
                    epss_f = float(epss)
                    self.max_epss = epss_f if self.max_epss is None else max(self.max_epss, epss_f)
            except Exception:
                pass
            try:
                rnk = v.get("ranking_epss")
                if rnk is not None:
                    rnk_f = float(rnk)
                    self.max_ranking_epss = rnk_f if self.max_ranking_epss is None else max(self.max_ranking_epss, rnk_f)
            except Exception:
                pass

    def to_row(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "hostnames": ",".join(sorted(self.hostnames)) if self.hostnames else None,
            "domains": ",".join(sorted(self.domains)) if self.domains else None,
            "org": self.org,
            "asn": self.asn,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "ports": ",".join(map(str, sorted(self.ports))) if self.ports else None,
            "transports": ",".join(sorted(self.transports)) if self.transports else None,
            "products": ",".join(sorted(self.products)) if self.products else None,
            "cves": ",".join(sorted(self.cves)) if self.cves else None,
            "max_epss": self.max_epss,
            "max_ranking_epss": self.max_ranking_epss,
            "services_count": self.services_count,
            "cve_count": self.cve_count,
            "tags": ",".join(sorted(self.tags)) if self.tags else None,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "shodan_host_link": f"https://www.shodan.io/host/{ip}",
        }


# ==========================
# Main
# ==========================

def main() -> None:
    parser = argparse.ArgumentParser(description="Export Shodan data (ringkasan per-IP + detil per-port/CVE) via search_cursor.")
    parser.add_argument("--query", default='hostname:"*.abc.co.id"', help='Shodan query. Default: hostname:"*.abc.co.id"')
    parser.add_argument("--apikey-file", default="apikey.txt", help="Path file API key (default: apikey.txt)")
    parser.add_argument("--max", type=int, default=0, help="Batas jumlah banner/service (0 = tanpa batas)")
    parser.add_argument("--out-jsonl", default=None, help="(Opsional) Output JSONL detil (1 baris per detail)")
    args = parser.parse_args()

    api_key = load_api_key(args.apikey_file)
    api = Shodan(api_key)

    # pastikan folder Output_subdomain ada
    out_dir = "Output_subdomain"
    os.makedirs(out_dir, exist_ok=True)
    out_summary = os.path.join(out_dir, "shodan_summary.csv")
    out_detail = os.path.join(out_dir, "shodan_detail.csv")
    out_jsonl = os.path.join(out_dir, "shodan_detail.jsonl") if args.out_jsonl else None

    detail_f = open(out_detail, "w", newline="", encoding="utf-8")
    detail_writer = csv.DictWriter(detail_f, fieldnames=DETAIL_FIELDS)
    detail_writer.writeheader()

    summary_f = open(out_summary, "w", newline="", encoding="utf-8")
    summary_writer = csv.DictWriter(summary_f, fieldnames=SUMMARY_FIELDS)
    summary_writer.writeheader()

    jsonl_f = open(out_jsonl, "w", encoding="utf-8") if out_jsonl else None

    per_ip: Dict[str, IpAccumulator] = {}
    total_detail_rows = 0
    total_services = 0

    try:
        for match in iter_shodan(api, args.query, max_results=args.max):
            total_services += 1
            ip = match.get("ip_str") or match.get("ip")
            if ip:
                acc = per_ip.get(ip)
                if acc is None:
                    acc = IpAccumulator()
                    per_ip[ip] = acc
                acc.update_from_match(match)

            rows = build_detail_rows(match)
            for r in rows:
                detail_writer.writerow({k: r.get(k) for k in DETAIL_FIELDS})
                total_detail_rows += 1
                if jsonl_f:
                    jsonl_f.write(json.dumps(r, ensure_ascii=False) + "\n")
    finally:
        for ip, acc in per_ip.items():
            row = acc.to_row(ip)
            summary_writer.writerow({k: row.get(k) for k in SUMMARY_FIELDS})
        detail_f.close()
        summary_f.close()
        if jsonl_f:
            jsonl_f.close()

    print(f"[OK] Summary CSV : {out_summary} (IPs: {len(per_ip)})")
    print(f"[OK] Detail  CSV : {out_detail} (rows: {total_detail_rows}, services: {total_services})")
    if out_jsonl:
        print(f"[OK] JSONL       : {out_jsonl}")


if __name__ == "__main__":
    main()

