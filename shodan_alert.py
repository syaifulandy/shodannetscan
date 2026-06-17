
#!/usr/bin/env python3
import argparse
import os
import sys
import logging
import pandas as pd
import ipaddress
import requests

MAX_NETWORK_SIZE = 65536
SHODAN_API_BASE = "https://api.shodan.io/shodan/alert"


# =========================
# ARGPARSE
# =========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="Bulk create Shodan Network Monitor Alert from Excel"
    )
    parser.add_argument("file", nargs="?", help="Input Excel file")
    parser.add_argument("--api-key", help="Shodan API Key")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    return parser.parse_args()


# =========================
# API KEY RESOLUTION
# =========================
def get_api_key(arg_key):
    if arg_key:
        return arg_key

    # apikey.txt
    if os.path.exists("apikey.txt"):
        with open("apikey.txt") as f:
            key = f.read().strip()
            if key:
                return key

    # env
    key = os.getenv("SHODAN_API_KEY")
    if key:
        return key

    print("[ERROR] Shodan API key not found")
    sys.exit(1)


# =========================
# LOGGING SETUP
# =========================
def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger().addHandler(console)


# =========================
# READ & VALIDATE EXCEL
# =========================
def load_excel(path):
    try:
        df = pd.read_excel(path, engine="openpyxl")
    except Exception as e:
        logging.error(f"Failed to read Excel: {e}")
        sys.exit(1)

    required_cols = ["Unit", "Segment IP/List IP"]
    for col in required_cols:
        if col not in df.columns:
            logging.error(f"Missing required column: {col}")
            sys.exit(1)

    # cleaning
    df = df[required_cols]
    df = df.dropna()
    df["Unit/Anper"] = df["Unit/Anper"].astype(str).str.strip()
    df["Segment IP/List IP"] = df["Segment IP/List IP"].astype(str).str.strip()
    df = df[df["Unit/Anper"] != ""]

    return df


# =========================
# PROCESS NETWORKS
# =========================
def process_networks(df):
    grouped = {}

    for _, row in df.iterrows():
        unit = row["Unit/Anper"]
        net_str = row["Segment IP/List IP"]

        try:
            net = ipaddress.ip_network(net_str, strict=False)
        except Exception:
            logging.warning(f"Invalid network skipped: {net_str}")
            continue

        if unit not in grouped:
            grouped[unit] = []

        grouped[unit].append(net)

    # dedup + collapse
    final = {}

    for unit, nets in grouped.items():
        merged = list(ipaddress.collapse_addresses(nets))

        total_size = sum(n.num_addresses for n in merged)
        if total_size > MAX_NETWORK_SIZE:
            logging.warning(
                f"{unit} skipped: network size {total_size} exceeds limit"
            )
            continue

        final[unit] = [str(n) for n in merged]

    return final


# =========================
# GET EXISTING ALERTS
# =========================

def get_existing_alerts(api_key):
    url = f"{SHODAN_API_BASE}/info?key={api_key}"

    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
    except requests.RequestException as e:
        logging.error(f"Failed to fetch alerts: {e}")
        sys.exit(1)

    try:
        alerts = r.json()
    except Exception:
        logging.error("Invalid JSON response from Shodan")
        sys.exit(1)

    if not isinstance(alerts, list):
        logging.error("Unexpected response format (not a list)")
        logging.error(f"Response: {alerts}")
        sys.exit(1)

    result = {}
    for alert in alerts:
        try:
            result[alert["name"]] = alert["id"]
        except KeyError:
            logging.warning(f"Malformed alert skipped: {alert}")

    return result


# =========================
# CREATE ALERT
# =========================
def create_alert(api_key, name, networks, dry_run=False):
    payload = {
        "name": name,
        "filters": {"ip": networks},
        "expires": 0,
    }

    if dry_run:
        logging.info(f"[DRY-RUN] {name} -> {networks}")
        return "DRY_RUN"

    url = f"{SHODAN_API_BASE}?key={api_key}"
    r = requests.post(url, json=payload)

    if r.status_code == 200:
        return "CREATED"
    else:
        logging.error(f"Failed create {name}: {r.text}")
        return "FAILED"


# =========================
# MAIN
# =========================
def main():
    args = parse_args()

    if not args.file:
        print("Usage:")
        print("  python3 shodan_alert_bulk.py data.xlsx")
        print("  python3 shodan_alert_bulk.py data.xlsx --dry-run")
        print("  python3 shodan_alert_bulk.py data.xlsx --api-key XXXXX")
        sys.exit(0)

    input_file = args.file

    base = os.path.splitext(os.path.basename(input_file))[0]
    log_file = f"{base}.log"
    result_file = f"{base}_results.csv"

    setup_logging(log_file)

    logging.info("Starting processing...")

    api_key = get_api_key(args.api_key)

    df = load_excel(input_file)

    grouped = process_networks(df)

    existing = get_existing_alerts(api_key)

    results = []

    total = len(grouped)
    for i, (unit, networks) in enumerate(grouped.items(), 1):
        logging.info(f"[{i}/{total}] Processing {unit}")

        if unit in existing:
            logging.info(f"{unit} already exists")
            status = "EXISTS"
        else:
            status = create_alert(api_key, unit, networks, args.dry_run)

        results.append({"Unit": unit, "Status": status})

    # save CSV
    pd.DataFrame(results).to_csv(result_file, index=False)

    logging.info("Done")
    logging.info(f"Result saved: {result_file}")


if __name__ == "__main__":
    main()
