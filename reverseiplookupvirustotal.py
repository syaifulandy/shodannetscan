import requests
import time
import sys
import csv

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/resolutions?limit=10"
RATE_LIMIT_DELAY = 15  # 4 request per menit
OUTPUT_FILE = "output.csv"

def load_apikey():
    try:
        with open("apikey.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("[!] File apikey.txt tidak ditemukan")
        sys.exit(1)

def load_ip_list():
    try:
        with open("listip.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] File listip.txt tidak ditemukan")
        sys.exit(1)

def query_ip(ip, api_key):
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    url = API_URL.format(ip=ip)

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        print(f"[!] {ip} → HTTP {r.status_code}")
        return "-"

    data = r.json().get("data", [])
    ids = [item.get("id") for item in data if "id" in item]

    return ";".join(ids) if ids else "-"

def main():
    print("=== VirusTotal IP Resolution Checker ===")
    print("File dibutuhkan:")
    print(" - apikey.txt")
    print(" - listip.txt")
    print("--------------------------------------")

    api_key = load_apikey()
    ip_list = load_ip_list()

    print(f"[+] Total IP: {len(ip_list)}")
    print("[+] Rate limit: 4 request / menit")
    print(f"[+] Output: {OUTPUT_FILE}\n")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip", "resolutions"])

        for i, ip in enumerate(ip_list, start=1):
            result = query_ip(ip, api_key)
            writer.writerow([ip, result])
            print(f"{ip} -> {result}")

            if i < len(ip_list):
                time.sleep(RATE_LIMIT_DELAY)

    print("\n[✓] Selesai. Output tersimpan di output.csv")

if __name__ == "__main__":
    main()
