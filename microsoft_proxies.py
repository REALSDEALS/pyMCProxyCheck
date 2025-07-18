# microsoft_proxies.py

"""
A Python utility to maintain a local database of Microsoft Azure Service Tag IP prefixes and ASNs,
and to verify IP addresses against that database.

Usage:
    # Install dependencies
    pip install -r requirements.txt

    # Update or create the database
    python microsoft_proxies.py --update

    # Export CSV files
    python microsoft_proxies.py --export

    # Check IP addresses
    python microsoft_proxies.py --check-ip <ip1> <ip2> ...
"""

import requests
import re
import sqlite3
import ipaddress
from ipwhois import IPWhois
import argparse
import csv
import os

# Microsoft download page for Azure Service Tags
DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"

def fetch_json_url():
    """
    Scrape the Microsoft download page to find the URL of the latest
    ServiceTags_Public JSON file—even if it’s buried inside JavaScript.
    """
    # 1) Send a realistic browser User-Agent so Microsoft returns the full page
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/115.0.0.0 Safari/537.36"
        )
    }
    resp = requests.get(DOWNLOAD_PAGE, headers=headers)
    resp.raise_for_status()

    # 2) Match any URL that looks like:
    #    https://download.microsoft.com/download/.../ServiceTags_Public_YYYYMMDD.json
    pattern = (
        r"https://download\.microsoft\.com/download/[0-9A-Fa-f\-/]+/"
        r"ServiceTags_Public_[0-9]{8}\.json"
    )
    match = re.search(pattern, resp.text)

    # 3) If we didn’t find it, raise an error
    if not match:
        raise RuntimeError("Could not find JSON download link on Microsoft page.")

    # 4) Return the full JSON URL
    return match.group(0)

def update_database(db_path="microsoft_services.db"):
    """
    Download the latest ServiceTags JSON, parse prefixes, discover ASNs in parallel,
    and populate a local SQLite database.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import time

    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("CREATE TABLE tags (tag TEXT, prefix TEXT)")
    c.execute("CREATE TABLE asns (asn INTEGER UNIQUE)")

    print("Downloading ServiceTags JSON...")
    json_url = fetch_json_url()
    resp = requests.get(json_url)
    data = resp.json()

    print("Inserting tags and prefixes into database...")
    for entry in data.get('values', []):
        tag = entry.get('name')
        for prefix in entry.get('properties', {}).get('addressPrefixes', []):
            c.execute("INSERT INTO tags VALUES (?, ?)", (tag, prefix))

    prefixes = {row[0] for row in c.execute("SELECT DISTINCT prefix FROM tags")}
    print(f"Performing parallel ASN lookups for {len(prefixes)} prefixes...")

    def lookup_asn(prefix):
        ip = prefix.split('/')[0]
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(asn_methods=['dns', 'whois'])
            asn = int(res.get('asn', 0))
            return asn if asn else None
        except Exception:
            return None

    asn_set = set()
    with ThreadPoolExecutor(max_workers=75) as executor:  # You can change this number. My advice is to keep it under 100.
        future_to_prefix = {executor.submit(lookup_asn, p): p for p in prefixes}
        for i, future in enumerate(as_completed(future_to_prefix), 1):
            prefix = future_to_prefix[future]
            try:
                asn = future.result()
                if asn:
                    asn_set.add(asn)
                print(f"[{i}/{len(prefixes)}] Processed {prefix}", end="\r")
            except Exception as e:
                print(f"[{i}/{len(prefixes)}] Error processing {prefix}: {e}", end="\r")

    print("\nASN lookups complete. Writing to database...")
    for asn in asn_set:
        c.execute("INSERT OR IGNORE INTO asns VALUES(?)", (asn,))

    conn.commit()
    conn.close()
    print("Database updated successfully.")

def export_csv(db_path="microsoft_services.db"):
    """
    Export tags/prefixes and ASNs to separate CSV files.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    with open("microsoft_trusted_prefixes.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tag", "prefix"])
        for tag, prefix in c.execute("SELECT tag, prefix FROM tags"):
            writer.writerow([tag, prefix])

    with open("microsoft_asns.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["asn"])
        for (asn,) in c.execute("SELECT asn FROM asns"):
            writer.writerow([asn])

    conn.close()

def check_ips(ips, db_path="microsoft_services.db"):
    """
    Check a list of IP addresses against the database and return results.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    results = []

    for ip_str in ips:
        info = {"ip": ip_str, "trusted": False, "details": []}
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for tag, prefix in c.execute("SELECT tag, prefix FROM tags"):
                if ip_obj in ipaddress.ip_network(prefix):
                    info["trusted"] = True
                    info["details"].append(f"{prefix} ({tag})")
                    break
            if not info["trusted"]:
                rdap = IPWhois(ip_str).lookup_rdap(asn_methods=['dns','whois'])
                asn = int(rdap.get('asn', 0))
                if asn and any(asn == row[0] for row in c.execute("SELECT asn FROM asns")):
                    info["trusted"] = True
                    info["details"].append(f"ASN {asn}")
        except Exception as e:
            info["details"].append(f"Error: {e}")

        results.append(info)

    conn.close()
    return results

def main():
    parser = argparse.ArgumentParser(description="Manage and query Microsoft proxy database")
    parser.add_argument("--update", action="store_true", help="Fetch latest Service Tags & update database")
    parser.add_argument("--export", action="store_true", help="Export prefixes and ASNs to CSV files")
    parser.add_argument("--check-ip", nargs="+", help="Check one or more IP addresses")
    args = parser.parse_args()

    if args.update:
        update_database()
        print("Database updated.")
    if args.export:
        export_csv()
        print("CSV files generated: microsoft_trusted_prefixes.csv, microsoft_asns.csv")
    if args.check_ip:
        results = check_ips(args.check_ip)
        for r in results:
            status = "Trusted ✅" if r["trusted"] else "Untrusted ❌"
            print(f"{r['ip']}: {status}")
            if r["details"]:
                print("   Details:", ", ".join(r["details"]))

if __name__ == "__main__":
    main()
