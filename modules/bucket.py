#!/usr/bin/env python3
import subprocess
import re
import json
import time
from urllib.parse import urlparse
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from serpapi import GoogleSearch
from colorama import Fore, init

init(autoreset=True)

API_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"



# -------------------
# Helpers
# -------------------
def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def get_dns_records(domain, retries=3):
    for _ in range(retries):
        ips = run_cmd(["dig", "+short", domain, "A"])
        if ips:
            return ips
        time.sleep(1)
    return []


def get_whois_info(ip):
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, check=True)
        return [line.strip() for line in result.stdout.splitlines()
                if re.search(r"(NetRange|CIDR|route)", line, re.IGNORECASE)]
    except Exception:
        return []


def extract_bucket_and_key(url):
    parsed = urlparse(url)
    host, path = parsed.netloc, parsed.path.lstrip("/")
    bucket = None
    if host.endswith(".s3.amazonaws.com"):
        bucket = host.split(".s3.amazonaws.com")[0]
    elif ".s3." in host:
        bucket = host.split(".s3.")[0]
    return bucket, path or None


def check_object_read(bucket, key):
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    try:
        s3.get_object(Bucket=bucket, Key=key)
        return True
    except (ClientError, EndpointConnectionError):
        return False


def check_object_write(bucket, key="test_permission_check.txt"):
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=b"test")
        s3.delete_object(Bucket=bucket, Key=key)
        return True
    except (ClientError, EndpointConnectionError):
        return False


def serpapi_search(query, num=10, retries=3):
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    for _ in range(retries):
        try:
            search = GoogleSearch(params)
            results = search.get_dict()
            urls = [r.get("link") for r in results.get("organic_results", []) if r.get("link")]
            if urls:
                return urls
        except Exception:
            time.sleep(2)
    return []


# -------------------
# Main process
# -------------------
def process(domain, safe_domain):
    timestamp = datetime.now().isoformat()
    results = {"module": "bucket", "target": domain, "timestamp": timestamp,
               "dns": [], "s3_buckets": []}

    print(Fore.CYAN + f"\n[+] Bucket scan for {domain}")

    # --- DNS + WHOIS ---
    ips = get_dns_records(domain)
    if ips:
        print(Fore.GREEN + f"[✓] Found {len(ips)} IP(s)")
        for ip in ips:
            whois_info = get_whois_info(ip)
            results["dns"].append({"ip": ip, "whois": whois_info})
            print(Fore.YELLOW + f"    └─ {ip}")
    else:
        print(Fore.RED + "[!] No DNS A records found")

    # --- S3 Buckets ---
    print(Fore.CYAN + "[*] Searching for exposed S3 buckets...")
    query = (f'(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com '
             f'OR site:*.s3.dualstack.us-east-1.amazonaws.com '
             f'OR site:*.s3.ap-south-1.amazonaws.com) "{domain}"')
    urls = serpapi_search(query)

    if urls:
        print(Fore.GREEN + f"[✓] Found {len(urls)} possible S3 URLs")
        for url in urls:
            bucket, key = extract_bucket_and_key(url)
            if bucket:
                readable = check_object_read(bucket, key) if key else False
                writable = check_object_write(bucket)
                results["s3_buckets"].append({
                    "url": url, "bucket": bucket, "key": key,
                    "readable": readable, "writable": writable
                })
                print(Fore.YELLOW + f"    └─ Bucket: {bucket}")
    else:
        print(Fore.RED + "[!] No related S3 buckets found")

    # Save JSON
    with open(f"{safe_domain}_bucket.json", "w") as f:
        json.dump(results, f, indent=2)

    print(Fore.CYAN + f"[✓] Results saved to {safe_domain}_bucket.json\n")
    return results

