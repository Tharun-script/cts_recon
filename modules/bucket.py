#!/usr/bin/env python3
import os
import subprocess
import re
from urllib.parse import urlparse
from datetime import datetime
from serpapi import GoogleSearch
import boto3
from botocore.exceptions import ClientError#!/usr/bin/env python3
import os
import subprocess
import re
from urllib.parse import urlparse
from datetime import datetime
from serpapi import GoogleSearch
import boto3
from botocore.exceptions import ClientError
from colorama import Fore, Style, init
import json

init(autoreset=True)

# === CONFIG ===
API_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"

# -------------------
# DNS + WHOIS Helpers
# -------------------
def get_dns_records(domain):
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "A"],
            capture_output=True, text=True, check=True
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []

def get_whois_info(ip):
    info = []
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if re.search(r"NetRange|CIDR|route", line, re.IGNORECASE):
                info.append(line.strip())
    except Exception as e:
        info.append(f"WHOIS lookup failed: {e}")
    return info

# -------------------
# S3 Helpers
# -------------------
def extract_bucket_and_key(url):
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path.lstrip("/")
    bucket = None
    if host.endswith(".s3.amazonaws.com"):
        bucket = host.split(".s3.amazonaws.com")[0]
    elif ".s3." in host:
        bucket = host.split(".s3.")[0]
    return bucket, path if path else None

def check_object_read(bucket, key):
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    try:
        s3.get_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False

def check_object_write(bucket, key="test_permission_check.txt"):
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=b"test")
        s3.delete_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False

def serpapi_search(query, num=10):
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    search = GoogleSearch(params)
    results = search.get_dict()
    urls = []
    for res in results.get("organic_results", []):
        link = res.get("link")
        if link:
            urls.append(link)
    return urls

# -------------------
# Save results to central {target}_scan.json
# -------------------
def save_scan(target, dns_results=None, whois_results=None, bucket_results=None):
    """Save all scan results to {target}_scan.json"""
    filename = f"{target}_scan.json"
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    else:
        data = {}

    timestamp = datetime.now().isoformat()
    if dns_results is not None:
        data["dns"] = {"timestamp": timestamp, "ips": dns_results}
    if whois_results is not None:
        data["whois"] = {"timestamp": timestamp, "results": whois_results}
    if bucket_results is not None:
        data["bucket"] = {"timestamp": timestamp, "results": bucket_results}

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

# -------------------
# Main bucket scan function
# -------------------
def bucket_scan(domain):
    print(Fore.CYAN + f"\n[*] Scanning target: {domain}")

    # --- DNS ---
    print(Fore.CYAN + f"[*] Resolving DNS records for {domain}...")
    ips = get_dns_records(domain)
    if ips:
        print(Fore.GREEN + f"[✓] Found {len(ips)} IP(s):")
        for ip in ips:
            print(Fore.YELLOW + f"  └─ {ip}")
    else:
        print(Fore.RED + "[!] No DNS A records found.")

    # --- WHOIS ---
    whois_results = []
    if ips:
        for ip in ips:
            info = get_whois_info(ip)
            whois_results.append({"ip": ip, "whois": info})
            if info:
                print(Fore.MAGENTA + f"  WHOIS for {ip}: {', '.join(info[:3])}...")

    # --- S3 Buckets ---
    print(Fore.CYAN + f"[*] Scanning S3 buckets for {domain}...")
    s3_query = (
        f'(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com '
        f'OR site:*.s3.dualstack.us-east-1.amazonaws.com '
        f'OR site:*.s3.ap-south-1.amazonaws.com) "{domain}"'
    )
    urls = serpapi_search(s3_query)
    s3_results = []
    if urls:
        print(Fore.GREEN + f"[✓] Found {len(urls)} possible S3 URLs:")
        for url in urls:
            bucket, key = extract_bucket_and_key(url)
            if bucket:
                read = check_object_read(bucket, key) if key else False
                write = check_object_write(bucket)
                s3_results.append({
                    "url": url,
                    "bucket": bucket,
                    "key": key,
                    "read": read,
                    "write": write
                })
                print(Fore.YELLOW + f"  Bucket: {bucket}")
                if key:
                    print(Fore.WHITE + f"    Key: {key}")
                print(Fore.GREEN + f"    Readable: {read}, Writable: {write}")
    else:
        print(Fore.RED + "[!] No related S3 buckets found.")

    # --- Save everything to JSON ---
    save_scan(domain, dns_results=ips, whois_results=whois_results, bucket_results=s3_results)
    print(Fore.CYAN + f"[*] Scan results saved to {domain}_scan.json")
    print(Fore.CYAN + f"[*] Bucket scan for {domain} completed.\n")
    return True

# -------------------
# Pipeline-compatible entry point
# -------------------
def process(domain):
    return bucket_scan(domain)

# -------------------
# Example usage
# -------------------
if __name__ == "__main__":
    target_domain = "evil.com"
    process(target_domain)

from colorama import Fore, Style, init
import json

init(autoreset=True)

# === CONFIG ===
API_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"

# -------------------
# DNS + WHOIS Helpers
# -------------------
def get_dns_records(domain):
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "A"],
            capture_output=True, text=True, check=True
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []

def get_whois_info(ip):
    info = []
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if re.search(r"NetRange|CIDR|route", line, re.IGNORECASE):
                info.append(line.strip())
    except Exception as e:
        info.append(f"WHOIS lookup failed: {e}")
    return info

# -------------------
# S3 Helpers
# -------------------
def extract_bucket_and_key(url):
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path.lstrip("/")
    bucket = None
    if host.endswith(".s3.amazonaws.com"):
        bucket = host.split(".s3.amazonaws.com")[0]
    elif ".s3." in host:
        bucket = host.split(".s3.")[0]
    return bucket, path if path else None

def check_object_read(bucket, key):
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    try:
        s3.get_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False

def check_object_write(bucket, key="test_permission_check.txt"):
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=b"test")
        s3.delete_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False

def serpapi_search(query, num=10):
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    search = GoogleSearch(params)
    results = search.get_dict()
    urls = []
    for res in results.get("organic_results", []):
        link = res.get("link")
        if link:
            urls.append(link)
    return urls

# -------------------
# Save results to central {target}_scan.json
# -------------------
def save_bucket_scan(target, s3_results):
    """Append bucket scan results to {target}_scan.json"""
    filename = f"{target}_scan.json"
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    else:
        data = {}

    # Add/update bucket results
    data["bucket"] = {
        "timestamp": datetime.now().isoformat(),
        "results": s3_results
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(Fore.CYAN + f"[*] Bucket scan results saved to {filename}")

# -------------------
# Main bucket scan function
# -------------------
def bucket_scan(domain):
    print(Fore.CYAN + f"\n[*] Scanning S3 buckets for target: {domain}")

    s3_query = (
        f'(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com '
        f'OR site:*.s3.dualstack.us-east-1.amazonaws.com '
        f'OR site:*.s3.ap-south-1.amazonaws.com) "{domain}"'
    )
    urls = serpapi_search(s3_query)

    s3_results = []
    if urls:
        print(Fore.GREEN + f"  [✓] Found {len(urls)} possible S3 URLs:")
        for url in urls:
            bucket, key = extract_bucket_and_key(url)
            if bucket:
                read = check_object_read(bucket, key) if key else False
                write = check_object_write(bucket)
                s3_results.append({
                    "url": url,
                    "bucket": bucket,
                    "key": key,
                    "read": read,
                    "write": write
                })

                # Print results nicely
                print(Fore.YELLOW + f"    Bucket: {bucket}")
                if key:
                    print(Fore.WHITE + f"      Key: {key}")
                print(Fore.GREEN + f"      Readable: {read}, Writable: {write}")
    else:
        print(Fore.RED + "  [!] No related S3 buckets found.")

    # Save results to central {target}_scan.json
    save_bucket_scan(domain, s3_results)

    # Final summary
    print(Fore.CYAN + f"[*] Bucket scan results saved to {domain}_scan.json")
    print(Fore.CYAN + f"[*] Bucket scan for {domain} completed.\n")
    return True

# -------------------
# Pipeline-compatible entry point
# -------------------
def process(domain):
    """
    Standard entry point for pipeline.
    Calls the main bucket_scan function.
    """
    return bucket_scan(domain)

# -------------------
# Example usage (for testing)
# -------------------
if __name__ == "__main__":
    target_domain = "cognizant.com"
    process(target_domain)

