#!/usr/bin/env python3
import os
from urllib.parse import urlparse
from datetime import datetime
from serpapi import GoogleSearch
import boto3
from botocore.exceptions import ClientError
from colorama import Fore, Style, init
import json

# Initialize colorama
init(autoreset=True)

# === CONFIG ===
API_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"

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

# -------------------
# SerpAPI search
# -------------------
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
# Save results
# -------------------
def save_bucket_scan(target, s3_results):
    """Append bucket scan results to {target}_scan.json"""
    filename = f"{target}_scan.json"
    # Load existing scan results
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

    # Write back to the same file
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(Fore.CYAN + f"  [*] Bucket scan results saved to {filename}")

# -------------------
# Main bucket scan
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

                # Print results
                print(Fore.YELLOW + f"    Bucket: {bucket}")
                if key:
                    print(Fore.WHITE + f"      Key: {key}")
                print(Fore.GREEN + f"      Readable: {read}, Writable: {write}")
    else:
        print(Fore.RED + "  [!] No related S3 buckets found.")

    # Save results
    save_bucket_scan(domain, s3_results)
    print(Fore.CYAN + f"[*] Bucket scan for {domain} completed.\n")
    return s3_results  # <-- returns full extracted info

# -------------------
# Entry point
# -------------------
if __name__ == "__main__":
    target_domain = "evil.com"
    results = bucket_scan(target_domain)
    print(Fore.CYAN + f"\n[*] Scan completed. Total buckets found: {len(results)}")
