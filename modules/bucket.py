#!/usr/bin/env python3
import subprocess
import re
import json
import os
from urllib.parse import urlparse
from datetime import datetime
from serpapi import GoogleSearch
import boto3
from botocore.exceptions import ClientError
from colorama import Fore, Style, init

init(autoreset=True)

# === CONFIG ===
API_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"


    
# -------------------
# DNS + WHOIS
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
# Main process
# -------------------
def process(domain):
    timestamp = datetime.now().isoformat()

    print(Fore.CYAN + f"[*] Scanning target {domain}...")

    # ---------------- DNS ----------------
    print(Fore.CYAN + f"    [*] Resolving DNS records for {domain}...")
    ips = get_dns_records(domain)
    dns_report = {"target": domain, "timestamp": timestamp, "ips": ips}
    write_json(domain, "dns", "scan", dns_report)

    if ips:
        print(Fore.GREEN + f"    [✓] Found {len(ips)} IP(s):")
        for ip in ips:
            print(Fore.YELLOW + f"       └─ {ip}")
    else:
        print(Fore.RED + "    [!] No DNS A records found.")

    # ---------------- WHOIS ----------------
    whois_results = []
    for ip in ips:
        whois_info = get_whois_info(ip)
        whois_results.append({"ip": ip, "whois": whois_info})
        if whois_info:
            print(Fore.MAGENTA + f"       WHOIS for {ip}: {', '.join(whois_info[:3])}...")
    whois_report = {"target": domain, "timestamp": timestamp, "whois": whois_results}
    write_json(domain, "whois", "scan", whois_report)

    # ---------------- S3 Buckets ----------------
    print(Fore.CYAN + f"    [*] Searching for S3 buckets mentioning {domain}...")
    s3_query = (
        f'(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com '
        f'OR site:*.s3.dualstack.us-east-1.amazonaws.com '
        f'OR site:*.s3.ap-south-1.amazonaws.com) "{domain}"'
    )
    urls = serpapi_search(s3_query)

    s3_results = []
    if urls:
        print(Fore.GREEN + f"    [✓] Found {len(urls)} possible S3 URLs:")
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

                print(Fore.YELLOW + f"       └─ Bucket: {bucket}")
                if key:
                    print(Fore.WHITE + f"          Key: {key}")
                print(Fore.GREEN + f"          Readable: {read}, Writable: {write}")
    else:
        print(Fore.RED + "    [!] No related S3 buckets found.")

    s3_report = {"target": domain, "timestamp": timestamp, "s3_buckets": s3_results}
    write_json(domain, "bucket", "scan", s3_report)

    print(Fore.CYAN + f"\n[*] Scanning for {domain} completed.\n")
    return True

