#!/usr/bin/env python3
import socket
import json
from datetime import datetime
from colorama import Fore, init
import ipwhois
import boto3
from botocore.exceptions import ClientError

init(autoreset=True)

def whois_lookup(ip):
    """Perform WHOIS lookup using ipwhois library"""
    try:
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap()
        return {
            "ip": ip,
            "asn": results.get("asn"),
            "asn_cidr": results.get("asn_cidr"),
            "asn_description": results.get("asn_description"),
            "network": results.get("network", {}).get("cidr"),
            "country": results.get("network", {}).get("country"),
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def check_s3_bucket(bucket_name):
    """Check if S3 bucket is publicly readable/writable"""
    s3 = boto3.client("s3")
    result = {"bucket": bucket_name, "readable": False, "writable": False}

    # Check READ
    try:
        s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        result["readable"] = True
    except ClientError as e:
        if "AccessDenied" in str(e):
            result["readable"] = False

    # Check WRITE (try uploading a dummy object)
    try:
        test_key = "test_upload_bucket_recon.txt"
        s3.put_object(Bucket=bucket_name, Key=test_key, Body=b"security test")
        result["writable"] = True

        # cleanup
        s3.delete_object(Bucket=bucket_name, Key=test_key)
    except ClientError as e:
        if "AccessDenied" in str(e):
            result["writable"] = False

    return result


def process(domain):
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    timestamp = datetime.now().isoformat()
    results = {
        "module": "bucket",
        "target": domain,
        "timestamp": timestamp,
        "dns": [],
        "whois": [],
        "s3_buckets": [],
    }

    print(Fore.CYAN + f"\n[+] Bucket scan for {domain}")

    # Step 1: Resolve IPs
    try:
        ip_list = socket.gethostbyname_ex(domain)[2]
        results["dns"] = ip_list
        print(Fore.GREEN + f"[✓] Found {len(ip_list)} IP(s)")
        for ip in ip_list:
            print(f"    └─ {ip}")

            # Step 2: WHOIS & CIDR Info
            whois_data = whois_lookup(ip)
            results["whois"].append(whois_data)
    except Exception as e:
        print(Fore.RED + f"[!] DNS resolution error: {e}")

    # Step 3: S3 bucket guessing (dummy wordlist, expand later)
    s3_candidates = [
        "iemgroup", "imlive", "bentleydownloads", "higherlogicdownload",
        "becketnewsite", "nirmawebsite", "academicscourse"
    ]

    print(Fore.YELLOW + "[*] Searching for exposed S3 buckets...")
    for bucket in s3_candidates:
        bucket_result = check_s3_bucket(bucket)
        results["s3_buckets"].append(bucket_result)

        status = []
        if bucket_result["readable"]:
            status.append("READ")
        if bucket_result["writable"]:
            status.append("WRITE")

        status_str = " / ".join(status) if status else "No Access"
        print(Fore.GREEN + f"    └─ Bucket: {bucket} ({status_str})")

    # Save JSON
    with open(f"{safe_domain}_bucket.json", "w") as f:
        json.dump(results, f, indent=2)

    print(Fore.CYAN + f"[✓] Results saved to {safe_domain}_bucket.json\n")
    return results
