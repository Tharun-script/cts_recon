import socket, json
from datetime import datetime
from colorama import Fore, Style, init
import ipwhois
import boto3
from botocore.exceptions import ClientError

init(autoreset=True)

def whois_lookup(ip):
    try:
        obj = ipwhois.IPWhois(ip)
        res = obj.lookup_rdap()
        return {
            "ip": ip,
            "asn": res.get("asn"),
            "asn_cidr": res.get("asn_cidr"),
            "asn_desc": res.get("asn_description"),
            "network": res.get("network", {}).get("cidr"),
            "country": res.get("network", {}).get("country")
        }
    except:
        return {"ip": ip, "error": "WHOIS failed"}

def check_s3(bucket):
    s3 = boto3.client("s3")
    result = {"bucket": bucket, "readable": False, "writable": False}
    try:
        s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
        result["readable"] = True
    except ClientError:
        result["readable"] = False
    try:
        key = "test_upload.txt"
        s3.put_object(Bucket=bucket, Key=key, Body=b"test")
        result["writable"] = True
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError:
        result["writable"] = False
    return result

def process(domain, reports_dir):
    print(Fore.YELLOW + f"\n[+] Running bucket module for {domain}" + Style.RESET_ALL)
    results = {"module": "bucket", "target": domain, "dns": [], "whois": [], "s3": []}
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        results["dns"] = ips
        for ip in ips:
            results["whois"].append(whois_lookup(ip))
    except:
        pass
    buckets = ["samplebucket1", "samplebucket2"]  # Replace with real guesses
    for b in buckets:
        results["s3"].append(check_s3(b))
    path = f"{reports_dir}/bucket.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(Fore.GREEN + f"[✓] bucket results saved → {path}" + Style.RESET_ALL)
