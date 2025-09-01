#!/usr/bin/env python3
import subprocess
import re
import json
import requests
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, init
from serpapi import GoogleSearch
from bs4 import BeautifulSoup
import boto3
from botocore.exceptions import ClientError

init(autoreset=True)

# Import report.py
try:
    from reconn import report
except ImportError:
    report = None

# === CONFIG ===
API_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"
SUSPICIOUS_KEYWORDS = ["login","secure","account","update","verify","signin","bank","payment"]

# -------------------
# DNS + WHOIS
# -------------------
def get_dns_records(domain):
    print(Fore.CYAN + "[+] Scanning DNS records...")
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "A"],
            capture_output=True, text=True, check=True
        )
        ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        print(Fore.GREEN + f"[✓] DNS scan completed: {len(ips)} IP(s) found")
        for ip in ips:
            print(Fore.YELLOW + f"    - {ip}")
        return ips
    except Exception as e:
        print(Fore.RED + f"[!] DNS scan failed: {e}")
        return []

def get_whois_info(ip):
    print(Fore.CYAN + f"[+] Performing WHOIS lookup for {ip}...")
    info = []
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if re.search(r"NetRange|CIDR|route", line, re.IGNORECASE):
                info.append(line.strip())
        print(Fore.GREEN + f"[✓] WHOIS lookup completed: {len(info)} entries found")
        for entry in info:
            print(Fore.YELLOW + f"    - {entry}")
    except Exception as e:
        info.append(f"WHOIS lookup failed: {e}")
        print(Fore.RED + f"[!] WHOIS lookup failed for {ip}: {e}")
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
    print(Fore.CYAN + "[+] Searching S3 buckets on Google...")
    params = {"engine":"google","q":query,"hl":"en","num":num,"api_key":API_KEY}
    search = GoogleSearch(params)
    results = search.get_dict()
    urls = []
    for res in results.get("organic_results", []):
        link = res.get("link")
        if link:
            urls.append(link)
    print(Fore.GREEN + f"[✓] Found {len(urls)} potential S3 URLs")
    for url in urls:
        print(Fore.YELLOW + f"    - {url}")
    return urls

# -------------------
# Phishing Checks
# -------------------
def normalize_domain(domain):
    if not domain.startswith("http"):
        return "https://" + domain
    return domain

def check_domain_keywords(url):
    domain = urlparse(url).netloc.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            return {"warning": f"Suspicious keyword: {keyword}"}
    return {"status": "No phishing keywords detected"}

def check_clickjacking_headers(response):
    headers = response.headers
    xfo = headers.get("X-Frame-Options","")
    csp = headers.get("Content-Security-Policy","")
    if "deny" in xfo.lower() or "sameorigin" in xfo.lower() or "frame-ancestors" in csp.lower():
        return {"status":"Clickjacking protection present"}
    return {"warning":"Clickjacking protection missing"}

def check_iframes(response):
    try:
        soup = BeautifulSoup(response.text,"html.parser")
        iframes = soup.find_all("iframe")
        if iframes:
            return {"warning":f"Found {len(iframes)} iframe(s)"}
        return {"status":"No iframes found"}
    except Exception as e:
        return {"error": str(e)}

def check_open_redirect(url):
    parsed = urlparse(url)
    for param in ["redirect","url","next","return"]:
        if param in parsed.query:
            return {"warning": f"Possible open redirect via {param}"}
    return {"status":"No open redirect"}

def check_credential_harvesting(response):
    try:
        soup = BeautifulSoup(response.text,"html.parser")
        if soup.find("input",{"type":"password"}):
            return {"warning":"Possible credential harvesting form detected"}
    except Exception as e:
        return {"error": str(e)}
    return {"status":"No password fields detected"}

# -------------------
# Main process
# -------------------
def process(domain):
    print(Fore.YELLOW + f"[+] Starting bucket scan for {domain}")
    results = {"target": domain, "timestamp": datetime.now().isoformat()}

    # DNS + WHOIS
    ips = get_dns_records(domain)
    results["dns"] = []
    for ip in ips:
        whois_info = get_whois_info(ip)
        results["dns"].append({"ip": ip, "whois": whois_info})

    # S3 Buckets
    s3_query =  f'(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com OR site:*.s3.dualstack.us-east-1.amazonaws.com OR site:*.s3.ap-south-1.amazonaws.com) "{domain}"'
    urls = serpapi_search(s3_query)
    s3_results = []
    for url in urls:
        bucket, key = extract_bucket_and_key(url)
        if bucket:
            read = check_object_read(bucket, key) if key else False
            write = check_object_write(bucket)
            s3_results.append({"url": url, "bucket": bucket, "key": key, "read": read, "write": write})
            print(Fore.YELLOW + f"    - Bucket: {bucket}, Read: {read}, Write: {write}")
    results["s3_buckets"] = s3_results

    # Phishing
    print(Fore.CYAN + "[+] Starting phishing checks...")
    url = normalize_domain(domain)
    try:
        response = requests.get(url, timeout=10)
        phishing_results = {
            "http_status": response.status_code,
            "domain_keywords": check_domain_keywords(url),
            "clickjacking": check_clickjacking_headers(response),
            "iframes": check_iframes(response),
            "open_redirect": check_open_redirect(url),
            "credential_harvesting": check_credential_harvesting(response),
        }
        results["phishing"] = phishing_results
        # Print summary
        print(Fore.GREEN + f"[✓] Phishing checks completed: HTTP {response.status_code}")
        for k,v in phishing_results.items():
            print(Fore.YELLOW + f"    - {k}: {v}")
    except Exception as e:
        results["phishing"] = {"error": str(e)}
        print(Fore.RED + f"[!] Phishing checks failed: {e}")

    # Save report
    if report:
        report.save_report("bucket", results)

    print(Fore.MAGENTA + f"[+] Bucket scan finished for {domain}")
    return Fore.GREEN + f"success"