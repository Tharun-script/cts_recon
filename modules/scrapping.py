#!/usr/bin/env python3
import subprocess
import re
import time
import requests
import json
from serpapi.google_search import GoogleSearch
from colorama import Fore, Style, init

init(autoreset=True)

# ==============================
# CONFIG
# ==============================
TOKENS = [
    "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",
    "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",
    "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"
]
token_index = 0

API_KEY = "882df33509cf14b58f1c79fdfda125f75b67795d7a49fabdd9dfcda4a32ac203"  # SerpAPI key
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# ==============================
# Optional report module
# ==============================
try:
    from reconn import report
except ImportError:
    report = None

# ==============================
# GitHub Helpers
# ==============================
def get_headers():
    global token_index
    return {"Authorization": f"token {TOKENS[token_index]}"}

DORKS = [
    '"@{domain}" in:file',
    '"{keyword}" aws_access_key_id',
    '"{keyword}" aws_secret_access_key',
    '"{keyword}" api_key',
    '"{keyword}" password',
    '"{keyword}" access_token',
    '"{keyword}" private_key',
]

BASE_PATTERNS = {
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z-]{10,48})",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
}

def github_search(query, page=1, per_page=20):
    global token_index
    for _ in range(len(TOKENS) + 1):
        url = f"https://api.github.com/search/code?q={query}&page={page}&per_page={per_page}"
        response = requests.get(url, headers=get_headers())
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:  # rate limit
            token_index = (token_index + 1) % len(TOKENS)
            if token_index == 0:
                time.sleep(60)
        else:
            return None
    return None

def extract_patterns(content, domain=None):
    results = {}
    patterns = BASE_PATTERNS.copy()
    if domain:
        patterns["Email"] = rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}"

    for name, regex in patterns.items():
        matches = re.findall(regex, content)
        if matches:
            flat_matches = [m if isinstance(m, str) else m[0] for m in matches]
            results[name] = list(set(flat_matches))
    return results

# ==============================
# TheHarvester Integration
# ==============================
def run_theharvester(domain):
    try:
        cmd = ["theHarvester", "-d", domain, "-b", "all"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        return set(emails)
    except subprocess.TimeoutExpired as e:
        print(Fore.YELLOW + "[!] TheHarvester timed out after 120s. Showing partial results...")
        output = e.stdout.decode() if e.stdout else ""
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        return set(emails)
    except Exception as e:
        print(Fore.RED + f"[!] TheHarvester error: {e}")
        return set()

# ==============================
# Pastebin via SerpAPI
# ==============================
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

def extract_emails_from_url(url, target_domain):
    try:
        if "pastebin.com/" in url and "/raw/" not in url:
            paste_id = url.split("/")[-1]
            raw_url = f"https://pastebin.com/raw/{paste_id}"
        else:
            raw_url = url

        response = requests.get(raw_url, timeout=10)
        if response.status_code != 200:
            return []

        content = response.text
        found_emails = re.findall(EMAIL_REGEX, content)
        domain_pattern = re.compile(rf"[a-zA-Z0-9._%+-]+@{re.escape(target_domain)}\b")
        return list(set(filter(domain_pattern.match, found_emails)))
    except:
        return []

# ==============================
# Pipeline Entry Point
# ==============================
def process(domain, output_file=None):
    """Pipeline entry function"""
    keyword = domain.split(".")[0]
    all_emails = set()
    found_secrets = []

    print(Fore.YELLOW + f"[*] Running scraping module for {domain}")

    # 1. TheHarvester
    harvester_emails = run_theharvester(domain)
    all_emails.update(harvester_emails)

    # 2. Pastebin
    pastebin_urls = serpapi_search(f'site:pastebin.com "{domain}"', num=15)
    for url in pastebin_urls:
        emails = extract_emails_from_url(url, domain)
        all_emails.update(emails)

    # 3. GitHub dorks
    for dork in DORKS:
        query = dork.format(keyword=keyword, domain=domain)
        page = 1
        while True:
            results = github_search(query, page=page)
            if not results or "items" not in results or not results["items"]:
                break

            for item in results["items"]:
                file_url = item["html_url"]
                raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

                try:
                    file_content = requests.get(raw_url, headers=get_headers(), timeout=10).text
                    leaks = extract_patterns(file_content, domain)

                    for leak_type, values in leaks.items():
                        for v in values:
                            if leak_type == "Email":
                                all_emails.add(v)
                            else:
                                found_secrets.append({
                                    "type": leak_type,
                                    "value": v,
                                    "source_url": file_url
                                })
                except Exception as e:
                    print(Fore.RED + f"[!] Error fetching {file_url}: {e}")

            page += 1
            if page > 3:
                break

    # ==============================
    # Final output
    # ==============================
    output = {
        "domain": domain,
        "emails": sorted(list(all_emails)),
        "secrets": found_secrets
    }

    # Show results to user immediately
    print("\n=== Final Results ===\n")
    print(Fore.GREEN + f"[+] Found {len(output['emails'])} unique emails")
    for email in output["emails"]:
        print(email)

    if output["secrets"]:
        print(Fore.GREEN + f"\n[+] Found {len(output['secrets'])} secrets/tokens")
        for s in output["secrets"]:
            print(f"[{s['type']}] {s['value']}  -->  {s['source_url']}")

    # Save JSON
    if not output_file:
        output_file = f"scraping_{domain}.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)

    print(Fore.CYAN + f"\n[+] Scraping result2s saved to {output_file}")

    # Forward to report.py if available
    if report:
        try:
            report.save_report("scraping", output)
            print(Fore.CYAN + "[+] Scraping results forwarded to report.py")
        except Exception as e:
            print(Fore.RED + f"[!] Error saving report: {e}")

    return Fore.GREEN + f"Success"

# ==============================
# Standalone Execution (optional)
# ==============================
if __name__ == "__main__":
    domain_input = input(Fore.CYAN + "Enter target domain (e.g., example.com): " + Style.RESET_ALL).strip()
    process(domain_input)
