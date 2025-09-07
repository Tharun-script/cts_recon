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
    ghp   # Token 3
]
token_index = 0

API_KEY = "882df33509cf14b58f1c79fdfda125f75b67795d7a49fabdd9dfcda4a32ac203"

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"\+91[-\s]?\d{10}"   # strict Indian mobile format

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
    '"{keyword}" username',
]

BASE_PATTERNS = {
    "Github Token": r"(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}",
    "AWS Access ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "Username": r"(?:username|user|uname|usr)[\'\"\s:=]{0,6}([a-zA-Z][a-zA-Z0-9_]{5,14})",
    "Password": r"(?i)(?:password|passwd|pwd)[\'\"\s:=]{0,6}([A-Za-z][A-Za-z0-9_@#$%^&*]{5,14})"
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
                print(Fore.YELLOW + "[!] GitHub rate limit reached, sleeping 60s...")
                time.sleep(60)
        else:
            return None
    return None

def extract_patterns(content, domain=None):
    results = {}
    patterns = BASE_PATTERNS.copy()
    if domain:
        patterns["Email"] = rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}"
        patterns["Phone"] = PHONE_REGEX

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
        cmd = ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,yahoo,crtsh,threatcrowd,hackertarget,github-code"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        output = result.stdout + result.stderr
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        return set(emails)
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[!] TheHarvester timed out after 120s.")
        return set()
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
    return [res.get("link") for res in results.get("organic_results", []) if res.get("link")]

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
# Pretty Print Helper
# ==============================
def pretty_print(result):
    print("\n" + Fore.CYAN + "="*50)
    print(Fore.CYAN + f" Scan Results for: {result['domain']} ")
    print(Fore.CYAN + "="*50 + "\n")

    def section(title, items, color=Fore.GREEN, kind=None):
        if not items:
            return
        print(color + f"[+] {title} ({len(items)})")
        for i, item in enumerate(items, 1):
            if isinstance(item, dict):
                if kind == "passwords":
                    print(f"   {i}. {item['password']}  {Fore.YELLOW}(source: {item['source']})")
                elif kind == "secrets":
                    print(f"   {i}. {item['type']}: {item['value']}  {Fore.YELLOW}(source: {item['source']})")
            else:
                print(f"   {i}. {item}")
        print()

    section("Emails", result["emails"])
    section("Phones", result["phones"])
    section("Usernames", result["usernames"])
    section("Passwords", result["passwords"], kind="passwords")
    section("Secrets / Tokens", result["secrets"], kind="secrets")

    print(Fore.CYAN + "="*50 + "\n")

# ==============================
# Pipeline Entry Point
# ==============================
def process(domain: str):
    keyword = domain.split(".")[0]
    all_emails, all_phones, usernames = set(), set(), set()
    passwords, found_secrets = [], []

    # 1. TheHarvester
    print(Fore.YELLOW + "[*] Running TheHarvester...")
    all_emails.update(run_theharvester(domain))

    # 2. Pastebin
    print(Fore.YELLOW + "[*] Searching Pastebin...")
    pastebin_urls = serpapi_search(f'site:pastebin.com "{domain}"', num=15)
    for url in pastebin_urls:
        all_emails.update(extract_emails_from_url(url, domain))

    # 3. GitHub Dorks
    print(Fore.YELLOW + "[*] Searching GitHub...")
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
                            elif leak_type == "Phone":
                                all_phones.add(v)
                            elif leak_type == "Username":
                                usernames.add(v)
                            elif leak_type == "Password":
                                passwords.append({"password": v, "source": file_url})
                            else:
                                found_secrets.append({"type": leak_type, "value": v, "source": file_url})
                except Exception as e:
                    print(Fore.RED + f"[!] Error fetching {file_url}: {e}")
            page += 1
            if page > 3:
                break

    # Build result
    result = {
        "domain": domain,
        "emails": sorted(list(all_emails)),
        "phones": sorted(list(all_phones)),
        "usernames": sorted(list(usernames)),
        "passwords": passwords,
        "secrets": found_secrets,
    }

    # Save to <domain>_scan.json
    filename = f"{domain}_scan.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

    pretty_print(result)
    print(Fore.CYAN + f"[+] Results saved to {filename}")

    return result



