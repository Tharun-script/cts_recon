#!/usr/bin/env python3
"""
Scraping Module
---------------
Finds emails and secrets from:
 - TheHarvester
 - Pastebin (via SerpAPI)
 - GitHub dorks

Output JSON schema:
{
  "module": "scraping",
  "domain": "<target>",
  "emails": [...],
  "secrets": [
    {"type": "Secret Type", "value": "...", "source_url": "..."}
  ]
}
"""

import subprocess
import re
import time
import requests
from serpapi.google_search import GoogleSearch
from colorama import Fore, init

init(autoreset=True)

# ======================
# Config
# ======================
TOKENS = [ "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", "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", "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" ] 
token_index = 0 
API_KEY = "882df33509cf14b58f1c79fdfda125f75b67795d7a49fabdd9dfcda4a32ac203" 
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

DORKS = [
    '"@{domain}" in:file',
    '"{keyword}" aws_access_key_id',
    '"{keyword}" aws_secret_access_key',
    '"{keyword}" api_key',
    '"{keyword}" password',
    '"{keyword}" access_token',
    '"{keyword}" private_key',
]

PATTERNS = {
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z-]{10,48})",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
}


# ======================
# Helpers
# ======================
def get_headers():
    global token_index
    return {"Authorization": f"token {TOKENS[token_index]}"}


def github_search(query, page=1, per_page=20):
    """Search GitHub code with rotation on tokens if rate-limited."""
    global token_index
    for _ in range(len(TOKENS) + 1):
        url = f"https://api.github.com/search/code?q={query}&page={page}&per_page={per_page}"
        resp = requests.get(url, headers=get_headers())
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403:  # rate limited
            token_index = (token_index + 1) % len(TOKENS)
            if token_index == 0:
                print(Fore.YELLOW + "[!] GitHub rate limit reached. Waiting 60s...")
                time.sleep(60)
        else:
            return None
    return None


def extract_patterns(content, domain=None):
    """Run regexes against content to extract leaks & emails."""
    results = {}
    patterns = PATTERNS.copy()
    if domain:
        patterns["Email"] = rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}"

    for name, regex in patterns.items():
        matches = re.findall(regex, content)
        if matches:
            flat_matches = [m if isinstance(m, str) else m[0] for m in matches]
            results[name] = list(set(flat_matches))
    return results


def run_theharvester(domain):
    """Run theHarvester to collect emails."""
    try:
        print(Fore.CYAN + "[*] Running TheHarvester...")
        cmd = ["theHarvester", "-d", domain, "-b", "all"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        return set(re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output))
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[!] TheHarvester timed out after 120s.")
        return set()
    except Exception as e:
        print(Fore.RED + f"[!] TheHarvester error: {e}")
        return set()


def serpapi_search(query, num=10):
    """Search Pastebin dumps with SerpAPI."""
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    search = GoogleSearch(params)
    results = search.get_dict()
    return [r.get("link") for r in results.get("organic_results", []) if r.get("link")]


def extract_emails_from_url(url, target_domain):
    """Fetch URL and pull emails for domain."""
    try:
        if "pastebin.com/" in url and "/raw/" not in url:
            paste_id = url.split("/")[-1]
            url = f"https://pastebin.com/raw/{paste_id}"

        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []

        content = resp.text
        found = re.findall(EMAIL_REGEX, content)
        return list({e for e in found if e.endswith("@" + target_domain)})
    except:
        return []


# ======================
# Main Module Function
# ======================
def process(domain):
    """Main entry for scraping module."""
    keyword = domain.split(".")[0]
    all_emails, found_secrets = set(), []

    print(Fore.YELLOW + f"[*] Starting scraping for {domain}")

    # 1. theHarvester
    all_emails.update(run_theharvester(domain))

    # 2. Pastebin
    print(Fore.CYAN + "[*] Searching Pastebin via Google...")
    for url in serpapi_search(f'site:pastebin.com "{domain}"', num=15):
        all_emails.update(extract_emails_from_url(url, domain))

    # 3. GitHub Dorks
    print(Fore.CYAN + "[*] Running GitHub dorks...")
    for dork in DORKS:
        query = dork.format(keyword=keyword, domain=domain)
        page = 1
        while True:
            results = github_search(query, page=page)
            if not results or not results.get("items"):
                break

            for item in results["items"]:
                file_url = item["html_url"]
                raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                try:
                    content = requests.get(raw_url, headers=get_headers(), timeout=10).text
                    leaks = extract_patterns(content, domain)
                    for leak_type, values in leaks.items():
                        for v in values:
                            if leak_type == "Email":
                                all_emails.add(v)
                            else:
                                found_secrets.append({"type": leak_type, "value": v, "source_url": file_url})
                except Exception as e:
                    print(Fore.RED + f"[!] Error fetching {file_url}: {e}")

            page += 1
            if page > 3:
                break

    # Final structured output
    return {
        "module": "scraping",
        "domain": domain,
        "emails": sorted(all_emails),
        "secrets": found_secrets,
    }
