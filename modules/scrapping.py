#!/usr/bin/env python3
import subprocess
import re
import time
import json
import requests
from serpapi.google_search import GoogleSearch
from colorama import Fore, init

init(autoreset=True)

TOKENS = [
    "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",
    "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",
    "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"
]
token_index = 0

API_KEY = "882df33509cf14b58f1c79fdfda125f75b67795d7a49fabdd9dfcda4a32ac203"
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"



DORKS = [
    '"@{domain}" in:file',
    '"{keyword}" aws_access_key_id',
    '"{keyword}" password',
    '"{keyword}" api_key',
]

PATTERNS = {
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
}


def get_headers():
    global token_index
    return {"Authorization": f"token {TOKENS[token_index]}"}


def github_search(query, page=1, per_page=20):
    global token_index
    for _ in range(len(TOKENS)):
        url = f"https://api.github.com/search/code?q={query}&page={page}&per_page={per_page}"
        r = requests.get(url, headers=get_headers())
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 403:  # rate limit
            token_index = (token_index + 1) % len(TOKENS)
            time.sleep(5)
    return None


def extract_patterns(content, domain=None):
    results = {}
    patterns = PATTERNS.copy()
    if domain:
        patterns["Email"] = rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}"
    for name, regex in patterns.items():
        matches = re.findall(regex, content)
        if matches:
            flat = [m if isinstance(m, str) else m[0] for m in matches]
            results[name] = list(set(flat))
    return results


def run_theharvester(domain):
    try:
        cmd = ["theHarvester", "-d", domain, "-b", "all"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return set(re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", r.stdout + r.stderr))
    except Exception:
        return set()


def serpapi_search(query, num=10):
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    return [r.get("link") for r in GoogleSearch(params).get_dict().get("organic_results", [])
            if r.get("link")]


def extract_emails_from_url(url, domain):
    try:
        if "pastebin.com/" in url and "/raw/" not in url:
            url = f"https://pastebin.com/raw/{url.split('/')[-1]}"
        r = requests.get(url, timeout=10)
        return list({e for e in re.findall(EMAIL_REGEX, r.text) if e.endswith("@" + domain)})
    except:
        return []


def process(domain, safe_domain):
    print(Fore.YELLOW + f"\n[+] Scraping {domain}")
    keyword = domain.split(".")[0]
    emails, secrets = set(), []

    # theHarvester
    emails.update(run_theharvester(domain))

    # Pastebin
    for url in serpapi_search(f'site:pastebin.com "{domain}"'):
        emails.update(extract_emails_from_url(url, domain))

    # GitHub dorks
    for dork in DORKS:
        query = dork.format(keyword=keyword, domain=domain)
        for page in range(1, 3):
            results = github_search(query, page=page)
            if not results or not results.get("items"):
                break
            for item in results["items"]:
                file_url = item["html_url"]
                raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                try:
                    content = requests.get(raw_url, headers=get_headers(), timeout=10).text
                    leaks = extract_patterns(content, domain)
                    for leak_type, vals in leaks.items():
                        for v in vals:
                            if leak_type == "Email":
                                emails.add(v)
                            else:
                                secrets.append({"type": leak_type, "value": v, "source": file_url})
                except:
                    continue

    results = {"module": "scraping", "target": domain, "emails": sorted(emails), "secrets": secrets}

    with open(f"{safe_domain}_scraping.json", "w") as f:
        json.dump(results, f, indent=2)

    print(Fore.CYAN + f"[✓] Scraping completed, results saved.\n")
    return results

