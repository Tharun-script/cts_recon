import subprocess
import re
import time
import requests
import json
from serpapi.google_search import GoogleSearch
from colorama import Fore, Style, init

# ==============================
# CONFIG
# ==============================
TOKENS = [
    "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",  # Token 1
    "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",  # Token 2
    "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"  # Token 3
]
token_index = 0

API_KEY = "882df33509cf14b58f1c79fdfda125f75b67795d7a49fabdd9dfcda4a32ac203"   # SerpAPI key

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"\+91[6-9]\d{9}"   # Indian numbers starting with +91

init(autoreset=True)

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
    '"{keyword}" access_token',
    '"{keyword}" private_key',
    '"{keyword}" username',
    '"{keyword}" password',
]

BASE_PATTERNS = {
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z-]{10,48})",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "Phone Number": PHONE_REGEX,
    "Username": r"(?:username|user|uname|usr)\s*[:=]\s*[\"']?([a-zA-Z0-9._-]{3,50})[\"']?",
    "Password": r"(?:password|passwd|pwd|pass)\s*[:=]\s*[\"']?([a-zA-Z0-9!@#$%^&*()_+=\-]{4,50})[\"']?",
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
        cmd = ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,yahoo,crtsh,threatcrowd,hackertarget,github-code"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        output = result.stdout + result.stderr
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        phones = re.findall(PHONE_REGEX, output)
        return set(emails), set(phones)

    except subprocess.TimeoutExpired as e:
        print(Fore.YELLOW + "[!] TheHarvester timed out after 120s. Showing partial results...")
        output = e.stdout.decode() if e.stdout else ""
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        phones = re.findall(PHONE_REGEX, output)
        return set(emails), set(phones)

    except Exception as e:
        print(Fore.RED + f"[!] TheHarvester error: {e}")
        return set(), set()

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

def extract_from_url(url, target_domain):
    try:
        if "pastebin.com/" in url and "/raw/" not in url:
            paste_id = url.split("/")[-1]
            raw_url = f"https://pastebin.com/raw/{paste_id}"
        else:
            raw_url = url

        response = requests.get(raw_url, timeout=10)
        if response.status_code != 200:
            return [], []

        content = response.text
        found_emails = re.findall(EMAIL_REGEX, content)
        found_phones = re.findall(PHONE_REGEX, content)

        domain_pattern = re.compile(rf"[a-zA-Z0-9._%+-]+@{re.escape(target_domain)}\b")
        emails = list(set(filter(domain_pattern.match, found_emails)))

        return emails, list(set(found_phones))
    except:
        return [], []

# ==============================
# CORE SCAN FUNCTION (Pipeline entry)
# ==============================
def process(domain: str):
    """Main function for pipeline integration"""
    keyword = domain.split(".")[0]

    all_emails = set()
    all_phones = set()
    all_usernames = set()
    all_passwords = set()
    found_secrets = []

    # 1. TheHarvester
    print(Fore.YELLOW + "[*] Running TheHarvester...")
    harvester_emails, harvester_phones = run_theharvester(domain)
    all_emails.update(harvester_emails)
    all_phones.update(harvester_phones)

    # 2. Pastebin
    print(Fore.YELLOW + "[*] Searching Pastebin...")
    pastebin_urls = serpapi_search(f'site:pastebin.com "{domain}"', num=15)
    for url in pastebin_urls:
        emails, phones = extract_from_url(url, domain)
        all_emails.update(emails)
        all_phones.update(phones)

    # 3. GitHub dorks
    print(Fore.YELLOW + "[*] Searchin*]()
