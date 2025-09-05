import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urlparse
from colorama import Fore, Style, init
import urllib3
from serpapi import GoogleSearch
import json
import os

# -------------------------
# Initialize
# -------------------------
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# Config
# -------------------------
SERPAPI_KEY = "2b19c67a0c195af60bec0829621249eb402eb18bc56464d6b641c780ef01af2c"

SOCIAL_DOMAINS = [
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
    "youtube.com", "tiktok.com", "pinterest.com", "snapchat.com", "reddit.com",
    "discord.com", "t.me", "whatsapp.com", "wechat.com", "line.me",
    "vk.com", "ok.ru", "tumblr.com", "flickr.com", "medium.com",
    "blogger.com", "blogspot.com", "wordpress.com",
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "stackexchange.com", "stackoverflow.com", "dev.to",
    "glassdoor.com", "indeed.com", "angel.co", "producthunt.com",
    "trustpilot.com", "g2.com", "crunchbase.com", "goodfirms.co", "clutch.co",
    "quora.com", "douyin.com", "bilibili.com", "weibo.com",
    "kakao.com", "naver.com", "mix.com"
]

NOT_FOUND_PATTERNS = {
    "instagram.com": ["Sorry, this page isn't available."],
    "twitter.com": ["This account doesn’t exist", "page doesn’t exist"],
    "x.com": ["This account doesn’t exist", "page doesn’t exist"],
    "youtube.com": ["This page isn’t available", "404 Not Found"],
    "linkedin.com": ["Profile Not Found", "page doesn’t exist"],
    "github.com": ["Not Found"],
    "gitlab.com": ["404"],
    "bitbucket.org": ["Page not found"],
    "reddit.com": ["page not found"],
    "tiktok.com": ["Couldn't find this account", "page not available"],
    "pinterest.com": ["Page not found"],
    "snapchat.com": ["Page not found"],
    "medium.com": ["404"],
    "wordpress.com": ["doesn’t exist"],
    "blogspot.com": ["Blog has been removed"],
    "blogger.com": ["Blog has been removed"],
    "discord.com": ["Invite Invalid", "This invite may be expired"],
    "flickr.com": ["404 Not Found"],
    "tumblr.com": ["There's nothing here"],
    "vk.com": ["Page not found"],
    "ok.ru": ["Page not found"],
    "quora.com": ["Page not found"],
    "stackoverflow.com": ["Page Not Found"],
    "stackexchange.com": ["Page Not Found"],
    "dev.to": ["404"],
    "angel.co": ["404"],
    "producthunt.com": ["Page not found"],
    "trustpilot.com": ["Page not found"],
    "g2.com": ["Page not found"],
    "crunchbase.com": ["404"],
    "goodfirms.co": ["404"],
    "clutch.co": ["404"],
    "douyin.com": ["Page not found"],
    "bilibili.com": ["404"],
    "weibo.com": ["does not exist"],
    "kakao.com": ["404"],
    "naver.com": ["not exist"],
    "mix.com": ["Page not found"]
}

# -------------------------
# Utility functions
# -------------------------
def normalize_domain(domain):
    if not domain.startswith(("http://", "https://")):
        return "https://" + domain.strip()
    return domain.strip()

def domain_resolves(domain):
    try:
        hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def extract_links(domain):
    try:
        r = requests.get(domain, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        return [a['href'] for a in soup.find_all('a', href=True)]
    except Exception as e:
        print(Fore.YELLOW + f"  [!] Error fetching {domain}: {e}")
        return []

def check_social_link(link):
    for social in SOCIAL_DOMAINS:
        if social in link:
            try:
                r = requests.get(link, allow_redirects=True, timeout=10, verify=False)
                if r.status_code == 404:
                    return {"link": link, "status": "DEAD (404)"}
                if social in NOT_FOUND_PATTERNS:
                    for pattern in NOT_FOUND_PATTERNS[social]:
                        if pattern.lower() in r.text.lower():
                            return {"link": link, "status": f"DEAD ({pattern})"}
                return {"link": link, "status": "ALIVE"}
            except Exception:
                return {"link": link, "status": "ERROR (Connection failed)"}
    return None

def search_endpoints(domain, num_results=10):
    query = f'site:{domain} inurl:login OR inurl:register OR inurl:admin'
    params = {"engine": "google", "q": query, "num": num_results, "api_key": SERPAPI_KEY}

    search = GoogleSearch(params)
    results = []
    try:
        data = search.get_dict()
        if "organic_results" in data:
            for r in data["organic_results"]:
                link = r.get("link")
                if link:
                    results.append(link)
    except Exception:
        print(Fore.RED + "[!] SerpAPI search failed, skipping endpoint discovery")
    return results

def check_clickjacking(domain):
    endpoints = search_endpoints(domain)
    if not endpoints:
        endpoints = [normalize_domain(domain) + "/login", normalize_domain(domain) + "/register"]

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.0.0 Safari/537.36"
    }

    results = []
    for url in endpoints:
        url = normalize_domain(url) if not urlparse(url).scheme else url
        try:
            resp = requests.get(url, timeout=15, allow_redirects=True, headers=HEADERS, verify=False)
            if 200 <= resp.status_code < 400:
                xfo = resp.headers.get("X-Frame-Options", "")
                csp = resp.headers.get("Content-Security-Policy", "")
                if xfo or "frame-ancestors" in csp.lower():
                    results.append({"url": url, "status": "SAFE"})
                    print(f"[✓] {Fore.BLUE}{url}{Style.RESET_ALL} → {Fore.GREEN}SAFE (Clickjacking protection){Style.RESET_ALL}")
                else:
                    results.append({"url": url, "status": "VULNERABLE"})
                    print(f"[!] {Fore.BLUE}{url}{Style.RESET_ALL} → {Fore.RED}VULNERABLE (No protection){Style.RESET_ALL}")
            else:
                results.append({"url": url, "status": f"HTTP {resp.status_code}"})
                print(Fore.YELLOW + f"[!] {url} → HTTP {resp.status_code}")
        except Exception:
            results.append({"url": url, "status": "ERROR"})
            print(Fore.YELLOW + f"[!] {url} → Could not connect / skipped")
    return results

# -------------------------
# Pipeline Module
# -------------------------
def process(domain: str):
    domain = normalize_domain(domain)
    print(Fore.MAGENTA + f"\n[+] Scanning {domain}")

    if not domain_resolves(domain):
        print(Fore.RED + f"  [!] Cannot resolve {domain}, skipping...")
        return None

    # Social links
    links = extract_links(domain)
    social_results = []
    for link in links:
        res = check_social_link(link)
        if res:
            social_results.append(res)

    # CLI output
    if not social_results:
        print(Fore.YELLOW + f"  [✓] No social links found for {domain}")
    else:
        for r in social_results:
            color = Fore.GREEN if "ALIVE" in r["status"] else Fore.RED if "DEAD" in r["status"] else Fore.YELLOW
            print("  " + color + f"{r['link']} → {r['status']}")

    # Clickjacking
    print(Fore.CYAN + "\n[+] Checking clickjacking protections...")
    cj_results = check_clickjacking(domain)

    # Build result dict
    result = {
        "domain": domain,
        "social_links": social_results,
        "clickjacking": cj_results,
    }

    # Save to <domain>_scan.json
    filename = f"{domain.replace('https://', '').replace('http://', '').split('/')[0]}_scan.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

    print(Fore.CYAN + f"\n[+] Results saved to {filename}")
    return result

# -------------------------
# Entry
# -------------------------
def main():
    domains = input("Enter domains and subdomains (comma-separated): ").split(",")
    for d in domains:
        process(d.strip())

if __name__ == "__main__":
    main()
