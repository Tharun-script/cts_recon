import subprocess, requests, json, re
from colorama import Fore, Style, init
from serpapi.google_search import GoogleSearch

init(autoreset=True)

API_KEY = "YOUR_SERPAPI_KEY"
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

def run_theharvester(domain):
    try:
        cmd = ["theHarvester", "-d", domain, "-b", "all"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", r.stdout + r.stderr)
    except:
        return []

def serpapi_search(query, num=10):
    params = {"engine": "google", "q": query, "num": num, "api_key": API_KEY}
    return [r.get("link") for r in GoogleSearch(params).get_dict().get("organic_results", []) if r.get("link")]

def extract_emails(url, domain):
    try:
        r = requests.get(url, timeout=10)
        return list({e for e in re.findall(EMAIL_REGEX, r.text) if e.endswith(domain)})
    except:
        return []

def process(domain, reports_dir):
    print(Fore.YELLOW + f"\n[+] Running scraping module for {domain}" + Style.RESET_ALL)
    emails = set(run_theharvester(domain))
    for url in serpapi_search(f'site:pastebin.com "{domain}"'):
        emails.update(extract_emails(url, domain))
    results = {"module": "scraping", "target": domain, "emails": sorted(emails)}
    path = f"{reports_dir}/scraping.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(Fore.GREEN + f"[✓] scraping results saved → {path}" + Style.RESET_ALL)
