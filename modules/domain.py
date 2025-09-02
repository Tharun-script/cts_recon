import subprocess
import requests
import time
import json
import os
from colorama import Fore, Style, init

init(autoreset=True)


def run_subfinder(domain):
    try:
        print(Fore.CYAN + "\n[*] Running Subfinder..." + Style.RESET_ALL)
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, check=False
        )
        return result.stdout.splitlines()
    except Exception as e:
        print(Fore.RED + f"[!] Subfinder error: {e}" + Style.RESET_ALL)
        return []


def fetch_crtsh(domain, retries=3, delay=5):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = []
    for attempt in range(1, retries + 1):
        try:
            print(Fore.CYAN + f"[*] crt.sh attempt {attempt}" + Style.RESET_ALL)
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                subs = [entry["name_value"] for entry in data if "name_value" in entry]
                break
        except Exception as e:
            print(Fore.YELLOW + f"[!] crt.sh error: {e}, retrying..." + Style.RESET_ALL)
            time.sleep(delay)
    return subs


def probe_alive(subdomains):
    try:
        result = subprocess.run(
            ["httpx", "-silent"],
            input="\n".join(subdomains),
            capture_output=True, text=True
        )
        return result.stdout.splitlines()
    except Exception:
        return []


def run_tech_scans(alive_domains):
    try:
        result = subprocess.run(
            ["httpx", "-silent", "-tech-detect"],
            input="\n".join(alive_domains),
            capture_output=True, text=True
        )
        lines = result.stdout.splitlines()
        out = []
        for line in lines:
            parts = line.split(" [")
            domain = parts[0].strip()
            techs = parts[1].replace("]", "").split(", ") if len(parts) > 1 else []
            out.append({"domain": domain, "tech": techs})
        return out
    except Exception:
        return []


def process(domain):
    """Main standardized process for domain module"""
    print(Fore.YELLOW + f"\n[+] Running domain module for {domain}" + Style.RESET_ALL)

    subs = set(run_subfinder(domain) + fetch_crtsh(domain))
    alive = probe_alive(list(subs))
    tech = run_tech_scans(alive)

    findings = {
        "domains": [domain],
        "subdomains": list(subs),
        "ips": [],
        "emails": [],
        "alive": alive,
        "technologies": tech
    }

    out_file = f"{domain}_domain.json"
    with open(out_file, "w") as f:
        json.dump({"module": "domain", "findings": findings}, f, indent=2)

    print(Fore.GREEN + f"[✓] domain results saved to {out_file}" + Style.RESET_ALL)
    return findings
