#!/usr/bin/env python3
import subprocess
import requests
import json
import tempfile
from colorama import Fore, Style, init

init(autoreset=True)


def run_subfinder(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return set(result.stdout.splitlines())
    except Exception as e:
        print(Fore.RED + f"[!] Error running subfinder: {e}")
        return set()


def run_crtsh(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value")
                if name:
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if "*" not in sub:
                            subdomains.add(sub)
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching crt.sh: {e}")
    return subdomains


def probe_alive(subdomains):
    alive = []
    if not subdomains:
        return alive
    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as f:
            f.write("\n".join(subdomains))
            f.flush()
            result = subprocess.run(
                ["httpx", "-silent", "-list", f.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            alive = result.stdout.splitlines()
    except Exception as e:
        print(Fore.RED + f"[!] Error probing alive domains: {e}")
    return alive


def run_tech_scans(alive_subdomains):
    results = []
    if not alive_subdomains:
        alive_subdomains = []

    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as f:
            # add main domain (https) + alive subdomains
            all_targets = ["https://" + alive_subdomains[0].split("/")[2]] + alive_subdomains if alive_subdomains else []
            f.write("\n".join(all_targets))
            f.flush()

            result = subprocess.run(
                ["httpx", "-tech-detect", "-silent", "-list", f.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            results = result.stdout.splitlines()
    except Exception as e:
        print(Fore.RED + f"[!] Error running tech scans: {e}")
    return results

# -----------------------
# Pipeline-compatible entry
# -----------------------
def process(domain, safe_domain=None):
    print(Fore.CYAN + f"\n[+] Starting domain reconnaissance for: {domain}\n")

    # Subdomain enumeration
    print(Fore.YELLOW + "[*] Running Subfinder...")
    subfinder_results = run_subfinder(domain)
    print(Fore.GREEN + f"[✓] Found {len(subfinder_results)} unique subdomains with Subfinder")

    print(Fore.YELLOW + "[*] Fetching subdomains from crt.sh...")
    crtsh_results = run_crtsh(domain)
    print(Fore.GREEN + f"[✓] Found {len(crtsh_results)} unique subdomains from crt.sh")

    all_subdomains = sorted(subfinder_results.union(crtsh_results))
    print(Fore.CYAN + f"[+] Total unique subdomains collected: {len(all_subdomains)}")

    # Alive probing
    print(Fore.YELLOW + "\n[*] Probing alive subdomains with httpx...")
    alive = probe_alive(all_subdomains)
    print(Fore.GREEN + f"[✓] Found {len(alive)} alive subdomains")

    # Tech scans
    print(Fore.YELLOW + "\n[*] Running technology detection scans...")
    tech_results = run_tech_scans(alive)
    print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(tech_results)}")

    # Build JSON output
    output = {
        "domain": domain,
        "subdomains": all_subdomains,
        "alive": alive,
        "tech_scans": tech_results
    }

    print(Fore.CYAN + "\n=== Summary ===")
    print(Fore.WHITE + f"Total subdomains found: {len(all_subdomains)}")
    print(Fore.WHITE + f"Alive subdomains: {len(alive)}")

    print(Style.BRIGHT + Fore.CYAN + "\n[✓] Domain reconnaissance completed.\n")
    return output





