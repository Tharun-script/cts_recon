#!/usr/bin/env python3
"""
Domain Reconnaissance Module
----------------------------
- Enumerates subdomains (subfinder + crt.sh)
- Probes alive domains (httpx)
- Detects technologies (httpx --tech-detect)

JSON Output Schema:
{
    "domain": "<target>",
    "subdomains": [...],
    "alive": [...],
    "tech_scans": [...]
}
"""

import subprocess
import requests
import json
import tempfile
from colorama import Fore, Style, init

init(autoreset=True)


# ---------------------------
# Subdomain Enumeration
# ---------------------------
def run_subfinder(domain):
    """Run Subfinder to enumerate subdomains"""
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        subdomains = set(result.stdout.splitlines())
        return subdomains
    except Exception as e:
        print(Fore.RED + f"[!] Error running subfinder: {e}")
        return set()


def run_crtsh(domain):
    """Fetch subdomains from crt.sh"""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=15)
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


# ---------------------------
# Alive Subdomain Probing
# ---------------------------
def probe_alive(subdomains):
    """Check alive subdomains using httpx via temporary file"""
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


# ---------------------------
# Technology Detection
# ---------------------------
def run_tech_scans(alive_subdomains):
    """Run httpx with --tech-detect on alive domains using temporary file"""
    results = []
    if not alive_subdomains:
        return results

    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as f:
            f.write("\n".join(alive_subdomains))
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


# ---------------------------
# Main Module Function
# ---------------------------
def run(domain, safe_domain=None):
    """Main entry for pipeline"""
    print(Fore.CYAN + f"\n[+] Starting domain reconnaissance for: {domain}\n")

    # 1. Subfinder
    print(Fore.YELLOW + "[*] Running Subfinder...")
    subfinder_results = run_subfinder(domain)
    print(Fore.GREEN + f"[✓] Found {len(subfinder_results)} unique subdomains with Subfinder")

    # 2. crt.sh
    print(Fore.YELLOW + "[*] Fetching subdomains from crt.sh...")
    crtsh_results = run_crtsh(domain)
    print(Fore.GREEN + f"[✓] Found {len(crtsh_results)} unique subdomains from crt.sh")

    # Combine results
    all_subdomains = sorted(subfinder_results.union(crtsh_results))
    print(Fore.CYAN + f"[+] Total unique subdomains collected: {len(all_subdomains)}")

    # 3. Probe alive subdomains
    print(Fore.YELLOW + "\n[*] Probing alive subdomains with httpx...")
    alive = probe_alive(all_subdomains)
    print(Fore.GREEN + f"[✓] Found {len(alive)} alive subdomains")

    # 4. Technology detection
    print(Fore.YELLOW + "\n[*] Running technology detection scans...")
    tech_results = run_tech_scans(alive)
    print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(tech_results)}")

    # -----------------------
    # Build JSON Output
    # -----------------------
    output = {
        "domain": domain,
        "subdomains": all_subdomains,
        "alive": alive,
        "tech_scans": tech_results
    }

    # Human-readable preview
    print(Fore.CYAN + "\n=== Summary ===")
    print(Fore.WHITE + f"Total subdomains found: {len(all_subdomains)}")
    print(Fore.WHITE + f"Alive subdomains: {len(alive)}")
    if alive:
        print(Fore.GREEN + "\n[Alive Domains]")
        for sub in alive[:10]:
            print(Fore.WHITE + f"  └─ {sub}")
        if len(alive) > 10:
            print(Fore.YELLOW + f"  └─ ... and {len(alive) - 10} more")

    if tech_results:
        print(Fore.GREEN + "\n[Technology Detection]")
        for t in tech_results[:10]:
            print(Fore.WHITE + f"  └─ {t}")
        if len(tech_results) > 10:
            print(Fore.YELLOW + f"  └─ ... and {len(tech_results) - 10} more")

    print(Style.BRIGHT + Fore.CYAN + "\n[✓] Domain reconnaissance completed.\n")

    return output
