import subprocess
import requests
import time
import json
import os
from colorama import Fore, Style

# =======================
# Helper Functions
# =======================

def run_subfinder(domain):
    """Run subfinder and return list of subdomains"""
    try:
        print(Fore.CYAN + "[*] Running Subfinder..." + Style.RESET_ALL)
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, check=False
        )
        subdomains = result.stdout.splitlines()
        print(Fore.GREEN + f"[✓] Found {len(subdomains)} subdomains with Subfinder" + Style.RESET_ALL)
        return subdomains
    except FileNotFoundError:
        print(Fore.RED + "[!] subfinder not found! Install it with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" + Style.RESET_ALL)
        return []


def fetch_crtsh(domain, retries=3, delay=5):
    """Fetch subdomains from crt.sh with retries"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    all_domains = []
    for attempt in range(1, retries + 1):
        try:
            print(Fore.CYAN + f"[*] Fetching from crt.sh (attempt {attempt})..." + Style.RESET_ALL)
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                all_domains = [entry['name_value'] for entry in data if 'name_value' in entry]
                break
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] crt.sh timeout, retrying in {delay}s..." + Style.RESET_ALL)
            time.sleep(delay)
        except Exception as e:
            print(Fore.RED + f"[!] Error fetching crt.sh: {e}" + Style.RESET_ALL)
            break
    print(Fore.GREEN + f"[✓] Found {len(all_domains)} subdomains from crt.sh" + Style.RESET_ALL)
    return all_domains


def probe_alive(domains):
    """Use httpx to check alive domains"""
    try:
        print(Fore.CYAN + "\n[*] Probing alive subdomains with httpx..." + Style.RESET_ALL)
        process = subprocess.run(
            ["httpx", "-silent"],
            input="\n".join(domains),
            text=True,
            capture_output=True
        )
        alive = process.stdout.splitlines()
        print(Fore.GREEN + f"[✓] Found {len(alive)} alive subdomains" + Style.RESET_ALL)
        return alive
    except FileNotFoundError:
        print(Fore.RED + "[!] httpx not found! Install it with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest" + Style.RESET_ALL)
        return []


def run_tech_scans(domains):
    """Detect technologies using httpx -tech-detect"""
    tech_results = []
    try:
        print(Fore.CYAN + "\n[*] Running technology detection scans..." + Style.RESET_ALL)
        process = subprocess.run(
            ["httpx", "-tech-detect", "-silent"],
            input="\n".join(domains),
            text=True,
            capture_output=True
        )
        lines = process.stdout.splitlines()
        for line in lines:
            parts = line.split(" [")
            domain = parts[0].strip()
            techs = parts[1].replace("]", "").split(", ") if len(parts) > 1 else []
            tech_results.append({"domain": domain, "tech": techs})
        print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(tech_results)}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "[!] httpx not found for tech scans!" + Style.RESET_ALL)
    return tech_results


def print_domains(title, domains, color=Fore.GREEN):
    """Pretty print a list of domains or results"""
    print(Fore.MAGENTA + f"\n=== {title} ({len(domains)}) ===" + Style.RESET_ALL)
    for d in domains:
        print(color + f" - {d}" + Style.RESET_ALL)


# =======================
# Main Process Function
# =======================

def process(domain, safe_domain):
    """Main entry for domain enumeration & scanning"""
    print(Fore.YELLOW + f"\n[+] Running modules.domain for {domain}..." + Style.RESET_ALL)

    # Subfinder
    subfinder_subs = run_subfinder(domain)

    # crt.sh
    crt_subs = fetch_crtsh(domain)

    # Merge & dedupe
    all_subdomains = sorted(set(subfinder_subs + crt_subs))
    print_domains("All Subdomains", all_subdomains, Fore.CYAN)

    # Probe alive
    alive = probe_alive(all_subdomains)
    print_domains("Alive Subdomains", alive, Fore.GREEN)

    # Tech scan
    tech_results = run_tech_scans(alive)
    tech_display = [f"{t['domain']} → {', '.join(t['tech'])}" for t in tech_results]
    print_domains("Tech Scan Results", tech_display, Fore.YELLOW)

    # Save results
    report_dir = os.path.join(safe_domain, "reports")
    os.makedirs(report_dir, exist_ok=True)
    output_file = os.path.join(report_dir, "domain.json")

    data = {
        "subdomains": all_subdomains,
        "alive": alive,
        "technologies": tech_results
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(Fore.CYAN + f"\n[✓] Results saved to {output_file}" + Style.RESET_ALL)
