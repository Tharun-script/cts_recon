import subprocess
import requests
import time
import json
import os
from colorama import Fore, Style, init

# Initialize color output
init(autoreset=True)


def run_subfinder(domain):
    """Run subfinder tool to get subdomains"""
    try:
        print(Fore.CYAN + "\n[*] Running Subfinder..." + Style.RESET_ALL)
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, check=False
        )
        subs = result.stdout.splitlines()
        print(Fore.GREEN + f"[✓] Found {len(subs)} subdomains with Subfinder" + Style.RESET_ALL)
        return subs
    except Exception as e:
        print(Fore.RED + f"[!] Error running subfinder: {e}" + Style.RESET_ALL)
        return []


def fetch_crtsh(domain, retries=3, delay=5):
    """Fetch subdomains from crt.sh with retries"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(1, retries + 1):
        try:
            print(Fore.CYAN + f"[*] Fetching from crt.sh (attempt {attempt})..." + Style.RESET_ALL)
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                subs = [entry['name_value'] for entry in data if 'name_value' in entry]
                print(Fore.GREEN + f"[✓] Found {len(subs)} subdomains from crt.sh" + Style.RESET_ALL)
                return subs
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] crt.sh timeout, retrying in {delay}s..." + Style.RESET_ALL)
            time.sleep(delay)
        except Exception as e:
            print(Fore.RED + f"[!] Error fetching crt.sh: {e}" + Style.RESET_ALL)
            return []
    return []


def probe_alive(subdomains):
    """Probe alive domains using httpx"""
    try:
        print(Fore.CYAN + "\n[*] Probing alive subdomains with httpx..." + Style.RESET_ALL)
        result = subprocess.run(
            ["httpx", "-silent"],
            input="\n".join(subdomains),
            capture_output=True, text=True, check=False
        )
        alive = result.stdout.splitlines()
        print(Fore.GREEN + f"[✓] Found {len(alive)} alive subdomains" + Style.RESET_ALL)
        return alive
    except Exception as e:
        print(Fore.RED + f"[!] Error probing alive domains: {e}" + Style.RESET_ALL)
        return []


def run_tech_scans(alive_domains):
    """Run httpx tech detection on alive domains"""
    try:
        print(Fore.CYAN + "\n[*] Running technology detection scans..." + Style.RESET_ALL)
        result = subprocess.run(
            ["httpx", "-silent", "-tech-detect"],
            input="\n".join(alive_domains),
            capture_output=True, text=True, check=False
        )
        lines = result.stdout.splitlines()
        tech = []
        for line in lines:
            parts = line.split(" [")
            domain = parts[0].strip()
            if len(parts) > 1:
                techs = parts[1].replace("]", "").split(", ")
                tech.append({"domain": domain, "tech": techs})
        print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(tech)}" + Style.RESET_ALL)
        return tech
    except Exception as e:
        print(Fore.RED + f"[!] Error running tech scans: {e}" + Style.RESET_ALL)
        return []


def print_list(title, items, color=Fore.CYAN):
    """Pretty print list of items"""
    print(Fore.MAGENTA + f"\n=== {title} ({len(items)}) ===" + Style.RESET_ALL)
    for item in items:
        print(color + f" - {item}" + Style.RESET_ALL)


def process(domain):
    """Main entry for domain enumeration & scanning"""
    safe_domain = domain.replace(".", "_")  # auto-generate safe folder name
    print(Fore.YELLOW + f"\n[+] Running modules.domain for {domain}..." + Style.RESET_ALL)

    # Create reports folder
    reports_dir = os.path.join(f"{domain}_reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Subdomain discovery
    subfinder_results = run_subfinder(domain)
    crtsh_results = fetch_crtsh(domain)
    all_subdomains = sorted(set(subfinder_results + crtsh_results))
    print_list("All Subdomains", all_subdomains, Fore.CYAN)

    # Save subdomains
    with open(os.path.join(reports_dir, "subdomains.json"), "w") as f:
        json.dump(all_subdomains, f, indent=2)

    # Alive probing
    alive = probe_alive(all_subdomains)
    print_list("Alive Subdomains", alive, Fore.GREEN)
    with open(os.path.join(reports_dir, "alive.json"), "w") as f:
        json.dump(alive, f, indent=2)

    # Technology detection
    tech = run_tech_scans(alive)
    pretty_tech = [f"{t['domain']} → {', '.join(t['tech'])}" for t in tech]
    print_list("Technology Results", pretty_tech, Fore.YELLOW)
    with open(os.path.join(reports_dir, "tech.json"), "w") as f:
        json.dump(tech, f, indent=2)

    print(Fore.GREEN + f"\n[✓] Domain scan for {domain} completed! Reports saved in {reports_dir}" + Style.RESET_ALL)
