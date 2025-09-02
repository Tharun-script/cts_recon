import subprocess
import requests
import json
import time
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def run_subfinder(domain):
    try:
        print(Fore.YELLOW + "[*] Running Subfinder...")
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        subs = set(result.stdout.splitlines())
        print(Fore.GREEN + f"[✓] Subfinder found {len(subs)} subdomains")
        return subs
    except Exception as e:
        print(Fore.RED + f"[!] Error running subfinder: {e}")
        return set()


def run_crtsh(domain, retries=3, delay=5):
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    for attempt in range(1, retries + 1):
        try:
            print(Fore.YELLOW + f"[*] Fetching from crt.sh (attempt {attempt}/{retries})...")
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value")
                    if name:
                        for sub in name.split("\n"):
                            sub = sub.strip()
                            if "*" not in sub:
                                subdomains.add(sub)
                print(Fore.GREEN + f"[✓] crt.sh found {len(subdomains)} subdomains")
                return subdomains
            else:
                print(Fore.RED + f"[!] crt.sh returned status {resp.status_code}")
        except Exception as e:
            print(Fore.RED + f"[!] Error fetching crt.sh: {e}")
            if attempt < retries:
                print(Fore.YELLOW + f"    Retrying in {delay}s...")
                time.sleep(delay)

    print(Fore.RED + "[!] crt.sh failed after all retries")
    return subdomains


def probe_alive(subdomains):
    alive = []
    try:
        print(Fore.YELLOW + "\n[*] Probing alive subdomains with httpx...")
        input_data = "\n".join(subdomains).encode()
        process = subprocess.Popen(
            ["httpx", "-silent"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = process.communicate(input=input_data)
        alive = stdout.decode().splitlines()
        print(Fore.GREEN + f"[✓] Found {len(alive)} alive subdomains")
    except Exception as e:
        print(Fore.RED + f"[!] Error probing alive domains: {e}")
    return alive


def run_tech_scans(alive_subdomains):
    results = []
    try:
        print(Fore.YELLOW + "\n[*] Running technology detection scans with httpx...")
        input_data = "\n".join(alive_subdomains).encode()
        process = subprocess.Popen(
            ["httpx", "-tech-detect", "-silent"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = process.communicate(input=input_data)
        results = stdout.decode().splitlines()
        print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(results)}")
    except Exception as e:
        print(Fore.RED + f"[!] Error running tech scans: {e}")
    return results


def run(domain, safe_domain):
    print(Fore.CYAN + f"\n[+] Starting domain reconnaissance for: {domain}\n")

    # 1. Subfinder
    subfinder_results = run_subfinder(safe_domain)

    # 2. crt.sh
    crtsh_results = run_crtsh(safe_domain)

    # Combine
    all_subdomains = sorted(subfinder_results.union(crtsh_results))
    print(Fore.CYAN + f"\n[+] Total unique subdomains: {len(all_subdomains)}")

    # 3. Probe
    alive = probe_alive(all_subdomains)

    # 4. Tech scans
    tech_results = run_tech_scans(alive)

    # Build JSON output
    output = {
        "domain": domain,
        "subdomains": all_subdomains,
        "alive": alive,
        "tech_scans": tech_results
    }

    # Save results to JSON
    filename = f"{safe_domain}_recon.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4)
        print(Fore.CYAN + f"\n[✓] Results saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving JSON file: {e}")

    # Human summary
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


# 🔑 Entry point for pipeline
def process(domain, safe_domain=None):
    if not safe_domain:
        # Normalize domain → strip http/https and any path
        safe_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    return run(domain, safe_domain)


# Example run (uncomment for direct execution)
# process("cognizant.com")
