import subprocess
import requests
import json
import time
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


# ------------------- Helpers -------------------
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
    techstack = []
    try:
        print(Fore.YELLOW + "\n[*] Running technology detection scans with httpx...")
        input_data = "\n".join(alive_subdomains).encode()
        process = subprocess.Popen(
            ["httpx", "-tech-detect", "-silent"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = process.communicate(input=input_data)
        techstack = stdout.decode().splitlines()
        print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(techstack)}")
    except Exception as e:
        print(Fore.RED + f"[!] Error running tech scans: {e}")
    return techstack


# ------------------- JSON Save Helper -------------------
def save_json(data, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(Fore.CYAN + f"[✓] Saved {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving {filename}: {e}")


# ------------------- Main Run -------------------
def run(domain, safe_domain):
    print(Fore.CYAN + f"\n[+] Starting domain reconnaissance for: {domain}\n")

    # 1️⃣ Subdomain enumeration
    subfinder_results = run_subfinder(safe_domain)
    crtsh_results = run_crtsh(safe_domain)
    all_subdomains = sorted(subfinder_results.union(crtsh_results))
    print(Fore.CYAN + f"\n[+] Total unique subdomains: {len(all_subdomains)}")

    # 2️⃣ Probe alive
    alive = probe_alive(all_subdomains)

    # 3️⃣ Tech stack detection
    techstack = run_tech_scans(alive)

    # 4️⃣ Prepare uniform JSON structure
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    base_data = {"target": domain, "timestamp": timestamp}

    # Save each scan individually
    safe_domain_clean = safe_domain.replace("/", "_")
    save_json({**base_data, "subdomains": all_subdomains}, f"{safe_domain_clean}_subdomains.json")
    save_json({**base_data, "alive_subdomains": alive}, f"{safe_domain_clean}_alive_subdomains.json")
    save_json({**base_data, "techstack": techstack}, f"{safe_domain_clean}_techstack.json")

    # 5️⃣ Combined output for pipeline
    output = {
        "target": domain,
        "timestamp": timestamp,
        "data": {
            "subdomains": all_subdomains,
            "alive_subdomains": alive,
            "techstack": techstack
        }
    }

    # Print summary
    print(Fore.CYAN + "\n=== Summary ===")
    print(Fore.WHITE + f"Total subdomains found: {len(all_subdomains)}")
    print(Fore.WHITE + f"Alive subdomains: {len(alive)}")
    print(Fore.WHITE + f"Tech fingerprints: {len(techstack)}")
    print(Style.BRIGHT + Fore.CYAN + "\n[✓] Domain reconnaissance completed.\n")

    return output


# ------------------- Pipeline Entry -------------------
def process(domain, safe_domain=None):
    if not safe_domain:
        safe_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    return run(domain, safe_domain)
