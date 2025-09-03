import subprocess
import requests
import json
import time
import os
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

        if not subdomains:
            print(Fore.RED + "[!] No subdomains to probe.")
            return alive

        input_data = "\n".join(subdomains).encode()

        # Run httpx with multiple ports, tls-ignore, and verbose
        process = subprocess.Popen(
            [
                "httpx",
                "-silent",
                "-ports", "80,443,8080,8443",
                "-tls-ignore",
                "-threads", "50"
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = process.communicate(input=input_data)

        # Decode output
        alive = stdout.decode().splitlines()

        if alive:
            print(Fore.GREEN + f"[✓] Found {len(alive)} alive subdomains")
        else:
            print(Fore.RED + "[!] No alive subdomains found. Check network or firewall settings.")

    except Exception as e:
        print(Fore.RED + f"[!] Error probing alive domains: {e}")

    return alive



def run_tech_scans(alive_subdomains):
    techstack = []
    try:
        if not alive_subdomains:
            return techstack
        print(Fore.YELLOW + "\n[*] Running technology detection scans with httpx...")
        input_data = "\n".join(alive_subdomains).encode()
        process = subprocess.Popen(
            ["httpx", "-tech-detect", "-silent", "-timeout", "30"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = process.communicate(input=input_data)
        techstack = stdout.decode().splitlines()
        print(Fore.GREEN + f"[✓] Technology fingerprints collected: {len(techstack)}")
    except Exception as e:
        print(Fore.RED + f"[!] Error running tech scans: {e}")
    return techstack


def save_json(filename, data):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(Fore.CYAN + f"[✓] Saved results to {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving JSON file {filename}: {e}")


def run(domain, safe_domain):
    print(Fore.CYAN + f"\n[+] Starting domain reconnaissance for: {domain}\n")

    # 1. Subfinder
    subfinder_results = run_subfinder(safe_domain)

    # 2. crt.sh
    crtsh_results = run_crtsh(safe_domain)

    # Combine
    all_subdomains = sorted(subfinder_results.union(crtsh_results))
    print(Fore.CYAN + f"\n[+] Total unique subdomains: {len(all_subdomains)}")

    # Save subdomains JSON
    save_json(f"{safe_domain}_subdomains.json", {"target": domain, "subdomains": all_subdomains})

    # 3. Probe alive
    alive = probe_alive(all_subdomains)
    save_json(f"{safe_domain}_alive.json", {"target": domain, "alive_subdomains": alive})

    # 4. Tech scans
    techstack = run_tech_scans(alive)
    save_json(f"{safe_domain}_techstack.json", {"target": domain, "techstack": techstack})

    # Summary
    print(Fore.CYAN + "\n=== Summary ===")
    print(Fore.WHITE + f"Total subdomains found: {len(all_subdomains)}")
    print(Fore.WHITE + f"Alive subdomains: {len(alive)}")
    print(Fore.WHITE + f"Tech fingerprints: {len(techstack)}")
    print(Style.BRIGHT + Fore.CYAN + "\n[✓] Domain reconnaissance completed.\n")

    # Return combined data
    return {
        "target": domain,
        "subdomains": all_subdomains,
        "alive_subdomains": alive,
        "techstack": techstack
    }


def process(domain, safe_domain=None):
    if not safe_domain:
        safe_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    return run(domain, safe_domain)


# Example usage:
# process("rmkcet.ac.in")

