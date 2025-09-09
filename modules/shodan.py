#!/usr/bin/env python3
import shodan
import subprocess
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import requests

# ----------------------------
# Init
# ----------------------------
init(autoreset=True)

SHODAN_API_KEY = "A0icrJAHa3I1Gb5Hb0XUJdRqtgQIXUgs"
api = shodan.Shodan(SHODAN_API_KEY)

# Top 20 ports (443 excluded)
PORTS = "80,8080,8443,8000,8888,25,465,587,110,995,143,993,53,3389,636,21,22,3000,3306,5432"
NMAP_CMD = f"nmap -Pn --host-timeout 30s --max-retries 1 --min-rate 500 -p {PORTS}"


def run_nmap(ip):
    """Run nmap scan on given IP and return list of open ports."""
    print(Fore.MAGENTA + f"[*] Running Nmap on {ip}...")
    try:
        result = subprocess.run(
            f"{NMAP_CMD} {ip}",
            shell=True,
            capture_output=True,
            text=True
        )

        open_ports = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                open_ports.append(port)

        return ip, open_ports
    except Exception as e:
        print(Fore.RED + f"[!] Error running Nmap on {ip}: {e}")
        return ip, []


def fetch_cvss(cve_id):
    """Fetch CVSS score for a CVE from Shodan CVE DB."""
    try:
        url = f"https://cvedb.shodan.io/cve/{cve_id}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("cvss", None)
        else:
            return None
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching CVSS for {cve_id}: {e}")
        return None


def process(domain):
    """
    Shodan + Nmap integration + CVE → CVSS enrichment.
    Returns dict so pipeline saves into <target>_deep.json.
    """
    try:
        print(Fore.YELLOW + f"[*] Searching Shodan for {domain}...")
        results = api.search(f"hostname:{domain}")
        entries = {}

        for result in results.get("matches", []):
            ip = result.get("ip_str")
            shodan_port = result.get("port")

            if ip not in entries:
                entries[ip] = {
                    "ip": ip,
                    "org": result.get("org", "N/A"),
                    "hostnames": result.get("hostnames", []),
                    "location": result.get("location", {}),
                    "vulnerabilities": [],
                    "ports": []
                }

            # Collect Shodan-discovered ports
            if shodan_port:
                entries[ip]["ports"].append(str(shodan_port))

            # Collect and enrich vulnerabilities with CVSS
            if "vulns" in result:
                for cve in result["vulns"].keys():
                    cvss = fetch_cvss(cve)
                    entries[ip]["vulnerabilities"].append({
                        "cve": cve,
                        "cvss": cvss
                    })

        ips = list(entries.keys())
        print(Fore.CYAN + f"[*] Running Nmap scans on {len(ips)} unique IPs in parallel...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(run_nmap, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip, nmap_ports = future.result()
                all_ports = sorted(set(entries[ip]["ports"] + nmap_ports), key=lambda x: int(x))
                entries[ip]["ports"] = all_ports

                # Print ports in list format
                print(Fore.GREEN + f"[+] {ip}")
                for p in all_ports:
                    print(Fore.GREEN + f"    - {p}")

        combined_data = list(entries.values())

        # ✅ return dict → pipeline will merge into {target}_deep.json
        return {
            "shodan_nmap": combined_data
        }

    except shodan.APIError as e:
        print(Fore.RED + f"[!] Shodan API Error: {e}")
        return {
            "shodan_nmap": {"error": str(e)}
        }


if __name__ == "__main__":
    target_domain = input("Enter the domain name: ").strip()
    output = process(target_domain)
    print(Fore.CYAN + json.dumps(output, indent=4))
