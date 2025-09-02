#!/usr/bin/env python3
import shodan
from colorama import Fore, init

init(autoreset=True)

SHODAN_API_KEY = "A0icrJAHa3I1Gb5Hb0XUJdRqtgQIXUgs"
api = shodan.Shodan(SHODAN_API_KEY)


def process(domain):
    """
    Shodan module for pipeline.py
    Returns JSON-ready dict (pipeline will save report).
    Includes CVE mapping separately.
    """
    try:
        print(Fore.YELLOW + f"[*] Searching Shodan for {domain}...")
        results = api.search(domain)
        shodan_data = []
        cve_mapping = []

        for idx, result in enumerate(results.get("matches", []), 1):
            ip = result.get("ip_str")
            hostnames = result.get("hostnames", []) or ["N/A"]
            vulns = list(result.get("vulns", {}).keys()) if "vulns" in result else []

            entry = {
                "ip": ip,
                "port": result.get("port", "N/A"),
                "org": result.get("org", "N/A"),
                "hostnames": hostnames,
                "location": result.get("location", {}),
                "vulnerabilities": vulns
            }
            shodan_data.append(entry)

            # CLI status output
            print(Fore.GREEN + f"[{idx}] IP: {ip}, Port: {entry['port']}, "
                  f"Org: {entry['org']}, Vulns: {', '.join(vulns) if vulns else 'None'}")

            # --- CVE mapping extraction ---
            if vulns:
                for host in hostnames:
                    cve_mapping.append({
                        "ip": ip,
                        "hostname": host,
                        "cves": vulns
                    })

        print(Fore.CYAN + f"[✓] Shodan scan completed for {domain} "
                          f"({len(shodan_data)} results)")

        # Print CVE mapping summary in CLI
        if cve_mapping:
            print(Fore.MAGENTA + "\n[+] CVE Mapping:")
            for m in cve_mapping:
                print(Fore.MAGENTA + f"    IP: {m['ip']}, Host: {m['hostname']}, "
                      f"CVEs: {', '.join(m['cves'])}")

        # Return JSON with both scan results + CVE mapping
        return {
            "shodan_results": shodan_data,
            "cve_mapping": cve_mapping
        }

    except shodan.APIError as e:
        print(Fore.RED + f"[!] Shodan API Error: {e}")
        return {"shodan_results": [], "cve_mapping": []}
