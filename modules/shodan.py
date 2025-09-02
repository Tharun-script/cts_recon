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
    """
    try:
        print(Fore.YELLOW + f"[*] Searching Shodan for {domain}...")
        results = api.search(domain)
        shodan_data = []

        for idx, result in enumerate(results.get("matches", []), 1):
            ip = result.get("ip_str")
            hostnames = result.get("hostnames", [])
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

            # CLI status output (human-readable, colorful)
            print(Fore.GREEN + f"[{idx}] IP: {ip}, Port: {entry['port']}, "
                  f"Org: {entry['org']}, Vulns: {', '.join(vulns) if vulns else 'None'}")

        print(Fore.CYAN + f"[✓] Shodan scan completed for {domain} "
                          f"({len(shodan_data)} results)")

        # Return only JSON data (pipeline saves to {target}_report/shodan.json)
        return {"shodan_results": shodan_data}

    except shodan.APIError as e:
        print(Fore.RED + f"[!] Shodan API Error: {e}")
        return {"shodan_results": []}
