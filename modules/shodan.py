#!/usr/bin/env python3
import json
import shodan
from colorama import Fore, init

init(autoreset=True)

API_KEY = "A0icrJAHa3I1Gb5Hb0XUJdRqtgQIXUgs"
api = shodan.Shodan(API_KEY)


def process(domain, safe_domain):
    print(Fore.YELLOW + f"\n[+] Shodan scan for {domain}")
    results = {"module": "shodan", "target": domain, "shodan_results": []}

    try:
        data = api.search(domain)
        for idx, result in enumerate(data.get("matches", []), 1):
            entry = {
                "ip": result.get("ip_str"),
                "port": result.get("port"),
                "org": result.get("org"),
                "hostnames": result.get("hostnames", []),
                "location": result.get("location", {}),
                "vulnerabilities": list(result.get("vulns", {}).keys()) if "vulns" in result else []
            }
            results["shodan_results"].append(entry)
            print(Fore.GREEN + f"[{idx}] {entry['ip']}:{entry['port']} | {entry['org']} | Vulns: {len(entry['vulnerabilities'])}")

    except shodan.APIError as e:
        print(Fore.RED + f"[!] Shodan API Error: {e}")

    with open(f"{safe_domain}_shodan.json", "w") as f:
        json.dump(results, f, indent=2)

    print(Fore.CYAN + f"[✓] Shodan scan completed, results saved.\n")
    return results
