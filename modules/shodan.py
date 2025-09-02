import shodan, json
from colorama import Fore, Style, init

init(autoreset=True)
API_KEY = "A0icrJAHa3I1Gb5Hb0XUJdRqtgQIXUgs"
api = shodan.Shodan(API_KEY)


def process(domain, reports_dir):
    print(Fore.YELLOW + f"\n[+] Running Shodan module for {domain}" + Style.RESET_ALL)
    results = {"module": "shodan", "target": domain, "ips": []}
    try:
        data = api.search(domain)
        for idx, r in enumerate(data.get("matches", []), 1):
            services = [{"port": r.get("port"), "banner": r.get("data"), "cves": list(r.get("vulns", {}).keys()) if r.get("vulns") else []}]
            ip_entry = {
                "ip": r.get("ip_str"),
                "org": r.get("org"),
                "ports": [r.get("port")],
                "location": r.get("location"),
                "services": services
            }
            results["ips"].append(ip_entry)
            status = f"{Fore.GREEN}[✓]" if services[0]["cves"] else "[*]"
            print(Fore.CYAN + f"{status} {r.get('ip_str')}:{r.get('port')} | {r.get('org')} | CVEs: {len(services[0]['cves'])}")
    except shodan.APIError as e:
        print(Fore.RED + f"[!] Shodan API Error: {e}")
    path = f"{reports_dir}/shodan.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(Fore.GREEN + f"[✓] shodan results saved → {path}" + Style.RESET_ALL)
