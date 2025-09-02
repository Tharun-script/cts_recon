import os
import json
from colorama import Fore, Style, init

# Initialize colorama for colorful CLI
init(autoreset=True)


def extract_relevant_info(module, data):
    """
    Normalize each module's findings into consistent fields.
    Keeps only useful info like IPs, domains, subdomains, emails, etc.
    """
    normalized = {}

    if module == "domain":
        normalized["subdomains"] = data.get("alive_subdomains", [])
        normalized["technologies"] = data.get("tech", [])
    elif module == "bucket":
        normalized["buckets"] = data.get("buckets", [])
    elif module == "shodan":
        normalized["ips"] = data.get("ips", [])
        normalized["ports"] = data.get("ports", [])
        normalized["services"] = data.get("services", [])
    elif module == "scraping":
        normalized["emails"] = data.get("emails", [])
        normalized["links"] = data.get("links", [])
        normalized["domains"] = data.get("domains", [])
    else:
        # Default: keep raw data if module not mapped
        normalized = data

    return normalized


def generate_report(target):
    """
    Combine all module reports into one normalized JSON.
    Saves as {target}_normalized.json
    """
    reports_dir = f"{target}_reports"
    normalized_path = f"{target}_normalized.json"

    findings = {
        "target": target,
        "findings": {}
    }

    modules = ["domain", "bucket", "shodan", "scraping"]

    print(Fore.CYAN + f"\n[+] Generating normalized report for {target}" + Style.RESET_ALL)

    for module in modules:
        file_path = os.path.join(reports_dir, f"{module}.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                    findings["findings"][module] = extract_relevant_info(module, data)

                print(Fore.GREEN + f"[✓] Loaded {module}.json" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error loading {module}.json: {e}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"[!] {module}.json not found, skipping..." + Style.RESET_ALL)

    with open(normalized_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(Fore.CYAN + f"\n[✓] Normalized report saved as {normalized_path}" + Style.RESET_ALL)
