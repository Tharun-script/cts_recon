#!/usr/bin/env python3
import os
import json
from colorama import Fore, Style, init

init(autoreset=True)

from modules import domain, bucket, shodan_module, scraping

def generate_normalized_report(target):
    reports_dir = f"{target}_reports"
    os.makedirs(reports_dir, exist_ok=True)

    normalized_path = f"{target}_normalized.json"
    findings = {"target": target, "findings": {}}

    modules = ["domain", "bucket", "shodan", "scraping"]

    print(Fore.CYAN + f"\n[+] Generating normalized report for {target}" + Style.RESET_ALL)

    for module in modules:
        file_path = os.path.join(reports_dir, f"{module}.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                    findings["findings"][module] = data
                print(Fore.GREEN + f"[✓] Loaded {module}.json" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error loading {module}.json: {e}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"[!] {module}.json not found, skipping..." + Style.RESET_ALL)

    with open(normalized_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(Fore.CYAN + f"\n[✓] Normalized report saved as {normalized_path}" + Style.RESET_ALL)

if __name__ == "__main__":
    target = input("Enter domain or IP: ").strip()
    reports_dir = f"{target}_reports"
    os.makedirs(reports_dir, exist_ok=True)

    # Run each module
    try:
        domain.process(target, reports_dir)
    except Exception as e:
        print(Fore.RED + f"[!] Error running domain module: {e}")

    try:
        bucket.process(target, reports_dir)
    except Exception as e:
        print(Fore.RED + f"[!] Error running bucket module: {e}")

    try:
        scraping.process(target, reports_dir)
    except Exception as e:
        print(Fore.RED + f"[!] Error running scraping module: {e}")

    try:
        shodan_module.process(target, reports_dir)
    except Exception as e:
        print(Fore.RED + f"[!] Error running shodan module: {e}")

    # Generate normalized report
    generate_normalized_report(target)
