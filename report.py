import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

def normalize_reports(target):
    """Combine all module reports into one normalized JSON"""
    reports_dir = f"{target}_reports"
    normalized_path = f"{target}_normalized.json"

    findings = {
        "target": target,
        "findings": {}
    }

    # List of expected module outputs
    modules = ["domain", "bucket", "shodan", "scraping"]

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

    # Save normalized report
    with open(normalized_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(Fore.CYAN + f"\n[✓] Normalized report saved as {normalized_path}" + Style.RESET_ALL)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(Fore.RED + "Usage: python report.py <target>" + Style.RESET_ALL)
        sys.exit(1)

    target = sys.argv[1]
    normalize_reports(target)
