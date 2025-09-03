#!/usr/bin/env python3
import subprocess
import os
import json
import tempfile
from datetime import datetime
from colorama import Fore, Style, init
import builtwith

init(autoreset=True)


# =====================
# Helper: Run commands
# =====================
def run_command_show_output(command, description):
    print(f"\n{Fore.BLUE}[+] {description}{Style.RESET_ALL}")
    results = []
    try:
        with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    print(Fore.GREEN + "    " + line + Style.RESET_ALL)
                    results.append(line)
            proc.wait()
            # ignore errors to avoid spamming
    except Exception as e:
        print(f"{Fore.RED}[!] Exception occurred: {e}{Style.RESET_ALL}")
    return results


# =====================
# Subdomain Enumeration (subfinder + crt.sh)
# =====================
def get_subdomains(domain):
    subdomains = set()

    # Run subfinder
    try:
        result = subprocess.run(
            f"subfinder -d {domain} -all -recursive -silent",
            shell=True, capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                subdomains.add(line)
    except Exception:
        pass  # skip silently

    # Run crt.sh
    try:
        result = subprocess.run(
            f"""curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u""",
            shell=True, capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                subdomains.add(line)
    except Exception:
        pass  # skip silently

    return sorted(subdomains)



# =====================
# Main process
# =====================
def process(domain):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = {"domain": domain, "timestamp": timestamp}

    # 1. Subdomains (subfinder + crt.sh merged)
    all_subdomains = get_subdomains(domain)
    results["unique_subdomains"] = all_subdomains
    print(f"{Fore.MAGENTA}[✓] Found {len(all_subdomains)} unique subdomains from Subfinder + crt.sh{Style.RESET_ALL}")

    # Save subdomains temporarily for httpx
    subdomains_file = tempfile.NamedTemporaryFile(delete=False, mode="w")
    subdomains_file.write("\n".join(all_subdomains))
    subdomains_file.close()

    # 2. Alive subdomains
    alive = run_command_show_output(
        f"httpx-toolkit -l {subdomains_file.name} -ports 80,443,8080,8000,8443,8081,5000,9000 -threads 200 -silent",
        "Probing live subdomains with httpx..."
    )
    results["alive_subdomains"] = alive
    print(f"{Fore.MAGENTA}[✓] Found {len(alive)} alive subdomains{Style.RESET_ALL}")

    # 3. Technology scans (main + alive)
    tech_results = run_tech_scans(alive, include_main=f"http://{domain}")
    results["technology"] = tech_results

    return results


# =====================
# CLI Entry
# =====================
if __name__ == "__main__":
    domain = input(Fore.YELLOW + "Enter the target domain (e.g. cognizant.com): " + Style.RESET_ALL).strip()
    output = process(domain)

    # Save in pipeline-style location
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    project_root = os.path.abspath(os.path.dirname(__file__))
    report_dir = os.path.join(project_root, f"{safe_domain}reports")
    os.makedirs(report_dir, exist_ok=True)

    out_file = os.path.join(report_dir, "subdomain_module.json")
    with open(out_file, "w") as f:
        json.dump(output, f, indent=4)

    print(f"\n✅ {Fore.GREEN}Module finished! Report saved in {out_file}{Style.RESET_ALL}")
