#!/usr/bin/env python3
import subprocess
import os
import json
from datetime import datetime
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Import report module if exists
try:
    from reconn import report
except ImportError:
    report = None

# -------------------
# Helper functions
# -------------------
def run_command(command, description):
    """Run a shell command and return stdout lines"""
    print(Fore.YELLOW + f"[+] {description}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(Fore.RED + f"[!] Command failed: {result.stderr.strip()}")
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Exception: {e}")
        return []

def save_json(data, file_path):
    """Save dictionary as JSON"""
    try:
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)
        print(Fore.MAGENTA + f"[+] Results saved to {file_path}")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to save JSON: {e}")

def check_alive(out_dir):
    """Check alive subdomains with httpx"""
    alive_file = os.path.join(out_dir, "subdomains_alive.txt")
    print(Fore.YELLOW + "[+] Checking alive subdomains with httpx...")
    try:
        command = f"httpx-toolkit -l {out_dir}/subdomains_all.txt -silent -timeout 10 -o {alive_file}"
        subprocess.run(command, shell=True, check=True)
        alive_subs = []
        if os.path.exists(alive_file):
            with open(alive_file) as f:
                alive_subs = [line.strip() for line in f if line.strip()]
        print(Fore.CYAN + f"[✓] Found {len(alive_subs)} alive subdomains")
        for sub in alive_subs:
            print(Fore.GREEN + f"- {sub}")
        return alive_subs
    except Exception as e:
        print(Fore.RED + f"[!] httpx error: {e}")
        return []

def run_wappy(targets):
    """
    Runs Wappy only on alive subdomains
    Returns structured dict: { "domain": ["Tech1", "Tech2", ...], ... }
    """
    print(Fore.YELLOW + "[+] Running Wappy scans on alive subdomains...")
    wappy_results = {}

    # Include venv bin path if necessary
    env = os.environ.copy()
    venv_bin = os.path.join(os.path.dirname(os.path.dirname(os.__file__)), "bin")
    env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")

    for target in targets:
        print(Fore.CYAN + f"    - Scanning {target} ...")
        try:
            result = subprocess.run(
                ["wappy", target],
                capture_output=True,
                text=True,
                env=env
            )

            output_lines = result.stdout.splitlines() if result.returncode == 0 else []
            techs = []

            for line in output_lines:
                line = line.strip()
                # Skip domain headers
                if not line or line.startswith(target):
                    continue
                techs.append(line)

            wappy_results[target] = techs

        except Exception as e:
            wappy_results[target] = [f"Error: {e}"]

    print(Fore.GREEN + "[✓] Wappy scans completed")
    return wappy_results

# -------------------
# Main process
# -------------------
def process(domain):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = f"recon-{domain}-{timestamp}"
    os.makedirs(out_dir, exist_ok=True)
    print(Fore.MAGENTA + f"\nOutput directory: {out_dir}\n")

    # -------------------
    # Subdomain enumeration
    # -------------------
    subfinder_subs = run_command(f"subfinder -d {domain} -all -silent", "Running Subfinder...")
    sublister_subs = run_command(f"sublist3r -d {domain}", "Running Sublist3r...")
    crtsh_subs = run_command(
        f"""curl -s "https://crt.sh/?q={domain}&output=json" | jq -r '.[].name_value'""",
        "Fetching subdomains from crt.sh..."
    )

    # Merge all unique
    all_subdomains = sorted(list(set(subfinder_subs + sublister_subs + crtsh_subs)))
    with open(os.path.join(out_dir, "subdomains_all.txt"), "w") as f:
        for sub in all_subdomains:
            f.write(sub + "\n")
    print(Fore.CYAN + f"[✓] Total {len(all_subdomains)} unique subdomains collected")

    # -------------------
    # Alive check
    # -------------------
    alive_subs = check_alive(out_dir)

    # -------------------
    # Wappy scan on alive subdomains
    # -------------------
    wappy_results = run_wappy(alive_subs)

    # -------------------
    # Final JSON report
    # -------------------
    results = {
        "domain": domain,
        "subdomains_all": all_subdomains,
        "subdomains_alive": alive_subs,
        "wappy_results": wappy_results
    }

    json_file = os.path.join(out_dir, f"{domain}_subdomain_report.json")
    save_json(results, json_file)

    if report:
        report.save_report("subdomain", results)

    print(Fore.MAGENTA + f"\n✅ Subdomain module scan completed for {domain}")
    return f"Success"
