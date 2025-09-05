#!/usr/bin/env python3
import socket
import subprocess
import importlib
import os
import sys
import json
from datetime import datetime
from colorama import Fore, Style, init

# -------- Initialize Colorama --------
init(autoreset=True)

# -------- Global scan collector --------
scan_data = {}

# -------- CLI Helpers --------
def status(msg):
    print(Fore.LIGHTCYAN_EX + "[*] " + Style.RESET_ALL + msg)

def success(msg):
    print(Fore.LIGHTGREEN_EX + "[+] " + Style.RESET_ALL + msg)

def warning(msg):
    print(Fore.LIGHTYELLOW_EX + "[!] " + Style.RESET_ALL + msg)

def error(msg):
    print(Fore.LIGHTRED_EX + "[-] " + Style.RESET_ALL + msg)

# -------- Classify Input --------
def classify_input(input_string):
    """Check if input is IP or Domain"""
    try:
        socket.inet_aton(input_string)
        return 'IP'
    except socket.error:
        return 'DOMAIN'

# -------- Convert IP to Domain --------
def ip_to_domain(ip):
    """Convert IP to domain using nslookup"""
    try:
        status(f"Resolving IP {ip} to domain...")
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "name =" in line:
                domain = line.split(" = ")[1].strip()
                success(f"Resolved to {domain}")
                return domain
        warning("No domain found for this IP.")
        return None
    except Exception as e:
        error(f"nslookup error: {e}")
        return None

# -------- Save Master Scan File --------
def save_scan_file(domain, scan_type):
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    filename = f"{safe_domain}_lite.json" if scan_type == "lite" else f"{safe_domain}_deep.json"

    scan_data["target"] = domain
    scan_data["scan_type"] = scan_type
    scan_data["timestamp"] = datetime.utcnow().isoformat()

    try:
        with open(filename, "w") as f:
            json.dump(scan_data, f, indent=4)
        success(f"Scan data saved → {filename}")
    except Exception as e:
        error(f"Failed to save scan file: {e}")
        return None

    # Run report only for lite scans
    if scan_type == "lite":
        try:
            status(f"Generating SPF report for {domain}...")
            subprocess.run([sys.executable, "report.py", filename], check=True)
        except Exception as e:
            error(f"Could not run report.py: {e}")

    return filename

# -------- Dynamic Module Loader --------
def route_to_modules(domain, modules_dir):
    if not os.path.isdir(modules_dir):
        error(f"Modules directory not found: {modules_dir}")
        return

    for file in sorted(os.listdir(modules_dir)):
        if file.endswith(".py") and not file.startswith("__"):
            module_basename = file[:-3]
            module_name = f"{os.path.basename(modules_dir)}.{module_basename}"

            try:
                module = importlib.import_module(module_name)
                importlib.reload(module)

                if hasattr(module, "process"):
                    status(f"Running {module_name}...")
                    result = module.process(domain)
                    scan_data[module_basename] = result  
                    success(f"{module_name} completed")
                else:
                    warning(f"{module_name} has no process(domain) function.")
            except Exception as e:
                error(f"{module_basename} failed: {e}")

# -------- Main Pipeline --------
def pipeline(input_string, scan_type="deep"):
    input_type = classify_input(input_string)
    status(f"Input classified as: {input_type}")

    if input_type == 'IP':
        domain = ip_to_domain(input_string)
        if not domain:
            error("Exiting.")
            return
    else:
        domain = input_string

    print("\nTarget:", Fore.LIGHTGREEN_EX + domain + Style.RESET_ALL)
    print("Scan Type:", Fore.LIGHTYELLOW_EX + scan_type.upper() + Style.RESET_ALL)
    print("-" * 50)

    # Choose modules directory
    modules_dir = os.path.join(os.path.dirname(__file__), "litemodules" if scan_type == "lite" else "modules")

    # Run all modules
    route_to_modules(domain, modules_dir)

    # Save scan file
    save_scan_file(domain, scan_type)

# -------- Entry Point --------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        user_input = input("Enter domain or IP: ").strip()

    print("\nSelect Scan Type:")
    print("  1) Lite Scan  (fast)")
    print("  2) Deep Scan  (detailed)")
    choice = input("Choice (1/2): ").strip()

    scan_type = "lite" if choice == "1" else "deep"
    pipeline(user_input, scan_type)
