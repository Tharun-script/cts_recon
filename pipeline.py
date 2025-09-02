#!/usr/bin/env python3
import socket
import subprocess
import importlib
import os
import sys
import json
from datetime import datetime

# -------- Global scan collector --------
scan_data = {}

# -------- Classify Input --------
def classify_input(input_string):
    """Check if input is IP or Domain"""
    try:
        socket.inet_aton(input_string)  # valid IPv4?
        return 'IP'
    except socket.error:
        return 'DOMAIN'

# -------- Convert IP to Domain --------
def ip_to_domain(ip):
    """Convert IP to domain using nslookup"""
    try:
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "name =" in line:
                return line.split(" = ")[1].strip()
        return None
    except Exception as e:
        print(f"Error during nslookup: {e}")
        return None

# -------- Save Master Scan File --------
def save_scan_file(domain):
    """
    Write all collected results into one scan file:
      <target>_scan.json
    """
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    filename = f"{safe_domain}_scan.json"
    scan_data["target"] = domain
    scan_data["timestamp"] = datetime.utcnow().isoformat()

    try:
        with open(filename, "w") as f:
            json.dump(scan_data, f, indent=4)
        print(f"\n[✓] Final scan file saved → {filename}")
    except Exception as e:
        print(f"[!] Failed to save scan file: {e}")

# -------- Dynamic Module Loader --------
def route_to_modules(domain):
    """Automatically load and run all modules in modules/ folder"""
    modules_dir = os.path.join(os.path.dirname(__file__), "modules")

    if not os.path.isdir(modules_dir):
        print(f"[!] Modules directory not found: {modules_dir}")
        return

    for file in sorted(os.listdir(modules_dir)):
        if file.endswith(".py") and not file.startswith("__"):
            module_basename = file[:-3]

            try:
                if __package__:
                    module_name = f"{__package__}.modules.{module_basename}"
                else:
                    module_name = f"modules.{module_basename}"

                module = importlib.import_module(module_name)
                importlib.reload(module)

                if hasattr(module, "process"):
                    print(f"\n[+] Running {module_name}...")
                    result = module.process(domain)

                    # store each module's result into scan_data
                    scan_data[module_basename] = result  

                    print(f"[✓] {module_name} finished")
                else:
                    print(f"[!] {module_name} has no process(domain) function.")
            except Exception as e:
                print(f"[!] Error running {module_basename}: {e}")

# -------- Main Pipeline --------
def pipeline(input_string):
    input_type = classify_input(input_string)
    print(f"\n[*] Input classified as: {input_type}")

    if input_type == 'IP':
        print(f"[*] Converting IP {input_string} to domain...")
        domain = ip_to_domain(input_string)
        if domain:
            print(f"[✓] IP converted to domain: {domain}")
        else:
            print("[!] Could not resolve IP to domain. Exiting.")
            return
    else:
        domain = input_string

    # Run all modules
    route_to_modules(domain)

    # Save final combined scan file
    save_scan_file(domain)

# -------- Entry Point --------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        user_input = input("Enter domain or IP: ").strip()

    pipeline(user_input)
