#!/usr/bin/env python3
import socket
import subprocess
import importlib
import os
import sys
import json

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

# -------- Save Module Report --------
def save_module_report(domain, module_name, data):
    """
    Save a module's returned JSON to:
      reconn/<safe_domain>reports/<module_name>.json
    Example:
      /home/kali/Downloads/reconn/cognizant.comreports/bucket.json
    """
    # sanitize domain minimally (remove path separators)
    safe_domain = domain.replace("/", "_").replace("\\", "_")

    # reports folder = <project_root>/<domain>reports
    project_root = os.path.abspath(os.path.dirname(__file__))  # this is 'reconn'
    report_dir = os.path.join(project_root, f"{safe_domain}reports")

    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, f"{module_name}.json")

    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Saved {module_name} report → {path}")
    except Exception as e:
        print(f"[!] Failed to save report for {module_name}: {e}")

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
            module_name = f"modules.{module_basename}"  # strip .py
            try:
                # import module (reload to pick up changes if needed)
                module = importlib.import_module(module_name)
                importlib.reload(module)
                if hasattr(module, "process"):
                    print(f"\n[+] Running {module_name}...")
                    result = module.process(domain)
                    # Save module output to domain-specific folder
                    save_module_report(domain, module_basename, result)
                    print(f"[✓] {module_name} finished")
                else:
                    print(f"[!] {module_name} has no process(domain) function.")
            except Exception as e:
                print(f"[!] Error running {module_name}: {e}")

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

    # Forward to modules
    route_to_modules(domain)

# -------- Entry Point --------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        user_input = input("Enter domain or IP: ").strip()

    pipeline(user_input)
