#!/usr/bin/env python3
import socket
import subprocess
import importlib
import os
import sys

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

# -------- Dynamic Module Loader --------
def route_to_modules(domain):
    """Automatically load and run all modules in modules/ folder and forward to report.py"""
    modules_dir = os.path.join(os.path.dirname(__file__), "modules")
    
    # Import report.py from current directory
    try:
        import report
    except ImportError:
        report = None
        print("[!] report.py not found. Results will not be saved in structured/normalized format.")

    for file in os.listdir(modules_dir):
        if file.endswith(".py") and not file.startswith("__"):
            module_name = f"modules.{file[:-3]}"  # strip .py
            try:
                module = importlib.import_module(module_name)
                if hasattr(module, "process"):
                    print(f"\n[+] Running {module_name}...")
                    result = module.process(domain)
                    print(f"[✓] {module_name} finished. Result: {result}")

                    # Forward result to report.py if available
                    if report:
                        try:
                            report.save_report(file[:-3], result)
                        except Exception as e:
                            print(f"[!] Error saving report for {module_name}: {e}")

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
        user_input = input("Enter domain or IP: ")

    pipeline(user_input)
