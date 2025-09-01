#!/usr/bin/env python3
import shodan
import json
from colorama import Fore, init
#from datetime import datetime
import os

init(autoreset=True)

try:
    from reconn import report
except ImportError:
    report = None

SHODAN_API_KEY = "A0icrJAHa3I1Gb5Hb0XUJdRqtgQIXUgs"
api = shodan.Shodan(SHODAN_API_KEY)

def process(domain):
    """Shodan module for pipeline.py"""
    try:
        print(Fore.YELLOW + f"[*] Searching Shodan for {domain}...")
        results = api.search(domain)
        shodan_data = []

        # Create output folder
        #timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = f"shodan_{domain}"
        os.makedirs(out_dir, exist_ok=True)

        txt_file = os.path.join(out_dir, f"{domain}_shodan_report.txt")
        json_file = os.path.join(out_dir, f"{domain}_shodan_results.json")

        with open(txt_file, "w", encoding="utf-8") as txtf:
            txtf.write(f"Shodan Scan Report for {domain}\n")
            #txtf.write(f"Timestamp: {datetime.now().isoformat()}\n")
            #txtf.write("="*80 + "\n\n")

            for idx, result in enumerate(results["matches"], 1):
                ip = result.get("ip_str")
                hostnames = result.get("hostnames", [])
                vulns = list(result.get("vulns", {}).keys()) if "vulns" in result else []

                entry = {
                    "ip": ip,
                    "port": result.get("port", "N/A"),
                    "org": result.get("org", "N/A"),
                    "hostnames": hostnames,
                    "location": result.get("location", {}),
                    #"timestamp": result.get("timestamp"),
                    "vulnerabilities": vulns
                }
                shodan_data.append(entry)

                # --- TXT human-readable output ---
                txtf.write(f"[{idx}] IP: {ip}\n")
                txtf.write(f"    Port: {entry['port']}\n")
                txtf.write(f"    Org: {entry['org']}\n")
                txtf.write(f"    Hostnames: {', '.join(hostnames) if hostnames else 'N/A'}\n")
                txtf.write(f"    Location: {entry['location']}\n")
                #txtf.write(f"    Timestamp: {entry['timestamp']}\n")
                txtf.write(f"    Vulnerabilities: {', '.join(vulns) if vulns else 'None'}\n")
                txtf.write("-"*60 + "\n")

                # --- CLI output ---
                display_entry = {k: v for k, v in entry.items() if k != "banner"}
                print(Fore.GREEN + json.dumps(display_entry, indent=4))

        # Save JSON report
        with open(json_file, "w", encoding="utf-8") as jf:
            json.dump({"shodan_results": shodan_data}, jf, indent=4)

        print(Fore.MAGENTA + f"[+] Shodan results saved (JSON): {json_file}")
        print(Fore.MAGENTA + f"[+] Shodan human-readable report (TXT): {txt_file}")

        # Forward to report.py
        report_data = {"shodan_results": shodan_data}
        if report:
            try:
                report.save_report("shodan", report_data)
                print(Fore.CYAN + "[+] Shodan results forwarded to report.py")
            except Exception as e:
                print(Fore.RED + f"[!] Error saving report for modules.shodan: {e}")

        # Also create CVE mapping JSON for easy host/IP -> CVE lookup
        cve_mapping = []
        for entry in shodan_data:
            if entry["vulnerabilities"]:
                for host in entry["hostnames"] if entry["hostnames"] else ["N/A"]:
                    cve_mapping.append({
                        "ip": entry["ip"],
                        "hostname": host,
                        "cves": entry["vulnerabilities"]
                    })
        cve_json_file = os.path.join(out_dir, f"{domain}_shodan_cve_mapping.json")
        with open(cve_json_file, "w", encoding="utf-8") as jf:
            json.dump(cve_mapping, jf, indent=4)
        print(Fore.MAGENTA + f"[+] CVE mapping saved: {cve_json_file}")

        return Fore.GREEN + f"Success"

    except shodan.APIError as e:
        print(Fore.RED + f"Shodan API Error: {e}")
        return None
