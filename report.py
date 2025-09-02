#!/usr/bin/env python3
import os
import json
import re

def generate_report(domain):
    """Read all module JSONs and create final reports with alive subdomains"""
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    project_root = os.path.abspath(os.path.dirname(__file__))
    report_dir = os.path.join(project_root, f"{safe_domain}reports")

    final_txt_path = os.path.join(report_dir, f"{safe_domain}_final.txt")
    normalized_json_path = os.path.join(report_dir, f"{safe_domain}_normalized.json")

    combined_data = {}
    human_output = []

    # Initialize normalized with correct structure
    normalized = {
        "ip": [],
        "email": [],
        "domains": [domain],
        "subdomain": [],
        "alive_subdomain": []   # ✅ new key
    }

    if not os.path.isdir(report_dir):
        print(f"[!] No reports found for {domain}")
        return

    # Order matters for consistent output
    order = ["domain.json", "shodan.json", "scrapping.json", "bucket.json", f"{safe_domain}_recon.json"]

    for file in order:
        path = os.path.join(report_dir, file)
        if os.path.isfile(path):
            with open(path) as f:
                data = json.load(f)
                combined_data[file] = data
                human_output.append(f"\n=== {file} ===\n{json.dumps(data, indent=4)}")

                # Normalize via regex
                text = json.dumps(data)

                # Extract IPs and Emails
                normalized["ip"].extend(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
                normalized["email"].extend(
                    re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
                )

                # Extract subdomains (ending with target domain but not equal)
                found_subs = [
                    d for d in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
                    if d.endswith(domain) and d != domain
                ]
                normalized["subdomain"].extend(found_subs)

                # ✅ Special case: extract alive subdomains from recon JSON
                if file.endswith("_recon.json"):
                    if "alive" in data:
                        normalized["alive_subdomain"].extend(data["alive"])

    # Deduplicate lists
    normalized["ip"] = sorted(set(normalized["ip"]))
    normalized["email"] = sorted(set(normalized["email"]))
    normalized["subdomain"] = sorted(set(normalized["subdomain"]))
    normalized["alive_subdomain"] = sorted(set(normalized["alive_subdomain"]))

    # Write human-readable TXT
    with open(final_txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(human_output))

    # Write normalized JSON
    with open(normalized_json_path, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=4)

    print(f"\n[✓] Reports generated:")
    print(f"    → {final_txt_path}")
    print(f"    → {normalized_json_path}")
