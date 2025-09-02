#!/usr/bin/env python3
import os
import json
import re

def generate_report(domain):
    """Read all module JSONs and create final reports"""
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    project_root = os.path.abspath(os.path.dirname(__file__))
    report_dir = os.path.join(project_root, f"{safe_domain}reports")

    final_txt_path = os.path.join(report_dir, f"{safe_domain}_final.txt")
    normalized_json_path = os.path.join(report_dir, f"{safe_domain}_normalized.json")

    combined_data = {}
    human_output = []

    # Initialize normalized with correct structure
    normalized = {"ip": [], "email": [], "domains": [domain], "subdomain": []}

    if not os.path.isdir(report_dir):
        print(f"[!] No reports found for {domain}")
        return

    # Ensure consistent order of module reports
    order = ["domain.json", "shodan.json", "scrapping.json", "bucket.json"]

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
                normalized["email"].extend(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))

                # Extract subdomains (only those ending with the target domain but not equal to it)
                normalized["subdomain"].extend(
                    [d for d in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
                     if d.endswith(domain) and d != domain]
                )

    # Deduplicate everything except "domains" (target domain should stay single)
    normalized["ip"] = sorted(set(normalized["ip"]))
    normalized["email"] = sorted(set(normalized["email"]))
    normalized["subdomain"] = sorted(set(normalized["subdomain"]))

    # Write human-readable TXT
    with open(final_txt_path, "w") as f:
        f.write("\n".join(human_output))

    # Write normalized JSON
    with open(normalized_json_path, "w") as f:
        json.dump(normalized, f, indent=4)

    print(f"\n[✓] Reports generated:")
    print(f"    → {final_txt_path}")
    print(f"    → {normalized_json_path}")
