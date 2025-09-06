import subprocess
import json
import os

# Vulnerability-related GF patterns only
VULN_PATTERNS = [
    "xss", "domxss", "sqli", "sqli-error", "lfi",
    "rce", "rce-2", "redirect", "ssrf", "ssti",
    "idor", "xxe", "xpath"
]

def run_gau(domain):
    """Fetch URLs using gau"""
    try:
        result = subprocess.run(
            ["gau", domain],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running gau: {e}")
        return []

def run_gf(pattern, urls):
    """Run gf pattern on given URLs"""
    try:
        proc = subprocess.Popen(
            ["gf", pattern],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output, _ = proc.communicate("\n".join(urls))
        return output.splitlines() if output else []
    except Exception as e:
        print(f"[!] Error running gf {pattern}: {e}")
        return []

def main():
    domain = input("Enter domain to scan (e.g., example.com): ").strip()
    if not domain:
        print("Domain is required!")
        return

    print(f"\n[+] Fetching URLs for {domain} using gau...")
    urls = run_gau(domain)

    if not urls:
        print("[!] No URLs found with gau.")
        return

    results = {}
    for pattern in VULN_PATTERNS:
        print(f"[+] Running gf pattern: {pattern}")
        matches = run_gf(pattern, urls)
        if matches:
            results[f"gf_{pattern}"] = matches

    # Save results to JSON
    file_path = f"{domain}_vuln_gau_gf.json"
    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] Results saved to {file_path}")

if __name__ == "__main__":
    main()
