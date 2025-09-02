import subprocess, requests, time, json
from colorama import Fore, Style, init

init(autoreset=True)

def run_subfinder(domain):
    print(Fore.CYAN + "[*] Running Subfinder..." + Style.RESET_ALL)
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True
        )
        return result.stdout.splitlines()
    except:
        return []

def fetch_crtsh(domain, retries=3):
    subs = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for i in range(retries):
        try:
            print(Fore.CYAN + f"[*] crt.sh attempt {i+1}" + Style.RESET_ALL)
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                data = r.json()
                subs += [entry["name_value"] for entry in data if "name_value" in entry]
                break
        except:
            time.sleep(5)
    return list(set(subs))

def probe_alive(subdomains):
    print(Fore.YELLOW + "[*] Probing alive hosts with httpx..." + Style.RESET_ALL)
    alive = []
    try:
        result = subprocess.run(
            ["httpx", "-silent"],
            input="\n".join(subdomains),
            capture_output=True, text=True
        )
        alive = result.stdout.splitlines()
    except:
        pass
    return alive

def run_tech_scans(alive_domains):
    tech_list = []
    try:
        result = subprocess.run(
            ["httpx", "-silent", "-tech-detect"],
            input="\n".join(alive_domains),
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.split(" [")
            domain = parts[0].strip()
            techs = parts[1].replace("]", "").split(", ") if len(parts) > 1 else []
            tech_list.append({"domain": domain, "technologies": techs})
    except:
        pass
    return tech_list

def process(domain, reports_dir):
    print(Fore.YELLOW + f"\n[+] Running domain module for {domain}" + Style.RESET_ALL)
    subdomains = list(set(run_subfinder(domain) + fetch_crtsh(domain)))
    alive = probe_alive(subdomains)
    tech = run_tech_scans(alive)
    findings = {
        "module": "domain",
        "target": domain,
        "subdomains": subdomains,
        "alive_hosts": alive,
        "technologies": tech
    }
    path = f"{reports_dir}/domain.json"
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)
    print(Fore.GREEN + f"[✓] domain results saved → {path}" + Style.RESET_ALL)
