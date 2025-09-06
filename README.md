-> create virtual environment python3 -m venv venv
-> activate it source venv/bin/activate
-> pip install -r requirements.txt
-> sudo apt install golang -y
-> download httpx with go
-> sudo apt install spiderfoot
-> go to /usr/share/spiderfoot/modules
-> sudo nano sfp_jsonimport.py
-> paste
```
import os
import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin

class sfp_jsonimport(SpiderFootPlugin):

    meta = {
        'name': "JSON Importer (Custom)",
        'summary': "Imports recon findings from a dynamically chosen JSON file into SpiderFoot and correlates them.",
        'flags': [],
        'useCases': ["Investigate"],
        'categories': ["Custom"]
    }

    opts = {}
    optdescs = {}

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        for opt in userOpts:
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return []

    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "S3_BUCKET",
            "PASSWORD",
            "TCP_PORT_OPEN",
            "PHONE_NUMBER",
            "SOFTWARE_USED",
            "VULNERABILITY_CVE",
            "EMAILADDR"
        ]

    def start(self):
        target = os.environ.get("SPF_TARGET")
        if not target:
            self.sf.error("SPF_TARGET environment variable not set.")
            return

        # ✅ fixed path (no backslashes)
        json_path = f"/home/kali/cts_recon/{target}_spf.json"

        if not os.path.isfile(json_path):
            self.sf.error(f"JSON file not found: {json_path}")
            return

        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            self.sf.error(f"Error loading JSON file: {e}")
            return

        root_evt = SpiderFootEvent("ROOT", f"JSON Import Root: {target}", self.__class__.__name__, None)
        self.notifyListeners(root_evt)

        root_domain = data.get("domain", target)
        domain_evt = SpiderFootEvent("DOMAIN_NAME", root_domain, self.__class__.__name__, root_evt)
        self.notifyListeners(domain_evt)
        self.sf.info(f"Imported root domain: {root_domain}")

        # Subdomains
        for dom in data.get("subdomains", []):
            evt = SpiderFootEvent("DOMAIN_NAME", dom, self.__class__.__name__, domain_evt)
            self.notifyListeners(evt)
            self.sf.info(f"Imported subdomain: {dom}")

        # IPs
        for ip, ipdata in data.get("ips", {}).items():
            ip_evt = SpiderFootEvent("IP_ADDRESS", ip, self.__class__.__name__, domain_evt)
            self.notifyListeners(ip_evt)
            self.sf.info(f"Imported IP: {ip}")

            for port in ipdata.get("open_ports", []):
                port_evt = SpiderFootEvent("TCP_PORT_OPEN", str(port), self.__class__.__name__, ip_evt)
                self.notifyListeners(port_evt)
                self.sf.info(f"Imported open port {port} on {ip}")

            for cve in ipdata.get("cves", []):
                cve_evt = SpiderFootEvent("VULNERABILITY_GENERAL", cve, self.__class__.__name__, ip_evt)
                self.notifyListeners(cve_evt)
                self.sf.info(f"Imported CVE {cve} for {ip}")

        # Emails
        for email in data.get("emails", []):
            email_evt = SpiderFootEvent("EMAILADDR", email, self.__class__.__name__, domain_evt)
            self.notifyListeners(email_evt)
            self.sf.info(f"Imported email: {email}")

        # Technologies
        for tech in data.get("technologies", []):
            tech_evt = SpiderFootEvent("SOFTWARE_USED", tech, self.__class__.__name__, domain_evt)
            self.notifyListeners(tech_evt)
            self.sf.info(f"Imported technology: {tech}")

        self.sf.info("✅ JSON Import completed successfully.")
```
-> copy the path of the project and add /{target}_lite.json
example json_path = f"/home/kali/cts_recon/{target}_spf.json"

->run the file python pipeline.py

enjoy
