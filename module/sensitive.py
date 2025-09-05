#!/usr/bin/env python3
import os
import json
import time
import requests
from serpapi import GoogleSearch
from colorama import init, Fore, Style
from threading import Thread
from itertools import cycle

# ==============================
# CONFIG
# ==============================
API_KEY = "882df33509cf14b58f1c79fdfda125f75b67795d7a49fabdd9dfcda4a32ac203"  # Replace with your SerpAPI key

# ==============================
# Google Dorking
# ==============================
def run_dork(query):
    search = GoogleSearch({
        "q": query,
        "api_key": API_KEY
    })
    results = search.get_dict()
    dork_results = []

    if "organic_results" in results:
        for res in results["organic_results"]:
            entry = {
                "title": res.get("title"),
                "link": res.get("link"),
            }
            dork_results.append(entry)
    return dork_results

def google_dorks(domain):
    print(Fore.LIGHTBLUE_EX + f"\n[*] Running Google dorks for {domain} ...")
    dorks = {
        "password_dork": f'site:{domain} intext:password (ext:xls OR ext:xml OR ext:xlsx OR ext:json OR ext:sql OR ext:log OR ext:bak OR ext:cfg OR ext:ini OR ext:yaml OR ext:yml OR ext:db OR ext:conf)',
        "confidential_dork": f'site:{domain} (\"confidential\" OR \"internal use only\") (ext:doc OR ext:docx OR ext:pptx OR ext:pdf OR ext:txt OR ext:csv OR ext:md OR ext:log)',
        "uncommon_ext_dork": f'site:{domain} (ext:zip OR ext:tar OR ext:gz OR ext:7z OR ext:rar OR ext:bak OR ext:db OR ext:config OR ext:sqlite OR ext:key OR ext:pem OR ext:crt OR ext:asc)'
    }

    results = {}
    for name, query in dorks.items():
        print(Fore.LIGHTGREEN_EX + f"[+] Running {name} ...")
        res = run_dork(query)
        results[name] = res
        print(Fore.LIGHTYELLOW_EX + f"    Found {len(res)} results for {name}")
    return results

# ==============================
# Wayback Machine
# ==============================
FILE_EXTENSIONS = [
    ".xls",".xml",".xlsx",".json",".pdf",".sql",".doc",".docx",".pptx",".txt",
    ".zip",".tar",".gz",".tgz",".bak",".7z",".rar",".log",".cache",".secret",
    ".db",".backup",".yml",".config",".csv",".yaml",".md",".md5",".exe",
    ".bin",".ini",".bat",".sh",".deb",".rpm",".img",".apk",".dmg",
    ".tmp",".crt",".pem",".key",".pub",".asc",".OLD",".PHP",".BAK",".SAVE",".ZIP",
    ".example",".php",".conf",".swp",".old",".tar.gz",
    ".jar",".bz2",".php.save",".php-backup",".php~",".aspx~",".asp~",".bkp",
    ".jsp~",".sql.gz",".sql.zip",".sql.tar.gz",".sql~",".swp~",".tar.bz2",".lz",".xz",
    ".tar.z",".sqlite",".sqlitedb",".sql.7z",".sql.bz2",".sql.lz",".sql.rar",
    ".sql.xz",".sql.z",".sql.tar.z",".war",".backup.zip",".backup.tar",".backup.tgz",
    ".backup.sql",".tar.bz",".tgz.bz",".tar.lz",".backup.7z",".backup.gz"
]

def loader_animation(message="Processing..."):
    animation = cycle(["|", "/", "-", "\\"])
    while not stop_loader:
        print(f"\r{message} {next(animation)}", end="")
        time.sleep(0.1)
    print("\r" + " " * len(message) + "\r", end="")

def fetch_wayback(domain, file_extensions):
    print(Fore.LIGHTBLUE_EX + f"\n[*] Fetching URLs from The Wayback Machine for {domain} ...")
    archive_url = f'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/'

    global stop_loader
    stop_loader = False
    loader_thread = Thread(target=loader_animation, args=("Fetching URLs...",))
    loader_thread.start()

    max_retries = 3
    retry_delay = 5
    attempt = 0

    while attempt < max_retries:
        try:
            with requests.get(archive_url, stream=True, timeout=60) as response:
                response.raise_for_status()
                print(Fore.LIGHTGREEN_EX + "\nStreaming response from archive...")

                url_list = []
                total_lines = 0
                for line in response.iter_lines(decode_unicode=True):
                    if line:
                        url_list.append(line)
                        total_lines += 1
                        if total_lines % 1000 == 0:
                            print(f"\rFetched {total_lines} URLs...", end="")

                print(Fore.LIGHTGREEN_EX + f"\nFetched {total_lines} URLs from archive.")
                stop_loader = True
                loader_thread.join()

                results = {}
                for ext in file_extensions:
                    key = ext.strip(".").lower() + "_urls"
                    filtered = [url for url in url_list if url.lower().endswith(ext.lower())]
                    if filtered:
                        results[key] = filtered
                return results

        except requests.exceptions.RequestException as e:
            attempt += 1
            if attempt < max_retries:
                print(Fore.LIGHTYELLOW_EX + f"\nAttempt {attempt} failed: {e}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print(Fore.LIGHTYELLOW_EX + f"\nError fetching URLs after {max_retries} attempts: {e}")
                stop_loader = True
                loader_thread.join()
                return {}

# ==============================
# Pipeline Hook
# ==============================
def process(domain):
    """Entry point for pipeline.py"""
    return {
        "google_dorks": google_dorks(domain),
        "wayback_machine": fetch_wayback(domain, FILE_EXTENSIONS)
    }

# ==============================
# CLI Mode
# ==============================
if __name__ == "__main__":
    init()

    domain = input(Fore.LIGHTBLUE_EX + "\nEnter the target domain (e.g., example.com): ").strip()
    if not domain:
        print(Fore.LIGHTYELLOW_EX + "Target domain required. Exiting.")
        exit()

    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"\nProcessing domain: {domain}")

    results = process(domain)

    file_path = f"{domain}_deep.json"
    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)

    print(Fore.LIGHTGREEN_EX + f"\nCombined results saved to {file_path}")
    print(Fore.LIGHTBLUE_EX + "\nProcess complete.\n")
