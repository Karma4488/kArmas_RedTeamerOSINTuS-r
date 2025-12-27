#!/usr/bin/env python3
# kArmas_RedTeamerOSINTuSɛr
# Single-file OSINT Username Intelligence Framework
# Termux 118.3 / Android 16 compatible
# Made in Red heart & l0v3 bY kArmasec 

import asyncio
import aiohttp
import argparse
import json
import csv
import sys
from datetime import datetime
from typing import List, Dict
from colorama import Fore, Style, init

init(autoreset=True)

# =========================
# Red Team banner / prompt
# =========================
BANNER = f"""
{Fore.GREEN}
██╗  ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗ ███████╗
██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝
█████╔╝ ███████║██████╔╝██╔████╔██║███████║███████╗
██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║╚════██║
██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝

kArmas_RedTeamerOSINTuSɛr
Authorized Red Team / OSINT Operations Only
Green Matrix Mode: ENABLED
{Style.RESET_ALL}
"""

# =========================
# Runtime configuration
# =========================
TIMEOUT = 12
MAX_CONCURRENCY = 25
HEADERS = {
    "User-Agent": "OSINT-Research/1.0 (Authorized)"
}

# =========================
# Global + Regional Coverage
# =========================
REGIONS = {
    "US": {
        "domains": ["com", "us"],
        "sites": [
            ("Facebook", "https://www.facebook.com/{u}"),
            ("Twitter/X", "https://twitter.com/{u}"),
            ("LinkedIn", "https://www.linkedin.com/in/{u}"),
            ("Reddit", "https://www.reddit.com/user/{u}")
        ]
    },
    "UK": {
        "domains": ["co.uk", "uk"],
        "sites": [
            ("Gumtree UK", "https://www.gumtree.com/profile/{u}"),
            ("Mumsnet", "https://www.mumsnet.com/Talk/profile/{u}")
        ]
    },
    "DK": {
        "domains": ["dk"],
        "sites": [
            ("Amino", "https://www.amino.dk/user/{u}"),
            ("ScooterGalleri", "https://www.scootergalleri.dk/bruger/{u}")
        ]
    },
    "AU": {
        "domains": ["com.au", "au"],
        "sites": [
            ("Gumtree AU", "https://www.gumtree.com.au/profile/{u}"),
            ("Whirlpool", "https://forums.whirlpool.net.au/user/{u}")
        ]
    },
    "IN": {
        "domains": ["in"],
        "sites": [
            ("ShareChat", "https://sharechat.com/profile/{u}")
        ]
    },
    "PK": {
        "domains": ["pk"],
        "sites": [
            ("PakWheels", "https://www.pakwheels.com/users/{u}")
        ]
    }
}

GLOBAL_SITES = [
    ("GitHub", "https://github.com/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("Telegram", "https://t.me/{u}"),
    ("Instagram", "https://www.instagram.com/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Medium", "https://medium.com/@{u}"),
    ("Dev.to", "https://dev.to/{u}")
]

DOMAIN_TEMPLATES = [
    ("WordPress", "https://{u}.wordpress.{d}"),
    ("Blogger", "https://{u}.blogspot.{d}")
]

# =========================
# Dark-web index checks
# Public OSINT indexes via clearnet
# =========================
DARKWEB_INDEXES = [
    {
        "name": "Ahmia",
        "url": "https://ahmia.fi/search/?q={u}"
    },
    {
        "name": "DarkSearch",
        "url": "https://darksearch.io/api/search?query={u}"
    }
]

# =========================
# Build SITES list
# =========================
SITES: List[Dict] = []

for name, tpl in GLOBAL_SITES:
    SITES.append({"name": name, "url": tpl.replace("{u}", "{username}"), "status": [200]})

for region, cfg in REGIONS.items():
    for name, tpl in cfg["sites"]:
        SITES.append({"name": f"{name} ({region})", "url": tpl.replace("{u}", "{username}"), "status": [200]})
    for d in cfg["domains"]:
        for name, tpl in DOMAIN_TEMPLATES:
            SITES.append({
                "name": f"{name} {d.upper()}",
                "url": tpl.replace("{u}", "{username}").replace("{d}", d),
                "status": [200]
            })

# =========================
# Detection logic
# =========================
def detect(site: Dict, status: int, body: str) -> bool:
    if "status" in site and status in site["status"]:
        return True
    return False

# =========================
# Core scanner
# =========================
class OSINTScanner:
    def __init__(self, username: str):
        self.username = username
        self.results = []
        self.sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def fetch(self, session: aiohttp.ClientSession, site: Dict):
        url = site["url"].replace("{username}", self.username)
        async with self.sem:
            try:
                async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as r:
                    text = await r.text(errors="ignore")
                    found = detect(site, r.status, text)
                    if found:
                        print(f"{Fore.GREEN}[+] FOUND{Style.RESET_ALL} {site['name']}")
                        self.results.append({
                            "platform": site["name"],
                            "url": url,
                            "status": r.status
                        })
            except Exception:
                pass

    async def darkweb_checks(self, session: aiohttp.ClientSession):
        for idx in DARKWEB_INDEXES:
            url = idx["url"].replace("{u}", self.username)
            try:
                async with session.get(url, headers=HEADERS, timeout=TIMEOUT) as r:
                    if r.status == 200:
                        print(f"{Fore.GREEN}[+] Dark-web index hit:{Style.RESET_ALL} {idx['name']}")
                        self.results.append({
                            "platform": f"DarkWeb Index: {idx['name']}",
                            "url": url,
                            "status": r.status
                        })
            except Exception:
                pass

    async def run(self):
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch(session, s) for s in SITES]
            await asyncio.gather(*tasks)
            await self.darkweb_checks(session)

    def save(self):
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        j = f"results_{ts}.json"
        c = f"results_{ts}.csv"

        with open(j, "w", encoding="utf-8") as jf:
            json.dump(self.results, jf, indent=2)

        with open(c, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=["platform", "url", "status"])
            writer.writeheader()
            writer.writerows(self.results)

        print(f"\n{Fore.GREEN}Output:{Style.RESET_ALL} {j}, {c}")

# =========================
# CLI
# =========================
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="kArmas_RedTeamerOSINTuSɛr – Username OSINT (Global + Dark-web Index)"
    )
    parser.add_argument("-u", "--username", required=True)
    args = parser.parse_args()

    scanner = OSINTScanner(args.username)
    asyncio.run(scanner.run())
    scanner.save()

if __name__ == "__main__":
    main()
