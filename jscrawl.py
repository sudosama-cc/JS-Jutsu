#!/usr/bin/env python3

import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os

def find_js_links(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }
        res = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        script_tags = soup.find_all("script", src=True)
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        return sorted(set(urljoin(base, tag["src"]) for tag in script_tags))
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return []

def save_output(js_links, domain, output_dir):
    parsed = urlparse(domain)
    fname = parsed.netloc or parsed.path
    fpath = os.path.join(output_dir, f"{fname}_js.txt")
    with open(fpath, "w") as f:
        for link in js_links:
            f.write(link + "\n")
    print(f"[+] Saved {len(js_links)} JS files → {fpath}")

def main():
    parser = argparse.ArgumentParser(description="🥷 jsjutsu-crawl: Extract JS URLs from web pages")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target domain (e.g. https://example.com)")
    group.add_argument("-list", "--listfile", help="File containing list of target domains")
    parser.add_argument("-o", "--output", default="jscrawl_output", help="Directory to save JS URLs")

    args = parser.parse_args()
    os.makedirs(args.output, exist_ok=True)

    targets = []
    if args.domain:
        targets = [args.domain.strip()]
    elif args.listfile:
        with open(args.listfile, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    for url in targets:
        print(f"[+] Crawling: {url}")
        js_links = find_js_links(url)
        save_output(js_links, url, args.output)

if __name__ == "__main__":
    main()
