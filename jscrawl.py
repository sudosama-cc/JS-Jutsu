#!/usr/bin/env python3

import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def find_js_links(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        script_tags = soup.find_all("script", src=True)
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        return list(set(urljoin(base, tag["src"]) for tag in script_tags))
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="jsjutsu-crawl: Extract JS URLs from a target website")
    parser.add_argument("-u", "--url", required=True, help="Target URL to crawl")
    parser.add_argument("-o", "--output", default="jsurls.txt", help="Output file for JS links")
    args = parser.parse_args()

    js_links = find_js_links(args.url)
    print(f"[+] Found {len(js_links)} JS files.")

    with open(args.output, "w") as f:
        for link in js_links:
            f.write(link + "\n")
    print(f"[+] Saved to {args.output}")

if __name__ == "__main__":
    main()
