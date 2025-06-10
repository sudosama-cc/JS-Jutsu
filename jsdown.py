#!/usr/bin/env python3

import argparse
import os
import requests
from urllib.parse import urlparse
from pathlib import Path
from uuid import uuid4

def sanitize_filename(url):
    path = urlparse(url).path
    name = os.path.basename(path)
    return name if name.endswith(".js") else f"{uuid4().hex}.js"

def download_all(file, outdir):
    Path(outdir).mkdir(exist_ok=True)
    with open(file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"[+] {len(urls)} JS files to download...")

    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                name = sanitize_filename(url)
                path = os.path.join(outdir, name)
                with open(path, "wb") as f:
                    f.write(r.content)
                print(f"[✓] {url} → {name}")
            else:
                print(f"[!] {url} → HTTP {r.status_code}")
        except Exception as e:
            print(f"[!] {url} → Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="jsjutsu-down: Download JS files from list")
    parser.add_argument("-f", "--file", required=True, help="Input file with JS URLs")
    parser.add_argument("-d", "--dir", default="jsjutsu_downloads", help="Download directory")
    args = parser.parse_args()

    download_all(args.file, args.dir)

if __name__ == "__main__":
    main()
