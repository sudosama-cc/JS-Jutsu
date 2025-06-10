#!/usr/bin/env python3

import argparse
import os
import re
from pathlib import Path

JS_REGEX = r"([\"'])(\/?api\/[^\"'>\\\s]+|https?:\/\/[^\"'>\\\s]+)([\"'])"

def extract_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            matches = re.findall(JS_REGEX, content)
            return list(set(match[1] for match in matches))
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return []

def analyze_dir(directory, output):
    results = []
    for file in Path(directory).glob("*.js"):
        endpoints = extract_from_file(file)
        print(f"[+] {file.name}: {len(endpoints)} found")
        results.extend(endpoints)

    with open(output, "w") as out:
        for item in sorted(set(results)):
            out.write(item + "\n")
    print(f"[✓] Results saved to {output}")

def main():
    parser = argparse.ArgumentParser(description="jsjutsu-hunt: Analyze JS files for endpoints and URLs")
    parser.add_argument("-d", "--dir", required=True, help="Directory with JS files")
    parser.add_argument("-o", "--output", default="endpoints.txt", help="Output file")
    args = parser.parse_args()

    analyze_dir(args.dir, args.output)

if __name__ == "__main__":
    main()
