#!/usr/bin/env python3

import argparse
import os
import re
from pathlib import Path

JS_REGEXES = {
    "API Endpoints": re.compile(r'([\'"])(\/?api\/[^\s\'"<>\\]+|https?:\/\/[^\s\'"<>\\]+)([\'"])', re.I),

    "Generic Secrets": re.compile(r'(api_key|apikey|secret|token|auth|access_token|client_secret)[\'"]?\s*[:=]\s*[\'"]([A-Za-z0-9\-_\.]+)[\'"]', re.I),

    "JWT Tokens": re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),

    "Emails": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),

    "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),

    "AWS Secret Key": re.compile(r'(?i)aws(.{0,20})?(secret|access)?(.{0,20})?["\'][0-9a-zA-Z\/+]{40}["\']'),

    "Google API Key": re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),

    "Slack Token": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),

    "Heroku API Key": re.compile(r'[hH]eroku(.{0,20})?["\']?[0-9a-fA-F]{32}'),

    "Passwords": re.compile(r'(password|passwd|pwd|passphrase|secret)[\'"]?\s*[:=]\s*[\'"]([^\'"]{6,})[\'"]', re.I),

    "Basic Auth Base64": re.compile(r'Basic\s[a-zA-Z0-9=+/]{10,}'),

    "Bearer Token": re.compile(r'Bearer\s[0-9a-zA-Z\-\._~\+/]+=*'),

    "Generic Hex": re.compile(r'[\da-fA-F]{16,}'),

    "IPv4 Addresses": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),

    "URL Encoded": re.compile(r'%[0-9a-fA-F]{2}'),

    "AWS ARN": re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[^\s\'"]+'),

    "Credit Card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
}

def extract_from_file(filepath):
    findings = {}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for name, pattern in JS_REGEXES.items():
                matches = pattern.findall(content)
                if matches:
                    # matches tipi regex tipine göre farklı olabilir
                    # tuple ise ilk elemanı al (gruplama durumunda)
                    if isinstance(matches[0], tuple):
                        extracted = [m[1] if len(m)>1 else m[0] for m in matches]
                    else:
                        extracted = matches
                    findings[name] = list(set(extracted))
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
    return findings

def analyze_dir(directory, output):
    aggregated = {}
    js_files = list(Path(directory).glob("*.js"))
    print(f"[+] Scanning {len(js_files)} JS files in {directory}")

    for file in js_files:
        file_findings = extract_from_file(file)
        print(f"[+] {file.name}: found {sum(len(v) for v in file_findings.values())} matches")
        for key, vals in file_findings.items():
            if key not in aggregated:
                aggregated[key] = set()
            aggregated[key].update(vals)

    # Kaydetme
    with open(output, "w") as out:
        for key, vals in aggregated.items():
            out.write(f"== {key} ==\n")
            for val in sorted(vals):
                out.write(val + "\n")
            out.write("\n")
    print(f"[✓] Analysis results saved to {output}")

def main():
    parser = argparse.ArgumentParser(description="jsjutsu-hunt: Analyze JS files for sensitive info and endpoints")
    parser.add_argument("-d", "--dir", required=True, help="Directory containing JS files")
    parser.add_argument("-o", "--output", default="jshunt_results.txt", help="Output file")
    args = parser.parse_args()

    analyze_dir(args.dir, args.output)

if __name__ == "__main__":
    main()
