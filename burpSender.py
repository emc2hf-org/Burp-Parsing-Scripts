#!/usr/bin/env python3

import argparse
import glob
import os
import requests
from urllib.parse import urljoin

def parse_burp_request(file_content):
    lines = file_content.splitlines()
    request_line = lines[0]
    method, path, _ = request_line.split()
    
    headers = {}
    body = None
    i = 1

    # Parse headers
    while i < len(lines):
        line = lines[i]
        i += 1
        if line == '':
            break  # End of headers
        key, value = line.split(':', 1)
        headers[key.strip()] = value.strip()
    
    # Remaining lines = body
    if i < len(lines):
        body = '\n'.join(lines[i:])

    return method, path, headers, body

def send_request(method, path, headers, body, proxy):
    # Build full URL from Host header + path
    host = headers.pop("Host", None)
    if not host:
        print("No Host header found. Skipping.")
        return
    url = urljoin(f"http://{host}", path)

    proxies = {
        "http": proxy,
        "https": proxy,
    }

    try:
        response = requests.request(method, url, headers=headers, data=body, proxies=proxies, verify=False, allow_redirects=False)
        print(f"[{response.status_code}] {method} {url}")
        print(response.text[:200])  # Print first 200 chars of response
    except Exception as e:
        print(f"Request to {url} failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Send Burp-style HTTP requests through a proxy")
    parser.add_argument("files", nargs="+", help="Request files (*.txt or multiple)")
    parser.add_argument("-p", "--proxy", required=True, help="Proxy URL (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    for pattern in args.files:
        for file_path in glob.glob(pattern):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                method, path, headers, body = parse_burp_request(content)
                send_request(method, path, headers, body, args.proxy)

if __name__ == "__main__":
    main()
