#!/usr/bin/env python3

import os
import base64
import argparse
import csv
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs

# Reads a Burp Exported .xml file and saves "unique" parameter requests
def parse_burp_xml(input_file, output_dir, csv_file=None):
    os.makedirs(output_dir, exist_ok=True)
    seen = set()
    counter = 1
    csv_rows = []

    tree = ET.parse(input_file)
    root = tree.getroot()

    for item in root.findall("item"):
        method = item.findtext("method")
        path = item.findtext("path")
        url = item.findtext("url")
        parsed_url = urlparse(url)

        request_elem = item.find("request")
        base64_encoded = request_elem.attrib.get("base64", "false") == "true"
        request_data = request_elem.text.strip()

        if base64_encoded:
            raw_request_bytes = base64.b64decode(request_data)
            raw_request = raw_request_bytes.decode("iso-8859-1")
        else:
            raw_request_bytes = request_data.encode("iso-8859-1")
            raw_request = request_data

        param_names = set(parse_qs(parsed_url.query).keys())

        # If POST, try to extract param names from body
        if method.upper() == "POST":
            parts = raw_request.split("\r\n\r\n", 1)
            if len(parts) == 2:
                body = parts[1]
                body_params = parse_qs(body)
                param_names.update(body_params.keys())

        # Skip if no parameters found
        if not param_names:
            continue

        # Deduplication key
        param_key = (method, parsed_url.path, tuple(sorted(param_names)))
        if param_key in seen:
            continue
        seen.add(param_key)

        # Save raw request to individual file
        filename = f"request_{counter:04d}.txt"
        with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:
            f.write(raw_request)
        counter += 1

        # Prepare CSV row
        if csv_file:
            response_elem = item.find("response")
            if response_elem is not None and response_elem.text:
                response_data = response_elem.text.strip()
                response_base64 = (
                    response_data
                    if response_elem.attrib.get("base64", "false") == "true"
                    else base64.b64encode(response_data.encode("iso-8859-1")).decode()
                )
            else:
                response_base64 = ""

            # Apply URL-safe base64 transformations
            request_b64 = base64.b64encode(raw_request_bytes).decode().replace('/', '_').replace('+', '-')
            response_b64 = response_base64.replace('/', '_').replace('+', '-') if response_base64 else ""

            csv_rows.append([
                request_b64,
                response_b64,
                method,
                url
            ])

    # Write CSV if requested
    if csv_file:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(csv_rows)
        print(f"Exported CSV to '{csv_file}'")

    print(f"Saved {counter - 1} unique requests with parameters to '{output_dir}/'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse Burp Suite XML export and extract unique parameterized requests.")
    parser.add_argument("-f", "--file", required=True, help="Path to Burp Suite .xml export file")
    parser.add_argument("-o", "--output", default="parsed_requests", help="Output directory for saved requests")
    parser.add_argument("--csv", help="Optional output CSV in [request_base64,response_base64,method,url] format")

    args = parser.parse_args()
    parse_burp_xml(args.file, args.output, args.csv)
