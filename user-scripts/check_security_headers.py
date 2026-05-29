#!/usr/bin/env python3
import argparse
import json
import urllib.request
import urllib.error

parser = argparse.ArgumentParser()
parser.add_argument("--target-url", required=True)
parser.add_argument("--proxy", default="")
parser.add_argument("--output-json", default="")
args = parser.parse_args()

findings = []

proxy_handler = (
    urllib.request.ProxyHandler({})
    if not args.proxy
    else urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy})
)
opener = urllib.request.build_opener(proxy_handler)

try:
    req = urllib.request.Request(args.target_url, method="GET")
    with opener.open(req, timeout=15) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}

        if "strict-transport-security" not in headers:
            findings.append(
                {
                    "url": args.target_url,
                    "category": "Security Misconfiguration",
                    "description": "Missing Strict-Transport-Security header",
                    "evidence": "HSTS not set",
                }
            )

        if "x-content-type-options" not in headers:
            findings.append(
                {
                    "url": args.target_url,
                    "category": "Security Misconfiguration",
                    "description": "Missing X-Content-Type-Options header",
                    "evidence": "X-Content-Type-Options not set",
                }
            )

        if "x-frame-options" not in headers:
            findings.append(
                {
                    "url": args.target_url,
                    "category": "Clickjacking",
                    "description": "Missing X-Frame-Options header",
                    "evidence": "Page may be framable",
                }
            )

        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(
                {
                    "url": args.target_url,
                    "category": "CSP Bypass",
                    "description": "Missing Content-Security-Policy header",
                    "evidence": "No CSP set",
                }
            )

except Exception as e:
    findings.append(
        {
            "url": args.target_url,
            "category": "User Script Finding",
            "description": f"Script error: {e}",
            "evidence": str(e),
        }
    )

output = json.dumps(findings, indent=2)
if args.output_json:
    with open(args.output_json, "w") as f:
        f.write(output)
else:
    print(output)
