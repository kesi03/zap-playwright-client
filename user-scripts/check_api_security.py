#!/usr/bin/env python3
import argparse
import json
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin

parser = argparse.ArgumentParser()
parser.add_argument("--target-url", required=True)
parser.add_argument("--proxy", default="")
parser.add_argument("--output-json", default="")
args = parser.parse_args()

findings = []
parsed = urlparse(args.target_url)
base = f"{parsed.scheme}://{parsed.netloc}"

proxy_handler = urllib.request.ProxyHandler({})
if args.proxy:
    proxy_handler = urllib.request.ProxyHandler(
        {"http": args.proxy, "https": args.proxy}
    )

opener = urllib.request.build_opener(proxy_handler)

common_api_paths = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/.well-known/",
    "/api/users",
    "/api/admin",
    "/health",
    "/actuator",
]

for path in common_api_paths:
    url = urljoin(base, path)
    try:
        req = urllib.request.Request(url, method="GET")
        with opener.open(req, timeout=8) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="ignore")[:500]

            if status == 200:
                findings.append(
                    {
                        "url": url,
                        "category": "Information Disclosure",
                        "description": f"API endpoint exposed: {path} (HTTP {status})",
                        "evidence": f"GET {url} → {status}",
                    }
                )

                if path in ("/api/users", "/api/admin"):
                    findings.append(
                        {
                            "url": url,
                            "category": "Broken Access Control",
                            "description": f"Sensitive API endpoint accessible without auth: {path}",
                            "evidence": f"Unauthenticated access to {url}",
                        }
                    )

            if status in (401, 403) and path in ("/api", "/api/v1", "/api/v2"):
                pass

    except urllib.error.HTTPError as e:
        if e.code == 401:
            findings.append(
                {
                    "url": url,
                    "category": "Information Disclosure",
                    "description": f"API endpoint exists (HTTP 401): {path}",
                    "evidence": f"GET {url} → {e.code}",
                }
            )
        elif e.code == 403:
            pass
        elif e.code == 405:
            findings.append(
                {
                    "url": url,
                    "category": "Information Disclosure",
                    "description": f"API endpoint discovered via method not allowed: {path}",
                    "evidence": f"GET {url} → {e.code}",
                }
            )
    except Exception as e:
        pass

json_headers = {"Content-Type": "application/json"}
for path in ["/graphql"]:
    url = urljoin(base, path)
    try:
        introspection = json.dumps({"query": "{__schema{types{name}}}"}).encode()
        req = urllib.request.Request(
            url, data=introspection, headers=json_headers, method="POST"
        )
        with opener.open(req, timeout=8) as resp:
            findings.append(
                {
                    "url": url,
                    "category": "GraphQL Introspection",
                    "description": "GraphQL introspection query succeeded — schema can be enumerated",
                    "evidence": f"POST {url} introspection → {resp.status}",
                }
            )
    except Exception:
        pass

output = json.dumps(findings, indent=2)
if args.output_json:
    with open(args.output_json, "w") as f:
        f.write(output)
else:
    print(output)
