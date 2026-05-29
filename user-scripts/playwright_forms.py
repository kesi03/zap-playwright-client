#!/usr/bin/env python3
"""
Playwright Python example: discovers forms and tests for autocomplete=off bypass.
Requires: pip install playwright && playwright install chromium
"""

import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--target-url", required=True)
parser.add_argument("--proxy", default="")
parser.add_argument("--output-json", default="")
args = parser.parse_args()
findings = []

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    findings.append(
        {
            "url": args.target_url,
            "category": "User Script Finding",
            "description": "playwright Python package not installed. Run: pip install playwright && playwright install chromium",
            "evidence": "ImportError: playwright.sync_api",
        }
    )
    output = json.dumps(findings, indent=2)
    if args.output_json:
        with open(args.output_json, "w") as f:
            f.write(output)
    else:
        print(output)
    sys.exit(0)

with sync_playwright() as p:
    proxy_config = {"server": args.proxy} if args.proxy else None
    browser = p.chromium.launch(headless=True, proxy=proxy_config)
    context = browser.new_context(
        ignore_https_errors=True,
        user_agent="Mozilla/5.0 (compatible; ZAP-Playwright/1.0)",
    )
    page = context.new_page()

    try:
        page.goto(args.target_url, wait_until="networkidle", timeout=30000)

        password_inputs = page.query_selector_all("input[type='password']")
        for inp in password_inputs:
            auto = inp.get_attribute("autocomplete")
            form_id = inp.evaluate(
                "el => (el.closest('form') || {}).id || el.name || 'unnamed'"
            )
            if auto is None or auto == "on":
                findings.append(
                    {
                        "url": args.target_url,
                        "category": "Autocomplete Sensitive",
                        "description": f"Password field '{form_id}' has autocomplete={auto or 'missing'} — credentials may be cached",
                        "evidence": f"<input type=password name={form_id} autocomplete={auto}>",
                    }
                )

        forms = page.query_selector_all("form")
        for form in forms:
            action = form.get_attribute("action") or "(self)"
            method = (form.get_attribute("method") or "get").upper()
            if method == "GET" and form.query_selector_all("input[type='password']"):
                findings.append(
                    {
                        "url": args.target_url,
                        "category": "Insecure Design",
                        "description": f"Form with password field uses GET method — credentials exposed in URL",
                        "evidence": f"<form method=GET action={action}> with password field",
                    }
                )

            if action and action.startswith("http://"):
                findings.append(
                    {
                        "url": args.target_url,
                        "category": "Login Over HTTP",
                        "description": f"Form submits credentials over unencrypted HTTP: {action}",
                        "evidence": f"<form action={action}>",
                    }
                )

        local_storage = page.evaluate("() => JSON.stringify(window.localStorage)")
        storage_data = json.loads(local_storage)
        for key in storage_data:
            val = str(storage_data[key]).lower()
            if any(
                word in val for word in ["token", "secret", "password", "jwt", "apikey"]
            ):
                findings.append(
                    {
                        "url": args.target_url,
                        "category": "Storage Secrets",
                        "description": f"Sensitive data in localStorage: key='{key}'",
                        "evidence": f"localStorage['{key}'] contains potential secret",
                    }
                )

    except Exception as e:
        findings.append(
            {
                "url": args.target_url,
                "category": "User Script Finding",
                "description": f"Playwright navigation failed: {e}",
                "evidence": str(e),
            }
        )
    finally:
        browser.close()

output = json.dumps(findings, indent=2)
if args.output_json:
    with open(args.output_json, "w") as f:
        f.write(output)
else:
    print(output)
