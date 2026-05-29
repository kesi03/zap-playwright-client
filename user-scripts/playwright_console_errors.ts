#!/usr/bin/env npx tsx
/**
 * TypeScript Playwright example: captures browser console errors, JS exceptions,
 * and checks for mixed content loading during page navigation.
 * Uses the project's already-installed playwright npm package.
 */
import { chromium } from "playwright";
import * as fs from "node:fs";

interface Finding {
  url: string;
  category: string;
  description: string;
  evidence: string;
}

function getArgs(): Record<string, string> {
  const args: Record<string, string> = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = process.argv[i].replace(/^--/, "");
    args[key] = process.argv[i + 1] || "";
  }
  return args;
}

function writeOutput(findings: Finding[], outputPath?: string) {
  const json = JSON.stringify(findings, null, 2);
  if (outputPath) {
    fs.writeFileSync(outputPath, json);
  } else {
    console.log(json);
  }
}

async function main() {
  const args = getArgs();
  const targetUrl = args["target-url"];
  const proxy = args["proxy"];
  const outputJson = args["output-json"];
  const findings: Finding[] = [];

  if (!targetUrl) {
    findings.push({
      url: "",
      category: "User Script Finding",
      description: "Missing --target-url argument",
      evidence: "target-url is required",
    });
    writeOutput(findings, outputJson);
    return;
  }

  const browser = await chromium.launch({
    headless: true,
    proxy: proxy ? { server: proxy } : undefined,
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent:
      "Mozilla/5.0 (compatible; ZAP-Playwright-UserScript/1.0)",
  });

  const page = await context.newPage();

  const consoleErrors: string[] = [];
  const jsExceptions: string[] = [];
  const mixedContent: string[] = [];

  page.on("console", (msg) => {
    if (msg.type() === "error") {
      consoleErrors.push(msg.text());
    }
  });

  page.on("pageerror", (err) => {
    jsExceptions.push(err.message);
  });

  page.on("response", (response) => {
    const req = response.request();
    const reqUrl = req.url();
    const parsed = new URL(reqUrl);

    if (parsed.protocol === "http:" && targetUrl.startsWith("https")) {
      mixedContent.push(reqUrl);
    }
  });

  try {
    await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 30000 });

    if (consoleErrors.length > 0) {
      const top5 = consoleErrors.slice(0, 5);
      findings.push({
        url: targetUrl,
        category: "Information Disclosure",
        description: `Browser console logged ${consoleErrors.length} error(s) during page load`,
        evidence: top5.join(" | "),
      });
    }

    for (const errMsg of jsExceptions) {
      findings.push({
        url: targetUrl,
        category: "DOMXSS Advanced",
        description: `Uncaught JavaScript exception: ${errMsg.substring(0, 200)}`,
        evidence: errMsg,
      });
    }

    if (mixedContent.length > 0) {
      const top3 = mixedContent.slice(0, 3);
      findings.push({
        url: targetUrl,
        category: "Mixed Content",
        description: `Page loads ${mixedContent.length} resource(s) over HTTP on an HTTPS page`,
        evidence: top3.join(" | "),
      });
    }

    const scripts = await page.$$eval("script[src]", (els) =>
      els.map((el) => {
        const src = el.getAttribute("src") || "";
        const integrity = el.getAttribute("integrity");
        return { src, hasIntegrity: !!integrity };
      })
    );

    const scriptsWithoutSRI = scripts.filter((s) => !s.hasIntegrity);
    if (scriptsWithoutSRI.length > 0) {
      const top3 = scriptsWithoutSRI.slice(0, 3);
      findings.push({
        url: targetUrl,
        category: "Missing SRI",
        description: `${scriptsWithoutSRI.length} external script(s) loaded without Subresource Integrity`,
        evidence: top3.map((s) => s.src).join(" | "),
      });
    }
  } catch (err: any) {
    findings.push({
      url: targetUrl,
      category: "User Script Finding",
      description: `Playwright navigation failed: ${err.message}`,
      evidence: err.cause || err.message,
    });
  } finally {
    await browser.close();
  }

  writeOutput(findings, outputJson);
}

main();
