#!/usr/bin/env npx tsx
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

async function main() {
  const args = getArgs();
  const targetUrl = args["target-url"];
  const outputJson = args["output-json"];
  const findings: Finding[] = [];

  if (!targetUrl) {
    findings.push({
      url: "",
      category: "User Script Finding",
      description: "Missing --target-url argument",
      evidence: "target-url is required",
    });
    return writeOutput(findings, outputJson);
  }

  try {
    const response = await fetch(targetUrl);
    const status = response.status;
    const contentType = response.headers.get("content-type") || "";

    if (status >= 400) {
      findings.push({
        url: targetUrl,
        category: "Security Misconfiguration",
        description: `Target returned HTTP ${status} ${response.statusText}`,
        evidence: `HTTP ${status} for ${targetUrl}`,
      });
    }

    if (response.redirected) {
      findings.push({
        url: targetUrl,
        category: "Information Disclosure",
        description: `Request redirected to ${response.url}`,
        evidence: `Redirect chain: ${targetUrl} -> ${response.url}`,
      });
    }

    if (contentType.includes("text/html")) {
      const html = await response.text();
      const formCount = (html.match(/<form[\s>]/gi) || []).length;
      if (formCount > 20) {
        findings.push({
          url: targetUrl,
          category: "Information Disclosure",
          description: `Page has ${formCount} forms — possible excessive attack surface`,
          evidence: `Found ${formCount} <form> elements`,
        });
      }
    }
  } catch (err: any) {
    findings.push({
      url: targetUrl,
      category: "User Script Finding",
      description: `Failed to reach target: ${err.message}`,
      evidence: err.cause || err.message,
    });
  }

  writeOutput(findings, outputJson);
}

function writeOutput(findings: Finding[], outputPath?: string) {
  const json = JSON.stringify(findings, null, 2);
  if (outputPath) {
    require("fs").writeFileSync(outputPath, json);
  } else {
    console.log(json);
  }
}

main();
