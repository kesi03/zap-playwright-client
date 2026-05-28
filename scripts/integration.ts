import { readFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, execSync } from "node:child_process";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET_URL = "http://example.com";
const ZAP_API = "http://127.0.0.1:8080";
const POLL_MS = 2000;
const TIMEOUT_MS = 120_000;
const LOG_DIR = join(execSync("echo %USERPROFILE%", { shell: true }).toString().trim(), ".pm2", "logs");
const ERROR_LOG = join(LOG_DIR, "zap-daemon-error.log");
const OUT_LOG = join(LOG_DIR, "zap-daemon-out.log");

interface AlertMatch {
  url: string;
  category: string;
  description: string;
}

function readLinesFrom(file: string, skip: number): { lines: string[]; total: number } {
  try {
    if (!existsSync(file)) return { lines: [], total: 0 };
    const content = readFileSync(file, "utf-8");
    const lines = content.split("\n");
    const tail = skip > 0 && skip < lines.length ? lines.slice(skip) : lines;
    return { lines: tail, total: lines.length };
  } catch {
    return { lines: [], total: 0 };
  }
}

function matchAlerts(lines: string[]): AlertMatch[] {
  const out: AlertMatch[] = [];
  for (const line of lines) {
    const m = line.match(/Created ZAP alert for (\S+): \[([^\]]+)\]\s*(.+)/);
    if (m) out.push({ url: m[1], category: m[2], description: m[3].trim() });
  }
  return out;
}

async function waitForZap(ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(ZAP_API + "/JSON/core/view/version/");
      if (r.ok) return true;
    } catch { /* */ }
    await new Promise(r => setTimeout(r, 2000));
  }
  return false;
}

async function main() {
  console.log("=== Playwright Client Integration Test ===\n");

  if (!(await waitForZap(5000))) {
    console.log("ZAP not running – starting via npm run dev ...");
    const r = spawnSync("npm", ["run", "dev"], { cwd: ROOT, stdio: "inherit", shell: true, timeout: 120_000 });
    if (r.status !== 0) { console.error("ZAP start failed"); process.exit(1); }
    if (!(await waitForZap(60_000))) { console.error("ZAP not ready"); process.exit(1); }
  }

  console.log("ZAP is ready\n");

  const errSize = readLinesFrom(ERROR_LOG, 0).total;
  const outSize = readLinesFrom(OUT_LOG, 0).total;

  console.log("Calling runCrawlAndScan for " + TARGET_URL + " ...\n");
  const resp = await fetch(ZAP_API + "/JSON/playwrightclient/action/runCrawlAndScan?url=" + encodeURIComponent(TARGET_URL));
  const data: any = await resp.json();
  console.log("Response:", JSON.stringify(data));

  if (data.result !== "started") {
    console.error("Unexpected API response");
    process.exit(1);
  }

  console.log("\nMonitoring logs for up to " + (TIMEOUT_MS / 1000) + "s ...\n");

  const alerts: AlertMatch[] = [];
  const deadline = Date.now() + TIMEOUT_MS;
  let prevErr = errSize;
  let prevOut = outSize;

  while (Date.now() < deadline) {
    const err = readLinesFrom(ERROR_LOG, prevErr);
    prevErr = err.total;
    const out = readLinesFrom(OUT_LOG, prevOut);
    prevOut = out.total;

    for (const a of matchAlerts([...err.lines, ...out.lines])) {
      alerts.push(a);
      console.log("  [ALERT] " + a.url + "  [" + a.category + "]  " + a.description);
    }

    if (alerts.length > 0) break;
    await new Promise(r => setTimeout(r, POLL_MS));
  }

  const elapsed = ((Date.now() - (deadline - TIMEOUT_MS)) / 1000).toFixed(1);

  console.log("\n=== Results (" + elapsed + "s) ===");
  console.log("Playwright alerts found in logs: " + alerts.length);

  if (alerts.length > 0) {
    const byCat = new Map<string, number>();
    const byUrl = new Map<string, number>();
    for (const a of alerts) {
      byCat.set(a.category, (byCat.get(a.category) || 0) + 1);
      byUrl.set(a.url, (byUrl.get(a.url) || 0) + 1);
    }
    console.log("\nBy category:");
    for (const [k, v] of byCat) console.log("  " + k + ": " + v);
    console.log("\nBy URL:");
    for (const [k, v] of byUrl) console.log("  " + k + ": " + v);
  }

  console.log("\nCross-check via ZAP alerts API ...");
  try {
    const ar = await fetch(ZAP_API + "/JSON/core/view/alerts?baseurl=" + encodeURIComponent(TARGET_URL) + "&start=0&count=500");
    const jd: any = await ar.json();
    const pa = (jd.alerts || []).filter((a: any) => a.pluginId === "60101");
    console.log("Playwright alerts in ZAP (pluginId=60101): " + pa.length);
    for (const a of pa) console.log("  " + a.alert + " [" + a.risk + "] @ " + a.url);
  } catch (e) {
    console.log("API cross-check failed: " + e);
  }

  if (alerts.length === 0) {
    console.log("\nFAIL: no alerts created");
    process.exit(1);
  }
  console.log("\nPASS: " + alerts.length + " Playwright alert(s) created");
}

main().catch(e => { console.error("Error:", e); process.exit(1); });
