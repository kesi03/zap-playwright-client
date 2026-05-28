import { mkdirSync, readFileSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { globSync } from "glob";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const UNPACK_DIR = "./zap-dev-install";
const TARGET_URL = "https://example.com";
const ZAP_API = "http://127.0.0.1:8080";
const OUT_DIR = join(ROOT, "test-photos");

function cleanDir(dir: string) {
  if (existsSync(dir)) {
    for (const f of globSync("*.png", { cwd: dir, absolute: true })) {
      try { unlinkSync(f); } catch {}
    }
  }
}

async function waitForZap(ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(ZAP_API + "/JSON/core/view/version/");
      if (r.ok) return true;
    } catch {}
    await new Promise(r => setTimeout(r, 2000));
  }
  return false;
}

function cleanHomeLock() {
  const lockFile = join(ROOT, UNPACK_DIR, "workspace", ".zap", ".homelock");
  if (existsSync(lockFile)) {
    try { unlinkSync(lockFile); } catch {}
  }
}

async function takeScreenshot(): Promise<string> {
  const url = ZAP_API + "/JSON/playwrightclient/action/screenshotPage/?url=" + encodeURIComponent(TARGET_URL);
  const r = await fetch(url);
  const data: any = await r.json();
  if (!data.result) throw new Error("screenshotPage failed: " + JSON.stringify(data));
  const path: string = data.result;
  const filename = path.split(/[/\\]/).pop()!;
  console.log("  screenshot saved -> " + filename);
  return filename;
}

async function downloadScreenshot(filename: string | null, outPath: string): Promise<number> {
  let url: string;
  if (filename) {
    url = ZAP_API + "/OTHER/playwrightclient/other/screenshot/?file=" + encodeURIComponent(filename);
  } else {
    url = ZAP_API + "/OTHER/playwrightclient/other/screenshot";
  }
  const r = await fetch(url);
  if (!r.ok) throw new Error("download failed (" + r.status + "): " + r.statusText);
  const buf = Buffer.from(await r.arrayBuffer());
  writeFileSync(outPath, buf);
  const contentType = r.headers.get("content-type") || "(none)";
  console.log("  " + r.status + " " + r.statusText + "  content-type: " + contentType + "  size: " + buf.length + " bytes");
  return buf.length;
}

function validatePng(filePath: string): boolean {
  const buf = readFileSync(filePath);
  if (buf.length < 8) return false;
  return buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47
      && buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A;
}

async function main() {
  console.log("=== Photo: Playwright Screenshot Test ===\n");

  cleanHomeLock();

  if (!(await waitForZap(5000))) {
    console.log("ZAP not running \u2013 starting via npm run dev ...");
    const r = spawnSync("npm", ["run", "dev"], { cwd: ROOT, stdio: "inherit", shell: true, timeout: 120_000 });
    if (r.status !== 0) { console.error("ZAP start failed"); process.exit(1); }
    if (!(await waitForZap(60_000))) { console.error("ZAP not ready"); process.exit(1); }
  }

  console.log("ZAP is ready\n");

  if (!existsSync(OUT_DIR)) {
    mkdirSync(OUT_DIR, { recursive: true });
  }
  cleanDir(OUT_DIR);

  console.log("1. Taking screenshot of " + TARGET_URL + " ...");
  const filename = await takeScreenshot();
  console.log();

  console.log("2. Downloading screenshot by filename ...");
  const namedPath = join(OUT_DIR, "named_" + filename);
  const namedSize = await downloadScreenshot(filename, namedPath);
  const namedOk = validatePng(namedPath);
  console.log("  valid PNG: " + (namedOk ? "yes" : "NO"));
  console.log();

  console.log("3. Downloading latest screenshot (no params) ...");
  const latestPath = join(OUT_DIR, "latest_" + filename);
  const latestSize = await downloadScreenshot(null, latestPath);
  const latestOk = validatePng(latestPath);
  console.log("  valid PNG: " + (latestOk ? "yes" : "NO"));
  console.log();

  console.log("=== Results ===");
  let pass = true;
  if (!namedOk) { console.log("  FAIL: named download is not a valid PNG"); pass = false; }
  else console.log("  PASS: named download (" + namedSize + " bytes)");

  if (!latestOk) { console.log("  FAIL: latest download is not a valid PNG"); pass = false; }
  else console.log("  PASS: latest download (" + latestSize + " bytes)");

  if (namedSize !== latestSize) {
    console.log("  WARN: file sizes differ (" + namedSize + " vs " + latestSize + ")");
  }

  console.log("\nOutput directory: " + OUT_DIR);
  if (pass) {
    console.log("\nAll checks passed.");
  } else {
    console.log("\nSome checks failed.");
    process.exit(1);
  }
}

main().catch(e => { console.error("Error:", e); process.exit(1); });
