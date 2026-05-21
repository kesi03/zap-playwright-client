import { execa } from "execa";
import { copyFileSync, readFileSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { globSync } from "glob";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ZAP_DOWNLOADER = "zap-downloader";
const OFFLINE_TAR = "zap-offline.tar";
const UNPACK_DIR = "./zap-dev-install";

async function step(label: string, fn: () => Promise<void>) {
  console.log(`\n=== ${label} ===`);
  try {
    await fn();
    console.log(`✓ ${label}`);
  } catch (e) {
    console.error(`✗ ${label} failed:`, e);
    process.exit(1);
  }
}

async function buildAddon() {
  const gradleCmd = join(ROOT, process.platform === "win32" ? "gradlew.bat" : "gradlew");
  await execa(gradleCmd, ["build"], { stdio: "inherit", cwd: ROOT });
}

async function offlinePack() {
  await execa(ZAP_DOWNLOADER, ["offline", "pack", "-o", OFFLINE_TAR], {
    stdio: "inherit",
    cwd: ROOT,
  });
}

async function offlineUnpack() {
  await execa(ZAP_DOWNLOADER, ["offline", "unpack", "-i", OFFLINE_TAR, "-o", UNPACK_DIR], {
    stdio: "inherit",
    cwd: ROOT,
  });
}

function findPluginDir(): string | null {
  const dirs = globSync("**/plugin", { cwd: join(ROOT, UNPACK_DIR), absolute: true });
  return dirs[0] || null;
}

function findTomlFile(): string | null {
  const files = globSync("**/default.toml", { cwd: join(ROOT, UNPACK_DIR), absolute: true });
  return files[0] || null;
}

function findZapFile(): string | null {
  const files = globSync("build/zapAddOn/bin/*.zap", { cwd: ROOT, absolute: true });
  return files[0] || null;
}

async function installAddon() {
  const zapFile = findZapFile();
  if (!zapFile) throw new Error("No .zap file found in build/zapAddOn/bin/");
  console.log(`Add-on: ${zapFile}`);

  const pluginDir = findPluginDir();
  if (!pluginDir) throw new Error("No plugin directory found in unpacked ZAP");

  const zapBaseName = zapFile.split(/[/\\]/).pop()!;
  const target = join(pluginDir, zapBaseName);
  copyFileSync(zapFile, target);
  console.log(`Installed into ${target}`);
}

async function patchToml() {
  const tomlFile = findTomlFile();
  if (!tomlFile) {
    console.log("No default.toml found, skipping patch");
    return;
  }

  const content = readFileSync(tomlFile, "utf-8");
  if (content.includes("UseZGC") && !content.includes("UnlockExperimentalVMOptions")) {
    const patched = content.replace(
      /-XX:\+UseZGC/,
      '-XX:+UnlockExperimentalVMOptions",\n  "-XX:+UseZGC'
    );
    writeFileSync(tomlFile, patched);
    console.log("TOML patched for ZGC compatibility");
  } else {
    console.log("No TOML patching needed");
  }
}

function cleanHomeLock() {
  const lockFile = join(ROOT, UNPACK_DIR, "workspace", ".zap", ".homelock");
  if (existsSync(lockFile)) {
    try { unlinkSync(lockFile); console.log("Cleaned stale .homelock"); } catch {}
  }
}

async function startDaemon() {
  cleanHomeLock();
  const tomlFile = findTomlFile();
  if (tomlFile) {
    await execa(ZAP_DOWNLOADER, ["daemon", "start", "-t", tomlFile], {
      stdio: "inherit",
      cwd: ROOT,
    });
  } else {
    await execa(ZAP_DOWNLOADER, ["daemon", "start", "-d", join(ROOT, UNPACK_DIR)], {
      stdio: "inherit",
      cwd: ROOT,
    });
  }
}

async function main() {
  console.log("ZAP Automation Template Manager — Dev Startup");
  console.log(`Root: ${ROOT}`);

  const devInstallExists = existsSync(join(ROOT, UNPACK_DIR));
  if (devInstallExists) {
    console.log(`\n${UNPACK_DIR} already exists — skipping offline pack/unpack`);
  }

  await step("Build Gradle add-on", buildAddon);
  if (!devInstallExists) {
    await step("Create offline ZAP package", offlinePack);
    await step("Unpack ZAP", offlineUnpack);
  }
  await step("Install add-on", installAddon);
  await step("Patch TOML", patchToml);
  await step("Start ZAP daemon", startDaemon);

  console.log(`\n✓ ZAP daemon is running. Open http://127.0.0.1:8080 in your browser.`);
}

main();
