// Captures README screenshots of a real run (fresh server, virtual passkeys).
//   node e2e/screenshots.mjs        (after `npm run build`)
// Writes docs/images/*.png.

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const serverDir = join(root, "server");
const img = join(root, "docs", "images");
const dbPath = join(serverDir, "data", "screenshots.db");
const ORIGIN = "http://localhost:8080";
mkdirSync(img, { recursive: true });
mkdirSync(dirname(dbPath), { recursive: true });
for (const f of [dbPath, dbPath + "-wal", dbPath + "-shm"]) rmSync(f, { force: true });

const exe = join(serverDir, "data", "sealdrop-server.exe");
if (spawnSync("go", ["build", "-o", exe, "."], { cwd: serverDir, stdio: "inherit" }).status !== 0) process.exit(1);
const server = spawn(exe, ["-db", dbPath, "-static", join(root, "web", "dist"), "-origin", ORIGIN], { stdio: "ignore" });
for (let i = 0; i < 50; i++) {
  try { await fetch(ORIGIN + "/api/users/x/keys"); break; } catch { await new Promise((r) => setTimeout(r, 200)); }
}

const browser = await chromium.launch({ channel: "msedge", headless: true });

async function user(name, prf = true) {
  const ctx = await browser.newContext({ viewport: { width: 900, height: 1000 }, deviceScaleFactor: 1.5, acceptDownloads: true, colorScheme: "light" });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: prf } });
  await page.goto(ORIGIN);
  await page.locator("#log").filter({ hasText: "Rust crypto core loaded" }).waitFor();
  return page;
}

const shot = (page, name) => page.screenshot({ path: join(img, name), fullPage: true });

try {
  const alice = await user("alice");
  await alice.fill("#username", "alice");
  await shot(alice, "01-sign-in.png");
  await alice.click("#register");
  await alice.locator("#signed-in").waitFor({ state: "visible" });

  const bob = await user("bob");
  await bob.fill("#username", "bob");
  await bob.click("#register");
  await bob.locator("#signed-in").waitFor({ state: "visible" });

  await alice.fill("#recipient", "bob");
  await alice.setInputFiles("#send-file", { name: "quarterly-plan.txt", mimeType: "text/plain", buffer: Buffer.from("Q4 plan: ship SealDrop.\n".repeat(400)) });
  await alice.click("#send-go");
  await alice.locator("#log").filter({ hasText: "Sent \"quarterly-plan.txt\"" }).waitFor();
  await shot(alice, "02-alice-sent.png");

  await bob.click("#refresh");
  const btn = bob.locator("#file-list button").first();
  await btn.waitFor();
  await Promise.all([bob.waitForEvent("download"), btn.click()]);
  await bob.locator("#log").filter({ hasText: "Verified signature from alice" }).waitFor();
  await shot(bob, "03-bob-decrypted.png");

  await alice.click("#demo-go");
  await alice.locator("#log").filter({ hasText: "Local demo:" }).waitFor();
  await alice.click("#demo-bench");
  await alice.waitForFunction(() => window.__sealdropBench, null, { timeout: 120_000 });
  await alice.locator("#local-demo").screenshot({ path: join(img, "04-local-demo-section.png") });
  await alice.locator("#log").screenshot({ path: join(img, "05-local-demo-log.png") });

  const carol = await user("carol", false);
  await carol.fill("#username", "carol");
  await carol.click("#register");
  await carol.locator("#passphrase-box").waitFor({ state: "visible" });
  await shot(carol, "06-passphrase-fallback.png");
  console.log("screenshots written to docs/images/");
} finally {
  await browser.close();
  server.kill();
}
