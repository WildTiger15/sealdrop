// Smoke test against a deployed SealDrop (default: the Render demo).
//   node e2e/live-smoke.mjs [https://sealdrop.onrender.com]
// Two fresh users with virtual passkeys (PRF): register, send a file, decrypt it.

import { readFileSync } from "node:fs";
import { chromium } from "playwright";

const ORIGIN = process.argv[2] ?? "https://sealdrop.onrender.com";
const tag = Math.random().toString(36).slice(2, 8);
const PLAINTEXT = `live smoke test ${tag}\n`.repeat(100);
const browser = await chromium.launch({ channel: "msedge", headless: true });

async function user(name) {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(ORIGIN, { timeout: 120_000 });
  await page.locator("#log").filter({ hasText: "Rust crypto core loaded" }).waitFor({ timeout: 60_000 });
  await page.fill("#username", name);
  await page.click("#register");
  await page.locator("#signed-in").waitFor({ state: "visible", timeout: 60_000 });
  console.log(`ok  ${name} registered, keys protected by: ${await page.innerText("#key-protection")}`);
  return page;
}

try {
  const alice = await user(`alice_${tag}`);
  const bob = await user(`bob_${tag}`);
  await alice.fill("#recipient", `bob_${tag}`);
  await alice.setInputFiles("#send-file", { name: "hello.txt", mimeType: "text/plain", buffer: Buffer.from(PLAINTEXT) });
  await alice.click("#send-go");
  await alice.locator("#log").filter({ hasText: "Sent \"hello.txt\"" }).waitFor({ timeout: 60_000 });
  console.log("ok  " + (await alice.locator("#log").innerText()).split("\n")[0]);
  await bob.click("#refresh");
  const btn = bob.locator("#file-list button").first();
  await btn.waitFor({ timeout: 30_000 });
  const [dl] = await Promise.all([bob.waitForEvent("download"), btn.click()]);
  const same = readFileSync(await dl.path(), "utf8") === PLAINTEXT;
  console.log("ok  " + (await bob.locator("#log").innerText()).split("\n")[0]);
  console.log(same ? "LIVE SMOKE TEST PASSED: bob decrypted exactly what alice sent" : "LIVE SMOKE TEST FAILED: content mismatch");
  if (!same) process.exitCode = 1;
} finally {
  await browser.close();
}
