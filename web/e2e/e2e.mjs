// End to end test: real Go server, real browser, real (virtual) passkeys.
//
// Chrome/Edge DevTools can emulate a FIDO2 authenticator, including the PRF
// extension, so the full flow runs without a hardware key:
//   alice and bob register with passkeys (PRF) -> alice sends bob a file ->
//   bob signs out, signs back in, decrypts it -> carol (no PRF) uses the
//   passphrase fallback -> the database is dumped and checked for plaintext.
//
//   node e2e/e2e.mjs        (after `npm run build`)

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const serverDir = join(root, "server");
const dbPath = join(serverDir, "data", "e2e.db");
const ORIGIN = "http://localhost:8080";
const SECRET_PHRASE = "the eagle lands at midnight - SealDrop e2e plaintext marker";
const out = [];
const say = (s) => { console.log(s); out.push(s); };

function check(cond, msg) {
  if (!cond) throw new Error("CHECK FAILED: " + msg);
  say("  ok  " + msg);
}

// ---- start the server on a fresh database ----
mkdirSync(dirname(dbPath), { recursive: true });
for (const f of [dbPath, dbPath + "-wal", dbPath + "-shm"]) rmSync(f, { force: true });
const go = process.platform === "win32" ? "go.exe" : "go";
const build = spawnSync(go, ["build", "-o", join(serverDir, "data", "sealdrop-server.exe"), "."], { cwd: serverDir, stdio: "inherit" });
if (build.status !== 0) process.exit(1);
const server = spawn(join(serverDir, "data", "sealdrop-server.exe"),
  ["-addr", "localhost:8080", "-db", dbPath, "-static", join(root, "web", "dist"), "-origin", ORIGIN],
  { cwd: serverDir, stdio: ["ignore", "inherit", "inherit"] });
for (let i = 0; i < 50; i++) {
  try { await fetch(ORIGIN + "/api/users/x/keys"); break; } catch { await new Promise((r) => setTimeout(r, 200)); }
}

const browser = await chromium.launch({ channel: "msedge", headless: true });

async function userPage(name, { prf = true } = {}) {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true, hasPrf: prf,
    },
  });
  page.on("pageerror", (e) => say(`  [${name} page error] ${e.message}`));
  await page.goto(ORIGIN);
  await page.locator("#log").filter({ hasText: "Rust crypto core loaded" }).waitFor();
  return { name, page, ctx, cdp, authenticatorId };
}

const logText = (u) => u.page.locator("#log").innerText();

async function register(u) {
  await u.page.fill("#username", u.name);
  await u.page.click("#register");
}

try {
  say("SealDrop end to end test");
  say("1. Register alice and bob with passkeys (virtual authenticator with PRF)");
  const alice = await userPage("alice");
  const bob = await userPage("bob");
  for (const u of [alice, bob]) {
    await register(u);
    await u.page.locator("#signed-in").waitFor({ state: "visible", timeout: 30_000 });
    check((await u.page.innerText("#key-protection")) === "passkey (PRF)", `${u.name}: keys protected by passkey PRF`);
  }
  const creds = await alice.cdp.send("WebAuthn.getCredentials", { authenticatorId: alice.authenticatorId });
  check(creds.credentials.length === 1, "alice's passkey lives in her authenticator");

  say("2. alice sends bob a file");
  await alice.page.fill("#recipient", "bob");
  await alice.page.setInputFiles("#send-file", { name: "plan.txt", mimeType: "text/plain", buffer: Buffer.from(SECRET_PHRASE.repeat(200)) });
  await alice.page.click("#send-go");
  await alice.page.locator("#log").filter({ hasText: "Sent \"plan.txt\"" }).waitFor();
  say("  " + (await logText(alice)).split("\n")[0]);

  say("3. bob signs out, signs back in with his passkey, decrypts");
  await bob.page.click("#logout");
  await bob.page.locator("#log").filter({ hasText: "Rust crypto core loaded" }).waitFor();
  await bob.page.fill("#username", "bob");
  await bob.page.click("#login");
  await bob.page.locator("#signed-in").waitFor({ state: "visible" });
  check((await logText(bob)).includes("Private keys unwrapped"), "bob's keys unwrapped with PRF after a fresh sign in");
  const btn = bob.page.locator("#file-list button").first();
  await btn.waitFor();
  const [download] = await Promise.all([bob.page.waitForEvent("download"), btn.click()]);
  const got = readFileSync(await download.path(), "utf8");
  check(got === SECRET_PHRASE.repeat(200), "bob's decrypted file matches what alice sent");
  check((await logText(bob)).includes("Verified signature from alice"), "ML-DSA signature verified before decryption");

  say("4. eve cannot fetch the file, and the server rejects non-SealDrop uploads");
  const eve = await userPage("eve");
  await register(eve);
  await eve.page.locator("#signed-in").waitFor({ state: "visible" });
  const files = await alice.page.evaluate(() => fetch("/api/files").then((r) => r.json()));
  const status = await eve.page.evaluate((id) => fetch("/api/files/" + id).then((r) => r.status), files[0].id);
  check(status === 404, "eve gets 404 for a file not addressed to her");
  const up = await eve.page.evaluate(() => fetch("/api/files", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ recipient: "bob", blob: btoa("just plaintext") }) }).then((r) => r.status));
  check(up === 400, "server refuses a blob that is not a sealed file");

  say("5. carol's authenticator has no PRF: passphrase fallback, labeled weaker");
  const carol = await userPage("carol", { prf: false });
  await register(carol);
  await carol.page.locator("#passphrase-box").waitFor({ state: "visible" });
  check((await carol.page.innerText("#passphrase-box")).includes("This is weaker"), "fallback is clearly labeled weaker");
  await carol.page.fill("#passphrase", "correct horse battery staple");
  await carol.page.click("#passphrase-go");
  await carol.page.locator("#signed-in").waitFor({ state: "visible", timeout: 60_000 });
  check((await carol.page.innerText("#key-protection")).startsWith("passphrase"), "carol's keys are protected by the passphrase");

  say("6. Local demo in the browser: round trip and tamper rejection");
  await alice.page.click("#demo-go");
  await alice.page.locator("#log").filter({ hasText: "Local demo:" }).waitFor();
  const demo = (await logText(alice)).split("\n").find((l) => l.includes("Local demo:"));
  check(demo.includes("round trip OK") && demo.includes("tampered copy rejected"), "WASM round trip OK, tampered copy rejected");

  say("7. Browser benchmark (WASM, 1 MiB, median of 10)");
  await alice.page.click("#demo-bench");
  await alice.page.waitForFunction(() => window.__sealdropBench, null, { timeout: 120_000 });
  const bench = await alice.page.evaluate(() => window.__sealdropBench);
  say(`  seal ${bench.seal_ms.toFixed(1)} ms (${bench.seal_mib_s.toFixed(1)} MiB/s), open ${bench.open_ms.toFixed(1)} ms (${bench.open_mib_s.toFixed(1)} MiB/s)`);
  writeFileSync(join(root, "outputs", "browser-bench.json"), JSON.stringify({ browser: browser.version(), ...bench }, null, 2));
} finally {
  await browser.close();
  server.kill();
}

say("8. Zero knowledge check: dump the server database");
await new Promise((r) => setTimeout(r, 500));
const dump = spawnSync(go, ["run", "./cmd/dbdump", "-db", dbPath, "-needle", SECRET_PHRASE, "-needle", "eagle lands", "-needle", "correct horse"],
  { cwd: serverDir, encoding: "utf8" });
say(dump.stdout.trim());
if (dump.status !== 0) { say(dump.stderr); process.exitCode = 1; }
writeFileSync(join(root, "outputs", "e2e.txt"), out.join("\n") + "\n");
say(process.exitCode ? "E2E FAILED" : "E2E PASSED");
