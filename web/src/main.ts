// main.ts: UI glue. All cryptography happens in Rust (./pkg, WebAssembly).
// The decrypted secret identity lives only in this tab's memory.

import init, * as sd from "./pkg/sealdrop_wasm.js";
import * as passkey from "./passkey";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const logEl = $("log");

function log(msg: string) {
  logEl.textContent = `${new Date().toLocaleTimeString()}  ${msg}\n` + (logEl.textContent ?? "");
}

const b64 = {
  enc(b: Uint8Array): string {
    let s = "";
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    return btoa(s);
  },
  dec(s: string): Uint8Array {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  },
};

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
// Short, human comparable fingerprint: first 16 bytes in groups of 4 hex chars.
const shortFp = (fp: Uint8Array) => hex(fp.subarray(0, 16)).match(/.{4}/g)!.join(" ");

async function api(path: string, init?: RequestInit): Promise<any> {
  const r = await fetch(path, init);
  if (!r.ok) {
    const data = await r.json().catch(() => ({}));
    throw new Error(data.error ?? `HTTP ${r.status}`);
  }
  return r.status === 204 ? null : r.json();
}

// ---- Session state ----
let username = "";
let secret: Uint8Array | null = null;

function forget() {
  secret?.fill(0); // best effort wipe of our copy
  secret = null;
  username = "";
}

function showSignedIn(protection: string) {
  $("signed-out").hidden = true;
  $("signed-in").hidden = false;
  $("send").hidden = false;
  $("inbox").hidden = false;
  $("agents").hidden = false;
  $("grants").hidden = false;
  $("passphrase-box").hidden = true;
  $("me").textContent = username;
  $("key-protection").textContent = protection;
  $("my-fp").textContent = shortFp(sd.fingerprint(sd.publicSigKey(secret!)));
  refresh().then(refreshAgents);
}

// Ask the user for a passphrase (fallback when PRF is unavailable).
function askPassphrase(): Promise<string> {
  $("passphrase-box").hidden = false;
  return new Promise((resolve) => {
    $("passphrase-go").onclick = () => {
      const p = $<HTMLInputElement>("passphrase").value;
      if (p.length < 12) {
        log("Passphrase must be at least 12 characters.");
        return;
      }
      $<HTMLInputElement>("passphrase").value = "";
      $("passphrase-box").hidden = true;
      resolve(p);
    };
  });
}

// First sign in of a new account: create keys, wrap them, publish public keys.
async function createKeys(prf: Uint8Array | null) {
  const id = sd.generateIdentity();
  let wrapped: Uint8Array;
  let protection: string;
  if (prf) {
    wrapped = sd.wrapWithPrf(prf, id, username);
    protection = "passkey (PRF)";
  } else {
    log("PRF not supported here: falling back to a passphrase (weaker).");
    wrapped = sd.wrapWithPassphrase(await askPassphrase(), id, username);
    protection = "passphrase (weaker fallback)";
  }
  prf?.fill(0);
  await api("/api/me/keys", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      kem_pk: b64.enc(sd.publicKemKey(id)),
      sig_vk: b64.enc(sd.publicSigKey(id)),
      wrapped_keys: b64.enc(wrapped),
    }),
  });
  secret = id;
  log(`Created post quantum keys (X-Wing + ML-DSA-65). Private keys uploaded only in wrapped form.`);
  showSignedIn(protection);
}

async function unlock(prf: Uint8Array | null) {
  const me = await api("/api/me");
  if (!me.has_keys) return createKeys(prf);
  const blob = b64.dec(me.wrapped_keys);
  if (sd.wrappedKdf(blob) === 1) {
    if (!prf) throw new Error("This account's keys are protected by passkey PRF, but no PRF output was returned.");
    secret = sd.unwrapWithPrf(prf, blob, username);
    prf.fill(0);
    showSignedIn("passkey (PRF)");
  } else {
    log("Keys are protected by a passphrase (weaker fallback). Enter it to unlock.");
    secret = sd.unwrapWithPassphrase(await askPassphrase(), blob, username);
    showSignedIn("passphrase (weaker fallback)");
  }
  log("Private keys unwrapped in this tab.");
}

async function busy(btn: HTMLButtonElement, fn: () => Promise<void>) {
  btn.disabled = true;
  try {
    await fn();
  } catch (e) {
    log(`Error: ${(e as Error).message ?? e}`);
  } finally {
    btn.disabled = false;
  }
}

// ---- Account ----
$("register").onclick = () =>
  busy($("register") as HTMLButtonElement, async () => {
    const res = await passkey.register($<HTMLInputElement>("username").value.trim());
    username = res.username;
    log(`Passkey registered for ${username}. PRF ${res.prf ? "available" : "NOT available"}.`);
    await createKeys(res.prf);
  });

$("login").onclick = () =>
  busy($("login") as HTMLButtonElement, async () => {
    const res = await passkey.login($<HTMLInputElement>("username").value.trim());
    username = res.username;
    log(`Signed in as ${username}. PRF ${res.prf ? "available" : "NOT available"}.`);
    await unlock(res.prf);
  });

$("logout").onclick = async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  forget();
  location.reload();
};

// ---- Send ----
$("send-go").onclick = () =>
  busy($("send-go") as HTMLButtonElement, async () => {
    const to = $<HTMLInputElement>("recipient").value.trim();
    const f = $<HTMLInputElement>("send-file").files?.[0];
    if (!f || !secret) throw new Error("Pick a file first.");
    const keys = await api(`/api/users/${encodeURIComponent(to)}/keys`);
    const rpk = b64.dec(keys.kem_pk);
    log(`Recipient ${to} key fingerprint: ${shortFp(sd.fingerprint(b64.dec(keys.sig_vk)))} (compare it with them out of band)`);
    const pt = new Uint8Array(await f.arrayBuffer());
    const t0 = performance.now();
    const sealed = sd.seal(pt, rpk, secret);
    const ms = performance.now() - t0;
    await api("/api/files", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ recipient: to, blob: b64.enc(sealed) }),
    });
    log(`Sent "${f.name}" (${pt.length} bytes) to ${to}: encrypted + signed in ${ms.toFixed(1)} ms, ` +
      `${sealed.length - pt.length} bytes overhead.`);
    refresh();
  });

// ---- Inbox ----
async function refresh() {
  const files: Array<{ id: string; sender: string; recipient: string; size: number }> = await api("/api/files");
  const ul = $("file-list");
  ul.replaceChildren();
  for (const f of files) {
    const li = document.createElement("li");
    if (f.recipient === username) {
      li.textContent = `from ${f.sender} · ${f.size} bytes`;
      receivedFiles.set(f.id, f.sender);
      const btn = document.createElement("button");
      btn.textContent = "Decrypt";
      btn.dataset.fileId = f.id;
      btn.onclick = () => busy(btn, () => receive(f.id, f.sender));
      li.append(btn);
    } else {
      li.textContent = `sent to ${f.recipient} · ${f.size} bytes (only ${f.recipient} can decrypt)`;
    }
    ul.append(li);
  }
}

async function receive(id: string, sender: string) {
  if (!secret) return;
  const sealed = new Uint8Array(await (await fetch(`/api/files/${id}`)).arrayBuffer());
  const svk = await senderSigKey(sender);
  const t0 = performance.now();
  const pt = sd.open(sealed, secret, svk); // verifies the ML-DSA signature first
  const ms = performance.now() - t0;
  log(`Verified signature from ${sender} (${shortFp(sd.fingerprint(svk))}) and decrypted ${pt.length} bytes in ${ms.toFixed(1)} ms.`);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([pt as BlobPart]));
  a.download = `sealdrop-${id.slice(0, 8)}.bin`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

$("refresh").onclick = () => busy($("refresh") as HTMLButtonElement, refresh);

// Files can come from users or from agents ("agent:<id>", acting for someone).
async function senderSigKey(sender: string): Promise<Uint8Array> {
  const path = sender.startsWith("agent:")
    ? `/api/agents/${encodeURIComponent(sender.slice(6))}/keys`
    : `/api/users/${encodeURIComponent(sender)}/keys`;
  return b64.dec((await api(path)).sig_vk);
}

// ---- Agents and grants (Milestone 7) ----
const receivedFiles = new Map<string, string>(); // file id -> sender

async function refreshAgents() {
  const agents: Array<{ id: string; name: string; jkt: string }> = await api("/api/agents");
  const list = $("agent-list");
  const select = $<HTMLSelectElement>("grant-agent");
  list.replaceChildren();
  select.replaceChildren();
  for (const a of agents) {
    const li = document.createElement("li");
    li.textContent = `${a.name} · ${a.id}`;
    list.append(li);
    select.append(new Option(`${a.name} (${a.id})`, a.id));
  }
  const box = $("grant-files");
  box.querySelectorAll("label").forEach((l) => l.remove());
  for (const [id, sender] of receivedFiles) {
    const label = document.createElement("label");
    label.className = "inline";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = id;
    label.append(cb, ` ${id.slice(0, 8)} from ${sender}`);
    box.append(label);
  }
  await refreshGrants();
}

type GrantView = { id: string; agent_id: string; actions: string[]; file_ids: string[]; expires_at: number; revoked_at: number | null };

async function refreshGrants() {
  const grants: GrantView[] = await api("/api/grants");
  const ul = $("grant-list");
  ul.replaceChildren();
  for (const g of grants) {
    const li = document.createElement("li");
    const state = g.revoked_at ? "revoked"
      : Date.now() / 1000 >= g.expires_at ? "expired"
      : `until ${new Date(g.expires_at * 1000).toLocaleTimeString()}`;
    li.textContent = `${g.agent_id}: ${g.actions.join(", ")} on ${g.file_ids.length} file(s) · ${state}`;
    li.dataset.grantId = g.id;
    if (!g.revoked_at && Date.now() / 1000 < g.expires_at) {
      const btn = document.createElement("button");
      btn.textContent = "Revoke";
      btn.onclick = () => busy(btn, async () => {
        await api(`/api/grants/${encodeURIComponent(g.id)}`, { method: "DELETE" });
        log(`Revoked grant for ${g.agent_id}: no new tokens, wrapped file keys deleted.`);
        await refreshGrants();
      });
      li.append(btn);
    }
    ul.append(li);
  }
}

$("agent-register").onclick = () =>
  busy($("agent-register") as HTMLButtonElement, async () => {
    const bundle = JSON.parse($<HTMLTextAreaElement>("agent-bundle").value);
    const ag = await api("/api/agents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: bundle.name, kem_pk: bundle.kem_pk, sig_vk: bundle.sig_vk, auth_key: bundle.auth_key }),
    });
    log(`Registered agent "${ag.name}" as ${ag.id}. Only its public keys were sent.`);
    $<HTMLTextAreaElement>("agent-bundle").value = "";
    await refreshAgents();
  });

$("grant-go").onclick = () =>
  busy($("grant-go") as HTMLButtonElement, async () => {
    if (!secret) return;
    const agentId = $<HTMLSelectElement>("grant-agent").value;
    const actions = [...document.querySelectorAll<HTMLInputElement>("#grant-actions input:checked")].map((c) => c.value);
    const fileIds = [...document.querySelectorAll<HTMLInputElement>("#grant-files input:checked")].map((c) => c.value);
    const shareWith = $<HTMLInputElement>("grant-share").value.split(",").map((s) => s.trim()).filter(Boolean);
    const agentKeys = await api(`/api/agents/${encodeURIComponent(agentId)}/keys`);
    const agentPk = b64.dec(agentKeys.kem_pk);
    const needKeys = actions.includes("download") || actions.includes("share");
    const files = [];
    for (const id of fileIds) {
      let wrapped: string | undefined;
      if (needKeys) {
        // Verify the file, recover its key, and seal it to the agent, all in Rust/WASM.
        const sealed = new Uint8Array(await (await fetch(`/api/files/${id}`)).arrayBuffer());
        const svk = await senderSigKey(receivedFiles.get(id)!);
        wrapped = b64.enc(sd.wrapFileKeyForAgent(sealed, secret, svk, agentPk, id, agentId));
      }
      files.push({ file_id: id, wrapped_key: wrapped });
    }
    const res = await api("/api/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: agentId, actions, files, share_with: shareWith,
        ttl_minutes: Number($<HTMLInputElement>("grant-ttl").value) }),
    });
    $("grant-token-box").hidden = false;
    $<HTMLTextAreaElement>("grant-token").value = res.grant_token;
    log(`Granted ${agentKeys.name}: ${actions.join(", ")} on ${files.length} file(s)` +
      (needKeys ? ", file keys wrapped to the agent in this browser." : "."));
    await refreshGrants();
  });

// ---- Local demo (Milestone 4) ----
$("demo-go").onclick = () =>
  busy($("demo-go") as HTMLButtonElement, async () => {
    const f = $<HTMLInputElement>("demo-file").files?.[0];
    const pt = f ? new Uint8Array(await f.arrayBuffer()) : new TextEncoder().encode("hello, post quantum world");
    const alice = sd.generateIdentity();
    const bob = sd.generateIdentity();
    const t0 = performance.now();
    const sealed = sd.seal(pt, sd.publicKemKey(bob), alice);
    const t1 = performance.now();
    const back = sd.open(sealed, bob, sd.publicSigKey(alice));
    const t2 = performance.now();
    const same = back.length === pt.length && back.every((x, i) => x === pt[i]);
    let tamper = "accepted (BUG)";
    sealed[sealed.length - 100] ^= 1;
    try { sd.open(sealed, bob, sd.publicSigKey(alice)); } catch { tamper = "rejected"; }
    log(`Local demo: ${pt.length} bytes · seal ${(t1 - t0).toFixed(1)} ms · open ${(t2 - t1).toFixed(1)} ms · ` +
      `round trip ${same ? "OK" : "MISMATCH"} · tampered copy ${tamper}`);
    alice.fill(0);
    bob.fill(0);
  });

$("demo-bench").onclick = () =>
  busy($("demo-bench") as HTMLButtonElement, async () => {
    const pt = new Uint8Array(1 << 20);
    crypto.getRandomValues(pt.subarray(0, 65536));
    const alice = sd.generateIdentity();
    const bob = sd.generateIdentity();
    const bobPk = sd.publicKemKey(bob);
    const aliceVk = sd.publicSigKey(alice);
    const seal: number[] = [];
    const open: number[] = [];
    for (let i = 0; i < 10; i++) {
      const t0 = performance.now();
      const s = sd.seal(pt, bobPk, alice);
      const t1 = performance.now();
      sd.open(s, bob, aliceVk);
      seal.push(t1 - t0);
      open.push(performance.now() - t1);
    }
    const median = (a: number[]) => [...a].sort((x, y) => x - y)[a.length >> 1];
    const result = { seal_ms: median(seal), open_ms: median(open), seal_mib_s: 1000 / median(seal), open_mib_s: 1000 / median(open) };
    (window as any).__sealdropBench = result;
    log(`Browser benchmark, 1 MiB, median of 10: seal ${result.seal_ms.toFixed(1)} ms (${result.seal_mib_s.toFixed(1)} MiB/s), ` +
      `open ${result.open_ms.toFixed(1)} ms (${result.open_mib_s.toFixed(1)} MiB/s)`);
  });

await init();
log("Rust crypto core loaded (WebAssembly).");
