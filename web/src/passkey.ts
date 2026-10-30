// passkey.ts: WebAuthn ceremonies plus the PRF extension.
//
// The PRF extension asks the authenticator to compute HMAC(secret inside
// the passkey, salt). We use the result as key material for unwrapping our
// private keys. The PRF output must NEVER be sent to the server, so it is
// removed from the response before upload (see stripPrf).

const enc = new TextEncoder();

// Must match the server's prfSalt (it's public; uniqueness comes from the passkey).
async function prfSalt(): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", enc.encode("SealDrop PRF salt v1"));
}

type Json = Record<string, any>;

async function post(path: string, body: unknown): Promise<Json> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error ?? `HTTP ${r.status}`);
  return data;
}

// Remove PRF results from what we send to the server: they are a secret.
function stripPrf(cred: PublicKeyCredential): Json {
  const json = (cred as any).toJSON() as Json;
  if (json.clientExtensionResults?.prf) {
    json.clientExtensionResults.prf = { enabled: json.clientExtensionResults.prf.enabled };
  }
  return json;
}

function prfOutput(cred: PublicKeyCredential): Uint8Array | null {
  const first = (cred.getClientExtensionResults() as any).prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

function supportsJsonApi(): boolean {
  return typeof (PublicKeyCredential as any)?.parseCreationOptionsFromJSON === "function";
}

export interface PasskeyResult {
  username: string;
  prf: Uint8Array | null; // null: authenticator/browser has no PRF support
}

export async function register(username: string): Promise<PasskeyResult> {
  if (!window.PublicKeyCredential || !supportsJsonApi()) {
    throw new Error("This browser does not support passkeys (WebAuthn JSON API). Try a current Chrome, Edge, Safari or Firefox.");
  }
  const options = await post("/api/register/begin", { username });
  const publicKey = (PublicKeyCredential as any).parseCreationOptionsFromJSON(options.publicKey);
  // Ask for PRF support and, where the authenticator allows it, an output right away.
  publicKey.extensions = { ...publicKey.extensions, prf: { eval: { first: await prfSalt() } } };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  await post("/api/register/finish", stripPrf(cred));

  let prf = prfOutput(cred);
  const enabled = (cred.getClientExtensionResults() as any).prf?.enabled;
  if (!prf && enabled) {
    // Many authenticators only evaluate PRF during sign in, so sign in once.
    prf = (await login(username)).prf;
  }
  return { username, prf };
}

export async function login(username: string): Promise<PasskeyResult> {
  if (!window.PublicKeyCredential || !supportsJsonApi()) {
    throw new Error("This browser does not support passkeys (WebAuthn JSON API).");
  }
  const options = await post("/api/login/begin", { username });
  const publicKey = (PublicKeyCredential as any).parseRequestOptionsFromJSON({
    ...options.publicKey,
    extensions: undefined, // we set PRF ourselves below, as raw bytes
  });
  publicKey.extensions = { prf: { eval: { first: await prfSalt() } } };
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  const res = await post("/api/login/finish", stripPrf(cred));
  return { username: res.username, prf: prfOutput(cred) };
}
