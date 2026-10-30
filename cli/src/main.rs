//! `sealdrop-agent`: the crypto half of a SealDrop agent, as a small command
//! line tool built from `sealdrop-core`. The MCP server (Python) calls it as a
//! subprocess instead of using Python bindings.
//!
//! Protocol: one JSON object on stdin, one JSON object on stdout.
//! Secrets are passed only through stdin/stdout pipes, never as command line
//! arguments or environment variables (both are visible to other processes).
//! Errors go to stdout as {"error": "..."} with exit code 1, and never
//! contain secret material.
//!
//!   sealdrop-agent keygen          -> {secret, kem_pk, sig_vk}
//!   sealdrop-agent open-delegated  {secret, sealed, wrapped_key, sender_sig_vk, file_id, agent_id} -> {plaintext}
//!   sealdrop-agent seal            {secret, plaintext, recipient_kem_pk} -> {sealed}
//!   sealdrop-agent wrap-for-agent  {secret, sealed, sender_sig_vk, agent_kem_pk, file_id, agent_id} -> {wrapped_key}
//!       (the *user's* side of delegation; the browser does this via WASM, the CLI
//!        version exists for scripted tests)
//! All byte fields are standard base64.

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sealdrop_core::{Error, delegate, file, identity::SecretIdentity, xwing};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const COMMANDS: &[&str] = &["keygen", "open-delegated", "seal", "wrap-for-agent"];

fn keygen() -> Result<Value, Error> {
    let id = SecretIdentity::generate()?;
    let public = id.public();
    Ok(json!({
        // The agent's private identity: X-Wing seed || ML-DSA seed. The caller
        // must store it privately; it never goes to the server.
        "secret": B64.encode(id.to_bytes().as_slice()),
        "kem_pk": B64.encode(public.kem_pk),
        "sig_vk": B64.encode(public.sig_vk),
    }))
}

/// A base64 field from the input. Missing or malformed input is a format error.
fn bytes(input: &Value, field: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let s = input.get(field).and_then(Value::as_str).ok_or(Error::InvalidFormat)?;
    B64.decode(s).map(Zeroizing::new).map_err(|_| Error::InvalidFormat)
}

fn text<'a>(input: &'a Value, field: &str) -> Result<&'a str, Error> {
    input.get(field).and_then(Value::as_str).ok_or(Error::InvalidFormat)
}

fn kem_pk(input: &Value, field: &str) -> Result<[u8; xwing::PUBLIC_KEY_LEN], Error> {
    bytes(input, field)?.as_slice().try_into().map_err(|_| Error::InvalidKey)
}

/// Agent: unwrap the delegated file key, verify the sender's signature, decrypt.
fn open_delegated(input: &Value) -> Result<Value, Error> {
    let me = SecretIdentity::from_bytes(&bytes(input, "secret")?)?;
    let sealed = bytes(input, "sealed")?;
    let ctx = delegate::context(&sealed, text(input, "file_id")?, text(input, "agent_id")?)?;
    let key = delegate::unwrap_file_key(&bytes(input, "wrapped_key")?, &me.kem, &ctx)?;
    let pt = Zeroizing::new(file::open_with_file_key(&sealed, &key, &bytes(input, "sender_sig_vk")?)?);
    Ok(json!({ "plaintext": B64.encode(pt.as_slice()) }))
}

/// Agent: encrypt for a recipient and sign with the agent's own ML-DSA key.
fn seal(input: &Value) -> Result<Value, Error> {
    let me = SecretIdentity::from_bytes(&bytes(input, "secret")?)?;
    let sealed = file::seal(&bytes(input, "plaintext")?, &kem_pk(input, "recipient_kem_pk")?, &me)?;
    Ok(json!({ "sealed": B64.encode(sealed) }))
}

/// User: delegate one received file to an agent.
fn wrap_for_agent(input: &Value) -> Result<Value, Error> {
    let me = SecretIdentity::from_bytes(&bytes(input, "secret")?)?;
    let sealed = bytes(input, "sealed")?;
    let key = file::file_key(&sealed, &me, &bytes(input, "sender_sig_vk")?)?;
    let ctx = delegate::context(&sealed, text(input, "file_id")?, text(input, "agent_id")?)?;
    let wrapped = delegate::wrap_file_key(&key, &kem_pk(input, "agent_kem_pk")?, &ctx)?;
    Ok(json!({ "wrapped_key": B64.encode(wrapped) }))
}

fn run(cmd: &str, input: &Value) -> Result<Value, Error> {
    match cmd {
        "keygen" => keygen(),
        "open-delegated" => open_delegated(input),
        "seal" => seal(input),
        "wrap-for-agent" => wrap_for_agent(input),
        _ => Err(Error::InvalidFormat),
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if !COMMANDS.contains(&cmd.as_str()) {
        println!("{}", json!({ "error": "unknown command", "commands": COMMANDS }));
        std::process::exit(2);
    }
    let mut raw = Zeroizing::new(String::new());
    let input = if cmd == "keygen" {
        Value::Null
    } else {
        // Input may contain secrets: keep the raw text in a wiped buffer.
        if std::io::stdin().read_to_string(&mut raw).is_err() {
            Value::Null
        } else {
            serde_json::from_str(&raw).unwrap_or(Value::Null)
        }
    };
    let (out, code) = match run(&cmd, &input) {
        Ok(v) => (v, 0),
        Err(e) => (json!({ "error": e.to_string() }), 1),
    };
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{out}");
    std::process::exit(code);
}
