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
//!   sealdrop-agent keygen        -> {secret, kem_pk, sig_vk}

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sealdrop_core::{Error, identity::SecretIdentity};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const COMMANDS: &[&str] = &["keygen"];

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

fn run(cmd: &str, _input: &Value) -> Result<Value, Error> {
    match cmd {
        "keygen" => keygen(),
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
