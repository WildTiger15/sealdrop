"""Calls the Rust `sealdrop-agent` CLI (built from sealdrop-core) for all crypto.

Secrets go over the child's stdin and come back on its stdout: never as
command line arguments or environment variables, which other processes on the
machine can read.
"""
import base64
import json
import os
import pathlib
import subprocess

_REPO = pathlib.Path(__file__).resolve().parents[2]
_EXE = "sealdrop-agent.exe" if os.name == "nt" else "sealdrop-agent"


class CryptoError(Exception):
    """A crypto operation failed. The message never contains secret material."""


def cli_path() -> str:
    return os.environ.get("SEALDROP_AGENT_CLI") or str(_REPO / "target" / "release" / _EXE)


def _run(command: str, payload: dict | None = None) -> dict:
    proc = subprocess.run(
        [cli_path(), command],
        input=json.dumps(payload or {}).encode(),
        capture_output=True,
        timeout=120,
        check=False,
    )
    try:
        out = json.loads(proc.stdout or b"{}")
    except json.JSONDecodeError:
        raise CryptoError(f"{command}: unreadable output") from None
    if proc.returncode != 0:
        raise CryptoError(f"{command}: {out.get('error', 'failed')}")
    return out


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def keygen() -> dict:
    """New agent identity: {secret, kem_pk, sig_vk} (base64)."""
    return _run("keygen")


def open_delegated(secret: str, sealed: bytes, wrapped_key: bytes, sender_sig_vk: bytes,
                   file_id: str, agent_id: str) -> bytes:
    out = _run("open-delegated", {
        "secret": secret, "sealed": b64e(sealed), "wrapped_key": b64e(wrapped_key),
        "sender_sig_vk": b64e(sender_sig_vk), "file_id": file_id, "agent_id": agent_id,
    })
    return b64d(out["plaintext"])


def seal(secret: str, plaintext: bytes, recipient_kem_pk: bytes) -> bytes:
    out = _run("seal", {"secret": secret, "plaintext": b64e(plaintext), "recipient_kem_pk": b64e(recipient_kem_pk)})
    return b64d(out["sealed"])


def wrap_for_agent(user_secret: str, sealed: bytes, sender_sig_vk: bytes, agent_kem_pk: bytes,
                   file_id: str, agent_id: str) -> bytes:
    """The *user's* side of delegation (tests only; the browser does this in WASM)."""
    out = _run("wrap-for-agent", {
        "secret": user_secret, "sealed": b64e(sealed), "sender_sig_vk": b64e(sender_sig_vk),
        "agent_kem_pk": b64e(agent_kem_pk), "file_id": file_id, "agent_id": agent_id,
    })
    return b64d(out["wrapped_key"])
