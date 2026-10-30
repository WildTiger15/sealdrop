"""Drives the SealDrop MCP server as an MCP client would (stdio), as agent A.

Checks every tool, that refusals come from the server's policy, and that no
tool result ever contains a credential the MCP server process holds.
Run by web/e2e/agents.mjs, which sets up users, files, agents and grants.
"""
import asyncio
import json
import os
import pathlib
import re
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text())
A = fixture["agent_a"]
state = json.loads((pathlib.Path(A["home"]) / "agent.json").read_text())
SECRETS = {k: state[k] for k in ("secret", "auth_key", "grant_token")}
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.")
results: list[str] = []
failures = 0


def check(cond: bool, msg: str) -> None:
    global failures
    print(("  ok  " if cond else "  FAIL ") + msg)
    if not cond and results:
        print("       last tool result: " + results[-1][:300].replace("\n", " | "))
    failures += 0 if cond else 1


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "sealdrop_agent", "serve"], cwd=str(pathlib.Path(__file__).parents[1]),
        env={**os.environ, "SEALDROP_AGENT_HOME": A["home"], "SEALDROP_URL": fixture["origin"]},
    )
    async with stdio_client(params) as streams:
        async with ClientSession(*streams[:2]) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            check(tools == ["download_file", "list_files", "share_file", "upload_file"], f"tools exposed: {tools}")

            async def call(name: str, **args) -> str:
                r = await s.call_tool(name, args)
                text = "\n".join(c.text for c in r.content if hasattr(c, "text"))
                results.append(text)
                return text

            out = await call("list_files")
            check(fixture["report_id"] in out and fixture["notes_id"] in out, "list_files shows the 2 granted files")
            check(fixture["secret_id"] not in out, "list_files does not show the ungranted file")
            out = await call("download_file", file_id=fixture["report_id"])
            check("revenue up 4%" in out and "signature verified" in out, "download_file decrypts a granted file")
            out = await call("download_file", file_id=fixture["secret_id"])
            check("Refused by SealDrop (403): file not in grant" in out and fixture["secret_marker"] not in out,
                  "download_file of an ungranted file is refused by the server")
            out = await call("upload_file", content="Summary written by the agent.")
            check("Uploaded to alice" in out, "upload_file sends a new file to alice, signed by the agent")
            out = await call("share_file", file_id=fixture["report_id"], recipient="carol")
            check("Shared file" in out, "share_file to carol (allowed by the grant) works")
            out = await call("share_file", file_id=fixture["report_id"], recipient="mallory")
            check("share recipient not allowed by grant" in out, "share_file to mallory is refused")

    leaked = [k for k, v in SECRETS.items() for r in results if v and v in r]
    jwts = [r for r in results if JWT.search(r)]
    check(not leaked and not jwts, f"no credential in any of {len(results)} tool results (keys, grant token, JWTs)")


asyncio.run(main())
print("MCP E2E " + ("PASSED" if failures == 0 else f"FAILED ({failures})"))
sys.exit(1 if failures else 0)
