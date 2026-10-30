"""Agent command line.

  python -m sealdrop_agent init --name "Research bot"   create keys, print the public bundle
  python -m sealdrop_agent set-agent-id agt_...         after a user registers the bundle
  python -m sealdrop_agent set-grant  < token.txt       grant token from the user (read from stdin,
                                                        so it never lands in shell history)
  python -m sealdrop_agent serve                        run the MCP server (stdio)
"""
import argparse
import json
import sys

from .identity import AgentIdentity, home


def main() -> None:
    p = argparse.ArgumentParser(prog="sealdrop_agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--name", required=True)
    i.add_argument("--force", action="store_true", help="replace existing keys")
    s = sub.add_parser("set-agent-id")
    s.add_argument("agent_id")
    sub.add_parser("set-grant")
    sub.add_parser("bundle")
    sub.add_parser("serve")
    args = p.parse_args()

    if args.cmd == "init":
        if (home() / "agent.json").exists() and not args.force:
            sys.exit(f"keys already exist in {home()} (use --force to replace)")
        ident = AgentIdentity.create(args.name)
        print(json.dumps(ident.public_bundle()))
        print(f"Keys stored privately in {home() / 'agent.json'}. Paste the line above into SealDrop.", file=sys.stderr)
    elif args.cmd == "bundle":
        print(json.dumps(AgentIdentity.load().public_bundle()))
    elif args.cmd == "set-agent-id":
        ident = AgentIdentity.load()
        ident.agent_id = args.agent_id
        ident.save()
    elif args.cmd == "set-grant":
        ident = AgentIdentity.load()
        ident.grant_token = sys.stdin.read().strip()
        ident.save()
        print("grant token stored", file=sys.stderr)
    elif args.cmd == "serve":
        from .server import main as serve
        serve()


if __name__ == "__main__":
    main()
