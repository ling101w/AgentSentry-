#!/usr/bin/env python3
"""Small local client used by the shell sandbox transaction."""

from __future__ import annotations

import argparse
import json
import socket
import sys


def request(path: str, payload: dict[str, object]) -> dict[str, object]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(0.5)
    client.connect(path)
    client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    data = client.recv(65536)
    client.close()
    return json.loads(data.decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("operation", choices=("register", "unregister", "status"))
    parser.add_argument("--pid", type=int)
    args = parser.parse_args()
    payload: dict[str, object] = {"op": args.operation}
    if args.pid is not None:
        payload["pid"] = args.pid
    if args.operation == "register":
        payload["deny_network"] = True
    try:
        response = request(args.socket, payload)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not response.get("ok"):
        print(str(response.get("error", "kernel enforcer rejected request")), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
