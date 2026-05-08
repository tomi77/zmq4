#!/usr/bin/env python3
"""F4 libzmq interop bridge.

Reads one line of JSON from stdin describing the desired role,
endpoint, mechanism, and scenario; opens a libzmq PAIR socket; runs
the scenario; exits 0 on success.

JSON config schema:
    {
        "role":      "dialer" | "listener",
        "endpoint":  "tcp://127.0.0.1:5555" | "ipc:///tmp/zmq.sock",
        "mechanism": "NULL" | "PLAIN" | "CURVE",
        "scenario":  "handshake" | "single" | "multipart",
        "plain":     {"user": "...", "pass": "..."}            # PLAIN only
        "curve":     {"server_key": "<z85>",                   # CURVE only
                      "secret_key": "<z85>",
                      "public_key": "<z85>",
                      "is_server":  true|false}
    }

Output (newline-delimited):
    "READY <endpoint>"   — emitted to stdout once the socket is bound/connected.
                            For listeners with port=0, the bound port is interpolated.
    "OK"                 — emitted on scenario success, then exit(0).
    "ERR <message>"      — emitted on failure, then exit(1).
"""

import json
import sys
import zmq


def configure_security(sock: zmq.Socket, mechanism: str, params: dict) -> None:
    if mechanism == "NULL":
        return
    if mechanism == "PLAIN":
        if params.get("is_server", False):
            sock.plain_server = True
        else:
            sock.plain_username = params["user"].encode()
            sock.plain_password = params["pass"].encode()
        return
    if mechanism == "CURVE":
        if params["is_server"]:
            sock.curve_server = True
            sock.curve_secretkey = params["secret_key"].encode()
            sock.curve_publickey = params["public_key"].encode()
        else:
            sock.curve_serverkey = params["server_key"].encode()
            sock.curve_secretkey = params["secret_key"].encode()
            sock.curve_publickey = params["public_key"].encode()
        return
    raise ValueError(f"unknown mechanism {mechanism!r}")


def run_scenario(sock: zmq.Socket, scenario: str) -> None:
    if scenario == "handshake":
        # Just having a usable socket means the handshake completed.
        return
    if scenario == "single":
        # Echo: receive then send back.
        msg = sock.recv()
        sock.send(msg)
        return
    if scenario == "multipart":
        msgs = sock.recv_multipart()
        sock.send_multipart(msgs)
        return
    raise ValueError(f"unknown scenario {scenario!r}")


def main() -> int:
    raw = sys.stdin.readline()
    cfg = json.loads(raw)

    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.PAIR)
    sock.setsockopt(zmq.LINGER, 1000)

    try:
        # Mechanism-specific options must be set BEFORE bind/connect.
        plain_params = dict(cfg.get("plain", {}))
        plain_params["is_server"] = cfg["role"] == "listener"
        curve_params = dict(cfg.get("curve", {}))
        configure_security(sock, cfg["mechanism"],
                           plain_params if cfg["mechanism"] == "PLAIN" else curve_params)

        if cfg["role"] == "listener":
            sock.bind(cfg["endpoint"])
            # libzmq replaces the wildcard port with a concrete one.
            real_endpoint = sock.getsockopt(zmq.LAST_ENDPOINT).decode()
            print(f"READY {real_endpoint}", flush=True)
        else:
            sock.connect(cfg["endpoint"])
            print(f"READY {cfg['endpoint']}", flush=True)

        run_scenario(sock, cfg["scenario"])
        print("OK", flush=True)
        return 0
    except Exception as exc:
        print(f"ERR {type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        sock.close()
        ctx.term()


if __name__ == "__main__":
    sys.exit(main())
