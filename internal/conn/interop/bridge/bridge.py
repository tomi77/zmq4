#!/usr/bin/env python3
"""F4/F5a libzmq interop bridge.

Reads one line of JSON from stdin describing the desired role,
endpoint, mechanism, socket_type, and scenario; opens a libzmq socket;
runs the scenario; exits 0 on success.

JSON config schema:
    {
        "role":        "dialer" | "listener",
        "endpoint":    "tcp://127.0.0.1:5555" | "ipc:///tmp/zmq.sock",
        "mechanism":   "NULL" | "PLAIN" | "CURVE",
        "socket_type": "PAIR" | "REQ" | "REP" | "DEALER" | "ROUTER",
        "scenario":    "handshake" | "single" | "multipart",
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
import time
import zmq


SOCKET_TYPES = {
    "PAIR":   zmq.PAIR,
    "REQ":    zmq.REQ,
    "REP":    zmq.REP,
    "DEALER": zmq.DEALER,
    "ROUTER": zmq.ROUTER,
    "PUB":    zmq.PUB,
    "SUB":    zmq.SUB,
    "XPUB":   zmq.XPUB,
    "XSUB":   zmq.XSUB,
}


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


def run_scenario(sock: zmq.Socket, scenario: str, socket_type: str) -> None:
    if scenario == "handshake":
        # A usable socket means the handshake completed.
        return

    if socket_type in ("REQ", "DEALER"):
        # Active sockets: initiate by sending first, then recv the echo.
        if scenario == "single":
            sock.send(b"INTEROP")
            sock.recv()
        elif scenario == "multipart":
            sock.send_multipart([b"INTEROP_P1", b"INTEROP_P2"])
            sock.recv_multipart()
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        return

    if socket_type == "ROUTER":
        # ROUTER always uses multipart (libzmq prepends identity frame).
        # recv_multipart gives [identity, ...frames]; send_multipart echoes back.
        frames = sock.recv_multipart()
        sock.send_multipart(frames)
        return

    if socket_type == "PUB":
        # PUB: wait briefly for subscriptions to propagate, then send.
        time.sleep(0.1)
        if scenario == "single":
            sock.send(b"INTEROP")
        elif scenario == "multipart":
            sock.send_multipart([b"INTEROP", b"INTEROP_P1", b"INTEROP_P2"])
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        return

    if socket_type in ("SUB", "XSUB"):
        # SUB/XSUB: subscribe to all, then receive one message.
        sock.setsockopt(zmq.SUBSCRIBE, b"")
        if scenario == "single":
            sock.recv()
        elif scenario == "multipart":
            sock.recv_multipart()
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        return

    if socket_type == "XPUB":
        # XPUB: wait briefly for subscriptions, drain subscription frames, then send.
        time.sleep(0.1)
        # Drain any pending subscription frames with a short poll.
        poller = zmq.Poller()
        poller.register(sock, zmq.POLLIN)
        while poller.poll(timeout=50):
            sock.recv()  # consume subscription frame
        if scenario == "single":
            sock.send(b"INTEROP")
        elif scenario == "multipart":
            sock.send_multipart([b"INTEROP", b"INTEROP_P1", b"INTEROP_P2"])
        else:
            raise ValueError(f"unknown scenario {scenario!r}")
        return

    # PAIR, REP: passive echo.
    if scenario == "single":
        msg = sock.recv()
        sock.send(msg)
    elif scenario == "multipart":
        msgs = sock.recv_multipart()
        sock.send_multipart(msgs)
    else:
        raise ValueError(f"unknown scenario {scenario!r}")


def main() -> int:
    raw = sys.stdin.readline()
    cfg = json.loads(raw)

    ctx = zmq.Context.instance()
    socket_type_name = (cfg.get("socket_type") or "PAIR").upper()
    zmq_type = SOCKET_TYPES.get(socket_type_name, zmq.PAIR)
    sock = ctx.socket(zmq_type)
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

        run_scenario(sock, cfg["scenario"], socket_type_name)
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
