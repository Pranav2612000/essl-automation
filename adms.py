#!/usr/bin/env python3
"""
adms.py  —  Catch-all HTTP request logger. Logs EVERY incoming request, in full.

Purpose: run this, then trigger the device's cloud/ADMS diagnostic ("test
connection") from its menu. If the device sends anything at all, you'll see it
here — method, path, headers, and body. Total silence means the device isn't
reaching this machine. Use it to prove connectivity before moving on to the
real push server (door_open.py / caps.py).

RUN:
    python3 adms.py            # listens on port 8081
    python3 adms.py 80         # or pick a port (80 needs sudo)

On the device -> Comm -> Cloud Server Settings:
    Server Address: <this machine's IP>   (macOS: ipconfig getifaddr en0)
    Server Port:    <same port this is listening on, default 8081>
    Server Mode:    ADMS
Then run the device's diagnostic / test-connection, or reboot it, and watch
the output below.

NOTE: this prints every request in full, including headers and bodies that may
contain device serial numbers and attendance data. Don't paste raw output into
a public issue without reviewing it first.

Uses only Python's standard library — no Flask, no pip install needed.
Ctrl+C to stop.
"""

import datetime
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(
    os.environ.get("ZK_PORT", "8081"))
BIND = os.environ.get("ZK_BIND", "0.0.0.0")


def _stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Handler(BaseHTTPRequestHandler):
    # Silence the default noisy per-request logging; we print our own.
    def log_message(self, *args):
        pass

    def _dump(self, method):
        peer = self.client_address[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        print("\n" + "=" * 70)
        print(f"[{_stamp()}]  {method}  {self.path}")
        print(f"    from: {peer}")
        # Headers can reveal the device model / firmware / serial.
        for k, v in self.headers.items():
            print(f"    {k}: {v}")
        if body:
            text = body.decode("utf-8", errors="replace")
            print("    --- body ---")
            for line in text.splitlines() or [text]:
                print(f"    {line}")
        print("=" * 70)

        # Reply with something friendly so the device considers the test a
        # success (helps its diagnostic report "OK" and encourages it to talk).
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    # Handle every method the device might use.
    def do_GET(self):
        self._dump("GET")

    def do_POST(self):
        self._dump("POST")

    def do_PUT(self):
        self._dump("PUT")

    def do_HEAD(self):
        self._dump("HEAD")


def _lan_ip():
    """Best-effort local IP, for printing the address to configure on device."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))   # TEST-NET-1: routed nowhere, never sent
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == "__main__":
    ip = _lan_ip()
    print("=" * 70)
    print(" Catch-all request logger")
    print("=" * 70)
    print(f" Listening on:  http://{ip}:{PORT}   (bind {BIND})")
    print(f" Point the device's Cloud Server at:  {ip} : {PORT}")
    print(" Then run the device's diagnostic / test-connection, or reboot it.")
    print(" Anything the device sends will be dumped in full below.")
    print(" Ctrl+C to stop.")
    print("=" * 70)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
