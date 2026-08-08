#!/usr/bin/env python3
"""
door_open.py  —  Minimal iclock / ADMS push server for ZKTeco / eSSL devices
that speak the HTTP "push" protocol (User-Agent "iClock Proxy/1.09" and
similar).

This is the small, focused variant: handshake + attendance logging + remote
door open. If you also want capability discovery and parameter setting, use
caps.py, which is a superset of this file.

WHAT IT DOES
------------
  * Answers the device handshake and keeps it polling.
  * Receives & prints attendance punches (ATTLOG) as they happen.
  * Logs every check-in with the gap since the last one, so you can see the
    device's real poll cadence.
  * Lets you QUEUE A DOOR-OPEN command that fires on the device's next poll —
    your remote unlock button.

Handles both the plain and ".aspx" endpoint variants
(/iclock/getrequest, /iclock/getrequest.aspx, /iclock/cdata, ...).

RUN
---
    export ZK_AUTH_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
    python3 door_open.py                 # port 8081
    python3 door_open.py 8081

Device -> Comm -> Cloud Server Settings:
    Server Address: <this machine's IP>   (macOS: ipconfig getifaddr en0)
    Server Port:    8081
    Server Mode:    ADMS

REMOTE DOOR OPEN
----------------
Every endpoint below requires the token from $ZK_AUTH_TOKEN, passed either as
?token=<value> or as an X-Auth-Token header:

    /open?token=T                     door 1, 5 seconds
    /open?token=T&door=1&sec=10
    /hold?token=T                     latch door open  (/release to re-lock)
    /raw?token=T&p=01010105           send an arbitrary control payload
    /status?token=T                   see what's queued

The command is queued and the device runs it on its next poll (typically <15s).

SECURITY
--------
This server can physically unlock a door. Run it only on a trusted LAN, never
expose the port to the internet, and keep $ZK_AUTH_TOKEN secret. The device
endpoints (/iclock/*) are necessarily unauthenticated because the terminal
cannot present a token — anything that can reach the port can impersonate a
device and push fake attendance records.

Standard library only. Ctrl+C to stop.
"""

import datetime
import os
import secrets
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(
    os.environ.get("ZK_PORT", "8081"))
# The device dials in, so we listen on all interfaces by default. Narrow this
# with ZK_BIND if you know which interface the device uses.
BIND = os.environ.get("ZK_BIND", "0.0.0.0")
# Shared secret for the control endpoints. Required — see SECURITY above.
AUTH_TOKEN = os.environ.get("ZK_AUTH_TOKEN", "")

# Per-serial command queue. When you hit /open we append a command string here;
# the next getrequest poll from that device pops and delivers it.
_queue = {}                     # {serial: [command_str, ...]}
_last_seen = {}                 # {serial: monotonic_time}  -> for cadence
_known_serial = {"sn": None}    # remember the device SN so /open needs no args
_cmd_id = {"n": 0}              # incrementing command id


def _stamp():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _note(sn, label):
    now = time.monotonic()
    prev = _last_seen.get(sn)
    gap = "(first contact)" if prev is None else f"(+{now - prev:5.1f}s)"
    _last_seen[sn] = now
    if sn and sn != "unknown":
        _known_serial["sn"] = sn
    print(f"[{_stamp()}] {label:<26} SN={sn} {gap}")


def _door_command(door, seconds, cc="01", dd="00"):
    """
    Build a door-open control command per ZK PUSH spec:
      CONTROL DEVICE <AA><BB><CC><DD><EE>
        AA = 01        (output-control operation)
        BB = door ID   (01-10)
        CC = 01 lock relay / 02 aux output
        DD = 00 (off/normal) / FF (normal-open latch)
        EE = duration in seconds (01-FE), FF = indefinite
    Default 01 / door / 01 / 00 / EE  ->  e.g. 01 01 01 05 = door1 lock 5s.
    """
    _cmd_id["n"] += 1
    ss = max(1, min(254, int(seconds)))
    payload = f"01{int(door):02X}{cc}{dd}{ss:02X}"
    return f"C:{_cmd_id['n']}:CONTROL DEVICE {payload}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---- helpers -------------------------------------------------------
    def _reply(self, body="OK", ctype="text/plain", status=200):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # Some firmware wants a Date header to sync time; harmless to include.
        self.send_header("Date", datetime.datetime.now(
            datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", errors="replace") if n else ""

    def _authorized(self, q):
        """
        Gate the operator-facing endpoints on a shared secret. Returns True if
        the request may proceed; otherwise it has already sent a response.
        """
        if not AUTH_TOKEN:
            self._reply(
                "ZK_AUTH_TOKEN is not set, so the control endpoints are "
                "disabled.\nStart the server with a token, e.g.:\n"
                "  export ZK_AUTH_TOKEN=\"$(python3 -c "
                "'import secrets;print(secrets.token_urlsafe(24))')\"\n",
                status=503)
            return False
        supplied = q.get("token", [""])[0] or \
            self.headers.get("X-Auth-Token", "")
        if not secrets.compare_digest(supplied, AUTH_TOKEN):
            print(f"[{_stamp()}] DENIED {self.path.split('?')[0]} from "
                  f"{self.client_address[0]} (bad or missing token)")
            self._reply("Unauthorized: pass ?token=<ZK_AUTH_TOKEN> or an "
                        "X-Auth-Token header.\n", status=401)
            return False
        return True

    def _target(self):
        """Resolve the device SN to command, or respond and return None."""
        target = _known_serial["sn"]
        if not target:
            self._reply(
                "No device has checked in yet, so its serial number is "
                "unknown.\nWait for a poll to appear in the log, then retry.\n")
            return None
        return target

    def _enqueue(self, target, cmd, log_label):
        _queue.setdefault(target, []).append(cmd)
        print(f"[{_stamp()}] QUEUED {log_label}: {cmd}")

    # ---- routing -------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        sn = q.get("SN", ["unknown"])[0]

        # ----- device endpoints (unauthenticated: the terminal has no token) --
        if path.startswith("/iclock/getrequest"):
            _note(sn, "POLL (getrequest)")
            pending = _queue.get(sn)
            if pending:
                cmd = pending.pop(0)
                print(f"           -> SENDING: {cmd}")
                return self._reply(cmd)
            return self._reply("OK")

        if path.startswith("/iclock/cdata"):
            # GET on cdata = handshake / config request.
            _note(sn, "HANDSHAKE (cdata GET)")
            # Minimal config block. Realtime=1 asks for prompt punch upload.
            cfg = (
                f"GET OPTION FROM: {sn}\r\n"
                "Stamp=9999\r\n"
                "OpStamp=9999\r\n"
                "ErrorDelay=30\r\n"
                "Delay=10\r\n"
                "TransTimes=00:00;14:05\r\n"
                "TransInterval=1\r\n"
                "TransFlag=1111000000\r\n"
                "Realtime=1\r\n"
                "Encrypt=0\r\n"
            )
            return self._reply(cfg)

        if path.startswith("/iclock/ping"):
            _note(sn, "PING")
            return self._reply("OK")

        if path.startswith("/iclock/"):
            _note(sn, f"OTHER GET {path}")
            return self._reply("OK")

        # ----- operator endpoints (browser / phone) -----
        if not self._authorized(q):
            return

        if path == "/open":
            door = q.get("door", ["1"])[0]
            sec = q.get("sec", ["5"])[0]
            cc = q.get("cc", ["01"])[0]   # 01=lock relay, 02=aux
            dd = q.get("dd", ["00"])[0]   # 00=normal, FF=normal-open latch
            target = self._target()
            if not target:
                return
            cmd = _door_command(door, sec, cc, dd)
            self._enqueue(target, cmd,
                          f"door-open for {target} (door={door}, cc={cc}, "
                          f"dd={dd}, {sec}s)")
            return self._reply(
                f"Door-open queued for {target}: {cmd}\n"
                f"Fires on the device's next poll (typically <15s).\n")

        if path == "/hold":
            # Enable NORMAL-OPEN state on door 1 (DD=FF). This exercises the
            # door-state subsystem (the same one the device menu's "Normally
            # Open" setting uses) rather than the momentary output pulse, which
            # is a no-op on some standalone terminals.
            target = self._target()
            if not target:
                return
            _cmd_id["n"] += 1
            cmd = f"C:{_cmd_id['n']}:CONTROL DEVICE 010101FF00"
            self._enqueue(target, cmd, "HOLD-OPEN (normal-open enable)")
            return self._reply(
                f"Queued normal-open ENABLE: {cmd}\n"
                "If this works the door unlocks and STAYS open. "
                "Use /release to re-lock.\n")

        if path == "/release":
            # Disable normal-open / close (DD=00, duration=00).
            target = self._target()
            if not target:
                return
            _cmd_id["n"] += 1
            cmd = f"C:{_cmd_id['n']}:CONTROL DEVICE 0101010000"
            self._enqueue(target, cmd, "RELEASE (normal-open disable)")
            return self._reply(f"Queued normal-open DISABLE / re-lock: {cmd}\n")

        if path == "/info":
            # Ask the device to push its info (counts, versions, capabilities).
            # Different firmware honors different forms; we queue several and
            # watch what comes back on the next cdata POST.
            target = self._target()
            if not target:
                return
            for c in ("INFO", "CHECK", "LOG"):
                _cmd_id["n"] += 1
                _queue.setdefault(target, []).append(f"C:{_cmd_id['n']}:{c}")
            print(f"[{_stamp()}] QUEUED info/check/log queries for {target}")
            return self._reply(
                "Queued INFO/CHECK/LOG. Watch for a cdata POST or devicecmd "
                "reply with the device's details.\n")

        if path == "/param":
            # Query specific device parameters. The device replies via a
            # cdata POST (often table=options) or in the devicecmd body.
            names = q.get("names", [
                "~SerialNumber,LockCount,AuxOutCount,DoorCount,ReaderCount,"
                "~ZKFPVersion,~DeviceName,MachineType,AuxInCount,"
                "Door1Drivertime,Door2Drivertime"
            ])[0]
            target = self._target()
            if not target:
                return
            _cmd_id["n"] += 1
            cmd = f"C:{_cmd_id['n']}:GET OPTIONS {names}"
            self._enqueue(target, cmd, f"param query for {target}")
            return self._reply(
                f"Queued parameter query:\n  {cmd}\n"
                "Watch the log for the device's reply (devicecmd body or a "
                "cdata POST).\n")

        if path == "/sweep":
            # Queue the most likely 'open door' payloads in sequence. Watch the
            # door; whichever one opens it is the payload this firmware wants.
            # Each fires one poll interval apart.
            target = self._target()
            if not target:
                return
            candidates = [
                ("01010105", "door1 lock 5s (spec default)"),
                ("01020105", "door1 AUX 5s"),
                ("02010105", "door2 lock 5s"),
                ("010101FF", "door1 lock indefinite"),
                ("01010A05", "door1, CC=0A variant"),
                ("0101FF05", "door1 normal-open latch"),
                ("01000105", "door id 00 lock 5s"),
            ]
            for payload, _label in candidates:
                _cmd_id["n"] += 1
                _queue.setdefault(target, []).append(
                    f"C:{_cmd_id['n']}:CONTROL DEVICE {payload}")
            print(f"[{_stamp()}] QUEUED SWEEP of {len(candidates)} payloads "
                  f"for {target}")
            listing = "\n".join(f"  {p}  - {l}" for p, l in candidates)
            return self._reply(
                "Queued a sweep. Watch the door; each fires ~one poll apart.\n"
                "Note which payload (in the server log's -> SENDING line) "
                "opens it:\n" + listing + "\n")

        if path == "/raw":
            # Send an arbitrary control payload for testing, e.g.
            #   /raw?p=01000105   /raw?p=01010100   /raw?p=0101010A
            payload = q.get("p", ["01010105"])[0]
            target = self._target()
            if not target:
                return
            _cmd_id["n"] += 1
            cmd = f"C:{_cmd_id['n']}:CONTROL DEVICE {payload}"
            self._enqueue(target, cmd, f"raw for {target}")
            return self._reply(f"Queued raw command: {cmd}\n")

        if path == "/reboot":
            # Sanity check: if THIS makes the device reboot, the command
            # channel definitely controls the device. Reboot = 03000000.
            target = self._target()
            if not target:
                return
            _cmd_id["n"] += 1
            cmd = f"C:{_cmd_id['n']}:CONTROL DEVICE 03000000"
            self._enqueue(target, cmd, f"REBOOT for {target}")
            return self._reply(f"Queued reboot: {cmd}\n")

        if path == "/status":
            lines = ["Queued commands:"]
            if not _queue or not any(_queue.values()):
                lines.append("  (none)")
            for s, cmds in _queue.items():
                for c in cmds:
                    lines.append(f"  {s}: {c}")
            lines.append("")
            lines.append(f"Known device SN: {_known_serial['sn']}")
            return self._reply("\n".join(lines) + "\n")

        return self._reply("Unknown endpoint. See the module docstring for the "
                           "list of control endpoints.\n", status=404)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        sn = q.get("SN", ["unknown"])[0]
        table = q.get("table", [""])[0]
        body = self._body()

        if path.startswith("/iclock/cdata"):
            _note(sn, f"UPLOAD (table={table or '?'})")
            if table.upper() == "ATTLOG":
                count = 0
                for ln in body.splitlines():
                    if not ln.strip():
                        continue
                    count += 1
                    print(f"           -> PUNCH: {ln.strip()}")
                return self._reply(f"OK: {count}")
            if body.strip():
                print(f"           body: {body.strip()[:400]}")
            return self._reply("OK")

        if path.startswith("/iclock/devicecmd"):
            _note(sn, "CMD RESULT (devicecmd)")
            if body.strip():
                print(f"           ack: {body.strip()[:300]}")
            return self._reply("OK")

        _note(sn, f"OTHER POST {path}")
        if body.strip():
            print(f"           body: {body.strip()[:300]}")
        return self._reply("OK")


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
    tok = f"?token={AUTH_TOKEN}" if AUTH_TOKEN else "?token=<ZK_AUTH_TOKEN>"
    print("=" * 70)
    print(" ZKTeco / eSSL push server  (iclock / ADMS)")
    print("=" * 70)
    print(f" Listening on http://{ip}:{PORT}   (bind {BIND})")
    print()
    print(" Device -> Comm -> Cloud Server Settings:")
    print(f"     Server Address: {ip}")
    print(f"     Server Port:    {PORT}")
    print("     Server Mode:    ADMS")
    print()
    if not AUTH_TOKEN:
        print(" !! ZK_AUTH_TOKEN is not set — control endpoints are DISABLED.")
        print("    export ZK_AUTH_TOKEN=\"$(python3 -c "
              "'import secrets;print(secrets.token_urlsafe(24))')\"")
        print()
    print(" Remote door open (same network, token required):")
    print(f"     http://{ip}:{PORT}/open{tok}")
    print(f"     http://{ip}:{PORT}/open{tok}&door=1&sec=10")
    print(f"     http://{ip}:{PORT}/status{tok}")
    print()
    print(" Watch the log: (+Ns) shows the device's real poll/push cadence.")
    print(" Keep this port on a trusted LAN only — it can unlock a door.")
    print(" Ctrl+C to stop.")
    print("=" * 70)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
