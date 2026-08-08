#!/usr/bin/env python3
"""
pull_test.py — Test a pyzk DIRECT PULL connection to a ZKTeco / eSSL device.

This connects OUT from this machine to the device on port 4370 (the opposite
direction from the push server, which the device dials into). Many standalone
terminals never answer this handshake even when they are reachable on the
network, so a timeout here is a normal result rather than a bug.

Setup:
    pip install -r requirements.txt

    export ZK_DEVICE_IP=192.168.1.100      # your device's address
    export ZK_COMM_KEY=0                   # Comm Key set on the device
    python3 pull_test.py

    python3 pull_test.py 192.168.1.100 4370   # or pass IP / port as arguments

Tries TCP first, then UDP. ommit_ping is used because many of these devices
ignore ICMP.

WARNING: --unlock will physically open the door if the pull channel works.
Only run this against a device you are authorized to control.
"""

import argparse
import logging
import os
import sys

try:
    from zk import ZK
except ImportError:
    sys.exit("pyzk not installed. Run:  pip install -r requirements.txt")

DEFAULT_IP = os.environ.get("ZK_DEVICE_IP", "192.168.1.100")
DEFAULT_PORT = int(os.environ.get("ZK_DEVICE_PORT", "4370"))
# The device's Comm Key. Keep this in the environment, not in source control.
COMM_KEY = int(os.environ.get("ZK_COMM_KEY", "0"))


def try_connect(ip, port, force_udp, unlock_seconds=0):
    mode = "UDP" if force_udp else "TCP"
    print(f"\n--- Trying {mode} (force_udp={force_udp}) ---")
    zk = ZK(ip, port=port, timeout=30,
            password=COMM_KEY, force_udp=force_udp, ommit_ping=True,
            verbose=True)
    try:
        conn = zk.connect()
    except Exception as e:
        print(f"  {mode} failed: {e}")
        return False

    print(f"  CONNECTED over {mode}!")
    try:
        print("  Firmware:", conn.get_firmware_version())
        print("  Serial:  ", conn.get_serialnumber())
        print(f"  Users:    {len(conn.get_users())}")
        print(f"  Attendance records: {len(conn.get_attendance())}")
        if unlock_seconds:
            print(f"  Attempting SDK unlock({unlock_seconds})...")
            conn.unlock(unlock_seconds)
            print("  unlock() sent — check whether the door opened.")
    except Exception as e:
        print("  Connected, but a follow-up call failed:", e)
    finally:
        conn.disconnect()
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("ip", nargs="?", default=DEFAULT_IP,
                   help="device IP (default: $ZK_DEVICE_IP)")
    p.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT,
                   help="device port (default: $ZK_DEVICE_PORT or 4370)")
    p.add_argument("--unlock", type=int, metavar="SECONDS", default=0,
                   help="if connected, also send unlock() for N seconds "
                        "(this physically opens the door)")
    p.add_argument("--debug", action="store_true", help="verbose pyzk logging")
    args = p.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    print(f"Testing pyzk pull against {args.ip}:{args.port} "
          f"(comm key from $ZK_COMM_KEY)")
    if not try_connect(args.ip, args.port, False, args.unlock):
        try_connect(args.ip, args.port, True, args.unlock)
    print("\nDone. If neither transport connected, this device likely does not "
          "speak the pyzk pull protocol — use the push server instead.")


if __name__ == "__main__":
    main()
