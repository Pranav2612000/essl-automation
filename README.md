# essl-automation

A small set of standard-library Python scripts for talking to ZKTeco / eSSL
biometric access-control terminals that speak the HTTP **iclock / ADMS "push"**
protocol (User-Agent `iClock Proxy/1.09`, e.g. ZAM70 / x2008 class devices).

These devices don't accept inbound connections in any useful way — they dial
*out* to a "cloud server" you configure in their menu and poll it for commands.
So instead of a client, you run a tiny HTTP server on your LAN, the device
checks in every ~10-15 seconds, and you hand it commands on those polls. That
gets you live attendance punches and a remote door-unlock button without any
vendor software.

## Scripts

| Script | What it's for |
| --- | --- |
| `adms.py` | Catch-all request logger. Run this first to confirm the device can actually reach your machine — it dumps every request in full. |
| `door_open.py` | Minimal push server: handshake, live attendance punches, remote door open/hold/release. |
| `caps.py` | Superset of `door_open.py`, plus capability discovery (`/caps`) and parameter get/set (`/setopt`, `/setsensor`). Use this one if you're exploring what the firmware supports. |
| `pull_test.py` | Tests the *opposite* direction — a direct pyzk pull to port 4370. Many standalone terminals never answer this; a timeout is a normal result. |

Everything except `pull_test.py` is standard library only.

## Setup

```bash
git clone git@github.com:Pranav2612000/essl-automation.git
cd essl-automation

# only needed for pull_test.py
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your own values. Nothing in this repo
contains real device credentials — the comm key, device IP, and control token
are all read from the environment.

## Usage

Generate a control token and start the server:

```bash
export ZK_AUTH_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
python3 caps.py            # listens on :8081
```

Point the device at it — **Menu → Comm → Cloud Server Settings**:

```
Server Address: <your machine's LAN IP>     # macOS: ipconfig getifaddr en0
Server Port:    8081
Server Mode:    ADMS
```

Within a few seconds you should see polls in the log:

```
[14:22:07] HANDSHAKE (cdata GET)      SN=XXXXXXXXXX (first contact)
[14:22:18] POLL (getrequest)          SN=XXXXXXXXXX (+ 11.2s)
[14:22:31] UPLOAD (table=ATTLOG)      SN=XXXXXXXXXX (+ 12.8s)
           -> PUNCH: 12  2026-08-08 14:22:30  0  1
```

Then open the door from a browser or phone on the same network:

```
http://<your-ip>:8081/open?token=$ZK_AUTH_TOKEN
http://<your-ip>:8081/open?token=$ZK_AUTH_TOKEN&door=1&sec=10
http://<your-ip>:8081/status?token=$ZK_AUTH_TOKEN
```

Commands are queued and delivered on the device's next poll, so expect up to
~15s of latency. `/status` shows what's still pending.

### Endpoints

Control endpoints require the token from `$ZK_AUTH_TOKEN`, as `?token=<value>`
or an `X-Auth-Token` header. If the variable isn't set, they're disabled.

| Endpoint | Effect |
| --- | --- |
| `/open?door=1&sec=5` | Momentary unlock |
| `/hold` / `/release` | Latch the door open / re-lock it |
| `/raw?p=01010105` | Send an arbitrary `CONTROL DEVICE` payload |
| `/sweep` | Try the likely door-open payloads in sequence |
| `/param`, `/info` | Query device parameters |
| `/caps`, `/caps/show` | Discover supported options (`caps.py` only) |
| `/setopt?k=Name&v=Value`, `/setsensor?v=0` | Set a parameter (`caps.py` only) |
| `/status` | List queued commands |
| `/reboot` | Reboot the device |

Not every payload works on every firmware. Standalone terminals in particular
often ignore the momentary output pulse while still honouring the normal-open
latch — `/sweep` and `/hold` exist to find out which applies to yours.

## Environment variables

| Variable | Used by | Meaning |
| --- | --- | --- |
| `ZK_AUTH_TOKEN` | push servers | Shared secret for control endpoints. Required. |
| `ZK_PORT` | push servers | Listen port (default `8081`; a CLI argument overrides it). |
| `ZK_BIND` | push servers | Bind address (default `0.0.0.0`, since the device dials in). |
| `ZK_DEVICE_IP` | `pull_test.py` | Device address. |
| `ZK_DEVICE_PORT` | `pull_test.py` | Device port (default `4370`). |
| `ZK_COMM_KEY` | `pull_test.py` | The Comm Key configured on the device. |

## Security

Read this before running any of it:

- **These scripts can physically unlock a door.** Run them only against a
  device you own or are authorized to administer.
- **Keep the port on a trusted LAN.** Don't port-forward it or expose it to the
  internet. If you need remote access, put it behind a VPN.
- **The `/iclock/*` device endpoints cannot be authenticated** — the terminal
  has no way to present a token. Anything that can reach the port can
  impersonate a device and push fake attendance records. The protocol itself
  offers no real authentication; that's a property of these devices, not of
  this code.
- **Server output contains device serial numbers and attendance records.**
  Review logs before sharing them.
- Keep `$ZK_AUTH_TOKEN` and your device Comm Key in the environment or `.env`
  (gitignored), never in source.

## License

MIT
