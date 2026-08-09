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

`server.py` is the one you run for real. The rest are the exploratory tools it
grew out of — keep them for poking at a new device, not for production.

| Script | What it's for |
| --- | --- |
| `server.py` | **The production server.** Everything below, plus durable storage, de-duplication, and reliable forwarding of each punch to a cloud endpoint. See [Production server](#production-server) and [ROADMAP.md](ROADMAP.md). |
| `adms.py` | Catch-all request logger. Run this first to confirm the device can actually reach your machine — it dumps every request in full. |
| `door_open.py` | Minimal push server: handshake, live attendance punches, remote door open/hold/release. |
| `caps.py` | Superset of `door_open.py`, plus capability discovery (`/caps`) and parameter get/set (`/setopt`, `/setsensor`). Use this one if you're exploring what the firmware supports. |
| `pull_test.py` | Tests the *opposite* direction — a direct pyzk pull to port 4370. Many standalone terminals never answer this; a timeout is a normal result. |

Everything except `pull_test.py` is standard library only.

## Production server

```bash
export ZK_AUTH_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
export ZK_DEVICE_TZ="Asia/Kolkata"     # required: the device sends naive local time
export ZK_SINKS="log"                  # dry run — store punches, forward nothing

python3 server.py --check-config       # validate the environment and exit
python3 server.py                      # listens on :8081
```

Point the device at it exactly as described below, then watch punches land:

```
09:14:22 INFO  HANDSHAKE (cdata GET)   SN=XXXXXXXXXX (first contact)
09:14:33 INFO  POLL (getrequest)       SN=XXXXXXXXXX (+11.2s)
09:14:46 INFO  UPLOAD (table=ATTLOG)   SN=XXXXXXXXXX (+12.8s)
09:14:46 INFO  PUNCH 12 2026-08-08 09:14:22 2026-08-08T03:44:22Z (check_in via fingerprint)
09:14:46 INFO  delivered 1 row(s) -> infino [de65a370b37e]
```

To forward punches to [Infino Cloud](https://infino.ai/docs), set
`ZK_SINKS=infino,infino_arrivals` with `ZK_INFINO_DATABASE` and
`ZK_INFINO_API_KEY`. One database holds two tables, both created on startup if
they don't exist:

| Table | Grain | Holds |
| --- | --- | --- |
| `attendance` | one row per punch | device truth: user ID, time, direction, verify method |
| `arrivals` | one row per arrival | the same event plus `person_name`, `slack_id`, `github_id` from the directory |

`event_id` is the same in both, so they join. Identity is copied onto the
arrival row rather than referenced, so it records who someone was when they
arrived and stays true after they change their Slack handle — a point-in-time
answer, which is the one you want for an attendance record. Someone with no
directory entry still gets a row, with nulls and `identity_source='unmapped'` —
"arrivals we cannot name" is worth being able to query.

```sql
SELECT person_name, slack_id, github_id, arrived_at_local
  FROM arrivals
 WHERE local_date = '2026-08-09' AND identity_source = 'directory'
```

`log` and `log_arrivals` are the dry-run equivalents: same outbox, same rows,
printed instead of sent.

Each punch is committed to SQLite before the device is acknowledged and queued
in an outbox that a background worker drains in batches with exponential
backoff, honouring `Retry-After` on Infino's cold-start 503. A cloud outage
delays delivery rather than losing punches. Every row carries a stable
`event_id` derived from the punch itself, which is what makes the device's habit
of re-uploading whole batches harmless — and, since Infino has no idempotency
mechanism, it is also how readers should dedup:

```sql
SELECT employee_user_id, punched_at_local, direction
  FROM attendance
 WHERE local_date = '2026-08-08' AND direction = 'check_in'
```

Operator endpoints (`?token=` or an `X-Auth-Token` header):

| Endpoint | Effect |
| --- | --- |
| `/healthz` | Liveness. No token, no personal data. 503 when the device has gone quiet or deliveries are dead-lettered. |
| `/status` | Devices, queue depth, delivery counters |
| `/punches?limit=20` | Most recent punches in the local delivery buffer — a quick look |
| `/attendance` | Attendance from Infino: one row per person per day — see below |
| `/users/sync` | Ask the terminal to upload its user table (run by hand) |
| `/users` | Read back that user table |
| `/open?door=1&sec=5` | Momentary unlock |
| `/hold` / `/release` | Latch the door open / re-lock it |
| `/raw?p=…`, `/reboot` | Only with `ZK_DEBUG_ENDPOINTS=1` |

All settings are documented in `.env.example`. The discovery endpoints
(`/caps`, `/setopt`, `/sweep`, …) are deliberately absent — that work belongs in
`caps.py`.

### Reading attendance back

```bash
curl "http://<ip>:8081/attendance?token=$ZK_AUTH_TOKEN&date=2026-08-09"
curl "…/attendance?token=…&user_id=3&from=2026-08-01&to=2026-08-09&order=asc"
curl "…/attendance?token=…&limit=500&offset=500"
```

| Parameter | Meaning |
| --- | --- |
| `date=YYYY-MM-DD` | One device-local day. Mutually exclusive with `from`/`to`. |
| `from=` / `to=` | Inclusive device-local date range |
| `user_id=` | One person |
| `sn=` | One terminal |
| `limit=` / `offset=` | Page size (1–1000, default 100) and offset |
| `order=asc\|desc` | Oldest or newest first (default `desc`) |

One row per person per day — a daily summary, not a list of events. Use
`/punches` for the raw punches.

```json
{
  "source": {"infino_database": "office-bot-test",
             "attendance_table": "attendance", "arrivals_table": "arrivals"},
  "filters": {"user_id": null, "from": null, "to": null, "order": "desc"},
  "total": 2, "returned": 2, "limit": 100, "offset": 0, "has_more": false,
  "pending_delivery": 0, "redacted": false,
  "attendance": [{
    "user_id": "9", "local_date": "2026-08-09", "name": "Ajay",
    "slack_id": null, "github_id": null,
    "first_seen_local": "2026-08-09 16:30:44",
    "last_seen_local": "2026-08-09 16:30:45",
    "punches": 2, "minutes_on_site": 0
  }]
}
```

**Infino is the source of record.** SQLite is only the delivery buffer on the
way there, so it is not consulted: reading it would answer a subtly different
question depending on how far the outbox had drained. `pending_delivery` is
reported alongside every response so a caller can tell "nobody came in" from
"nothing has shipped yet". If Infino is unreachable the endpoint returns 502
rather than quietly falling back to local data.

`punches` counts distinct `event_id`s — Infino has no idempotency on append,
so a retry can land the same row twice and every reader has to dedup.
`minutes_on_site` is the span from first to last sighting, **not** a sum of
in/out pairs: a terminal that reports no direction (every punch is status
`255`) gives nothing to pair up.

### Who just walked in

The terminal only knows a user ID. To turn that into a person, point
`ZK_DIRECTORY_FILE` at a JSON file mapping each user ID to a name and the
accounts the device cannot know:

```json
{"7": {"name": "Asha Rao", "slack": "U0123ABCDEF", "github": "asharao"}}
```

Build it once from the device itself — `/users/sync`, wait a poll, then
`/users` — and fill in the handles by hand. `directory.example.json` is the
template; copy it to `directory.json`, which is gitignored because it is a
staff list. A check-in then logs:

```
Asha Rao entered office. slack: U0123ABCDEF github: asharao
```

An unknown user ID logs a warning naming the file to add them to, and never
interferes with recording the punch. A malformed file stops startup, so
`--check-config` catches a typo rather than a Monday morning does.

Any punch that isn't explicitly a departure counts as an arrival. Terminals
with their attendance-state feature switched off — the default on most eSSL
units — report every punch as status `255`, meaning they have no direction to
report at all, so requiring an explicit check-in would announce nobody. A
reader that matches the same face twice in consecutive seconds stores both
punches but announces once.

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

For `server.py` you can skip the exporting entirely and keep settings in a file:

```bash
cp dev.env.example dev.env
python3 -c "import secrets; print('ZK_AUTH_TOKEN=' + secrets.token_urlsafe(24))" >> dev.env

python3 server.py --dev                 # loads ./dev.env
python3 server.py --env-file prod.env    # any other file, repeatable
```

`dev.env` is a dry run: punches are stored and logged, nothing is forwarded, so
no cloud account is needed. Real environment variables still win over the file
(`ZK_PORT=9000 python3 server.py --dev`) unless you pass `--override-env`; a
positional port argument beats both. `dev.env` is gitignored because it holds a
working operator token — only the `*.env.example` templates are tracked.

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

`server.py` has a larger set, all documented with defaults in `.env.example`;
run `python3 server.py --check-config` to validate them (add `--dev` or
`--env-file PATH` to validate a file's worth of settings instead of the
environment's). The variables shared with the exploratory scripts:

| Variable | Used by | Meaning |
| --- | --- | --- |
| `ZK_AUTH_TOKEN` | push servers | Shared secret for control endpoints. Required. |
| `ZK_DEVICE_TZ` | `server.py` | IANA zone the device's clock is set to. Required. |
| `ZK_DIRECTORY_FILE` | `server.py` | JSON mapping PIN → name, Slack ID, GitHub login. Optional. |
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
  Review logs before sharing them. `server.py` also stores punches on disk at
  `$ZK_DB_PATH` — that file is personal data, so give it restrictive
  permissions and set a retention period. `ZK_REDACT_PINS=1` hashes employee
  IDs in logs and API output.
- Keep `$ZK_AUTH_TOKEN` and your device Comm Key in the environment or `.env`
  (gitignored), never in source.

## License

MIT
