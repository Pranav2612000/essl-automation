#!/usr/bin/env python3
"""
server.py  —  Production iclock / ADMS push server for ZKTeco / eSSL terminals.

This is the service you actually run. It is derived from the exploratory
scripts in this repo (adms.py, door_open.py, caps.py) but differs from them in
the ways that matter once attendance data has to reach somewhere else:

  * Attendance is stored only in Infino. There is no local database: a punch
    is acknowledged to the terminal only once the cloud has accepted it, which
    makes the device's own buffer the retry queue. Refuse the upload and it
    keeps the records and offers them again.
  * A greeting is claimed once per person per day against the arrivals table
    itself, so a restart or a device re-upload cannot produce a second one.
    Appends take about half a second to become visible to a query, so a small
    in-process set covers repeats faster than that — this terminal reports the
    same face twice one second apart.
  * Shared state is behind locks. ThreadingHTTPServer runs handlers
    concurrently; the exploratory scripts mutate module-level dicts and an
    integer counter without synchronisation.
  * Punch timestamps are anchored to a configured timezone. The device sends
    naive local time with no offset, which is unusable downstream unless we
    record which zone it meant.
  * Request bodies are capped, unknown serials can be rejected, and the
    discovery / door-sweep endpoints are gone (they live in caps.py, which is
    the right place for lab work).

WHAT IT DOES NOT DO YET
-----------------------
Fetching a person's pending GitHub / Slack work and DMing them a good-morning
summary is the goal of this project, but it is not in this file. The seam it
will plug into is the outbox: one row per (punch, sink), so a "greeting" sink
joins the existing "cloud" sink without touching the device protocol. See
ROADMAP.md, phases 4-8.

RUN
---
    export ZK_AUTH_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
    export ZK_DEVICE_TZ="Asia/Kolkata"
    python3 server.py --check-config      # validate config and exit
    python3 server.py                     # listens on :8081

Settings can come from a file instead of the environment:

    python3 server.py --dev               # load ./dev.env (dry run, no cloud)
    python3 server.py --env-file prod.env # any file; repeatable, later wins

Point ZK_DIRECTORY_FILE at a JSON file of user ID -> {name, slack, github} and a
check-in logs who walked in. See directory.example.json; build it from the
device's own roster with /users/sync then /users.

Real environment variables override the file (use --override-env to invert
that), and a positional port argument overrides both.

Device -> Comm -> Cloud Server Settings:
    Server Address: <this machine's IP>   (macOS: ipconfig getifaddr en0)
    Server Port:    8081
    Server Mode:    ADMS

ENDPOINTS
---------
Device (unauthenticated — a terminal cannot present a token):
    /iclock/cdata        GET handshake, POST attendance & other table uploads
    /iclock/getrequest   command poll
    /iclock/devicecmd    command acknowledgements
    /iclock/ping

Operator (require $ZK_AUTH_TOKEN as ?token= or an X-Auth-Token header):
    /healthz             liveness, no token, no data
    /status              devices, outbox depth, queued commands
    /punches?limit=20    most recent punches in the local buffer
    /attendance          attendance from Infino: one row per person per day
                         ?date= | ?from=&to=  ?user_id=  ?sn=
                         ?limit=&offset=  ?order=asc|desc
    /users/sync          ask the device to upload its user table (one-off)
    /users               read back the user table it sent
    /open?door=1&sec=5   momentary unlock
    /hold  /release      latch open / re-lock
    /raw?p=01010105      arbitrary control payload  (ZK_DEBUG_ENDPOINTS=1)
    /reboot              reboot the terminal        (ZK_DEBUG_ENDPOINTS=1)

SECURITY
--------
The device protocol has no authentication and no TLS: the terminal cannot
present a credential, so anything that can reach this port can impersonate it
and inject attendance records. Treat the listening port as LAN-only, never
port-forward it, and treat stored punches as attacker-influencable if the LAN
is not trusted. This server can also physically unlock a door. The cloud leg,
by contrast, is authenticated and HTTPS-only unless you explicitly opt out.

Standard library only.
"""

import argparse
import datetime
import hashlib
import json
import logging
import logging.handlers
import os
import random
import re
import secrets
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

USER_AGENT = "essl-automation-server/1.0"
PAYLOAD_SCHEMA = "essl.attendance.v1"
ARRIVAL_SCHEMA = "essl.arrival.v1"
LOG = logging.getLogger("essl")

# Sinks are split by what they carry, not by where they send it. An attendance
# sink takes one row per punch — device truth. An arrival sink takes one row
# per announced arrival, with identity attached. A punch produces an outbox row
# for every configured sink of the kind it qualifies for.
ATTENDANCE_SINKS = frozenset({"log", "infino"})
ARRIVAL_SINKS = frozenset({"log_arrivals", "infino_arrivals"})
KNOWN_SINKS = ATTENDANCE_SINKS | ARRIVAL_SINKS

# ATTLOG status codes (byte 3 of each record).
PUNCH_STATUS = {
    0: "check_in",
    1: "check_out",
    2: "break_out",
    3: "break_in",
    4: "overtime_in",
    5: "overtime_out",
    # Sent when the terminal's attendance-state feature is off, so it has no
    # direction to report. Most eSSL units ship that way and send it for every
    # punch — this is the common case, not a fault.
    255: "unspecified",
}
# Statuses that mean the person is leaving. Everything else counts as an
# arrival, including "unspecified": when the device declines to say, the
# useful default is to treat a punch as someone showing up. Phase 5's
# first-punch-of-day rule is what will make that precise.
DEPARTURE_STATUS = frozenset({1, 2, 5})     # check_out, break_out, overtime_out
# Verification method (byte 4). Firmware-dependent beyond these.
VERIFY_METHOD = {
    0: "password",
    1: "fingerprint",
    2: "card",
    3: "fingerprint_or_password",
    4: "card_or_fingerprint",
    15: "face",
}
# USERINFO `Pri` field: what the person may do on the terminal itself.
PRIVILEGE = {
    0: "user",
    2: "enroller",
    6: "admin",
    14: "super_admin",
}

# Fallback parse for firmware that pads ATTLOG columns with spaces rather than
# tabs. The timestamp itself contains a space, so a plain split() won't do.
_ATTLOG_RE = re.compile(
    r"^\s*(?P<pin>\S+)\s+"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<status>\S+))?"
    r"(?:\s+(?P<verify>\S+))?"
    r"(?:\s+(?P<workcode>\S+))?"
)

# A user record, as the terminal emits it in reply to DATA QUERY USERINFO:
#     USER PIN=7<TAB>Name=Asha Rao<TAB>Pri=0<TAB>Passwd=<TAB>Card=12345<TAB>Grp=1<TAB>TZ=…
# The same dump also carries FP / FACE / BIODATA lines holding biometric
# templates. We do not parse those — but they still pass through the log and
# the `uploads` table, which is what _SECRET_VALUE_RE below is for.
_USER_PREFIX_RE = re.compile(r"^\s*USER\s+", re.I)
# Fields to strip out of anything we log or store: biometric templates, and
# the terminal password, which is a credential that opens a door.
# The trailing lookahead stops the redaction at the next field rather than at
# the next tab: space-padded firmware would otherwise lose the whole rest of
# the record from the copy we keep.
_SECRET_VALUE_RE = re.compile(
    r"((?:^|[\t ])(?:tmp|template|content|passwd|password|pw)=)"
    r"[^\r\n]*?(?=[\t ]+[A-Za-z][A-Za-z0-9_]*=|[\r\n]|$)",
    re.I)
# A key in a `Key=value` record. The lookbehind stops it matching inside a
# value; keys always follow a separator.
_KV_KEY_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*)=")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised for a bad or missing environment variable."""


# Loaded by --dev, so a development run needs no exported variables at all.
DEV_ENV_FILE = "dev.env"

_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def load_env_file(path, override=False, protect=None):
    """Merge KEY=VALUE lines from `path` into os.environ.

    Accepts the same shape as the `.env` files these scripts already document:
    blank lines, `#` comments, an optional `export ` prefix, and single- or
    double-quoted values. The real environment wins by default, so an exported
    variable (or a systemd unit's Environment=) still overrides the file and a
    one-off `ZK_PORT=9000 python3 server.py --dev` does what it looks like.

    `protect` is the set of names the real environment supplied, snapshotted
    before the first file was read. Pass it when layering several files so a
    later file can override an earlier one while both still yield to the real
    environment; it defaults to whatever is in os.environ right now.
    `override=True` ignores it and lets the file win over everything.

    Returns the list of names taken from the file.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            lines = fh.readlines()
    except OSError as e:
        raise ConfigError(f"cannot read config file {path}: {e.strerror}")

    if protect is None:
        protect = frozenset(os.environ)

    applied = []
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            raise ConfigError(f"{path}:{lineno}: expected KEY=value, got {line!r}")
        name, raw = m.group(1), m.group(2).strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
            value = raw[1:-1]
        else:
            # An unquoted value ends at an inline comment; quote it to keep a #.
            value = raw.split(" #", 1)[0].strip()
        if override or name not in protect:
            os.environ[name] = value
            applied.append(name)
    return applied


def _env_int(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not an integer")


def _env_float(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not a number")


def _env_bool(name, default=False):
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name}={raw!r} is not a boolean (use 1/0)")


@dataclass(frozen=True)
class Config:
    port: int
    bind: str
    auth_token: str
    device_tz: str
    directory_file: str
    log_level: str
    log_file: str
    redact_pins: bool
    sinks: tuple
    infino_url: str
    infino_database: str
    infino_table: str
    infino_arrivals_table: str
    infino_users_table: str
    infino_api_key: str
    infino_timeout: float
    infino_bootstrap: bool
    infino_batch_rows: int
    infino_batch_bytes: int
    max_attempts: int
    retry_base_secs: float
    retry_cap_secs: float
    worker_poll_secs: float
    max_body_bytes: int
    allowed_serials: frozenset
    debug_endpoints: bool
    silence_secs: int

    @classmethod
    def from_env(cls, argv_port=None):
        serials = {s.strip() for s in
                   os.environ.get("ZK_ALLOWED_SERIALS", "").split(",")
                   if s.strip()}
        sinks = tuple(s.strip() for s in
                      os.environ.get("ZK_SINKS", "infino").split(",")
                      if s.strip())

        # Infino's docs hand you an SDK connect target with the database as the
        # last path segment ("https://api.platform.infino.ws/my-app"), but the
        # REST paths need host and database separately. Accept either form.
        infino_url = os.environ.get(
            "ZK_INFINO_URL", "https://api.platform.infino.ws").rstrip("/")
        database = os.environ.get("ZK_INFINO_DATABASE", "").strip()
        parsed = urlparse(infino_url)
        path = parsed.path.strip("/")
        if path:
            if not database:
                database = path
            infino_url = f"{parsed.scheme}://{parsed.netloc}"

        cfg = cls(
            port=argv_port if argv_port else _env_int("ZK_PORT", 8081),
            bind=os.environ.get("ZK_BIND", "0.0.0.0"),
            auth_token=os.environ.get("ZK_AUTH_TOKEN", ""),
            # The terminal sends naive local time. Without this we cannot say
            # what instant a punch refers to, so there is no safe default.
            device_tz=os.environ.get("ZK_DEVICE_TZ", ""),
            directory_file=os.environ.get("ZK_DIRECTORY_FILE", "").strip(),
            log_level=os.environ.get("ZK_LOG_LEVEL", "INFO").upper(),
            log_file=os.environ.get("ZK_LOG_FILE", ""),
            redact_pins=_env_bool("ZK_REDACT_PINS", False),
            sinks=sinks,
            infino_url=infino_url,
            infino_database=database,
            infino_table=os.environ.get("ZK_INFINO_TABLE", "attendance"),
            infino_arrivals_table=os.environ.get("ZK_INFINO_ARRIVALS_TABLE",
                                                 "arrivals"),
            infino_users_table=os.environ.get("ZK_INFINO_USERS_TABLE",
                                              "device_users"),
            # INFINO_API_KEY is the name Infino's own SDKs read, so accept it.
            infino_api_key=(os.environ.get("ZK_INFINO_API_KEY", "")
                            or os.environ.get("INFINO_API_KEY", "")),
            infino_timeout=_env_float("ZK_INFINO_TIMEOUT", 15.0),
            infino_bootstrap=_env_bool("ZK_INFINO_BOOTSTRAP", True),
            infino_batch_rows=_env_int("ZK_INFINO_BATCH_ROWS", 500),
            # Infino caps a data-plane request body at 5 MiB and suggests
            # aiming at 4 MiB to leave room for re-encoding. We are far below
            # either; this only matters when draining a long backlog.
            infino_batch_bytes=_env_int("ZK_INFINO_BATCH_BYTES", 3 * 1024 * 1024),
            max_attempts=_env_int("ZK_MAX_ATTEMPTS", 12),
            retry_base_secs=_env_float("ZK_RETRY_BASE_SECS", 5.0),
            retry_cap_secs=_env_float("ZK_RETRY_CAP_SECS", 900.0),
            worker_poll_secs=_env_float("ZK_WORKER_POLL_SECS", 2.0),
            max_body_bytes=_env_int("ZK_MAX_BODY_BYTES", 4 * 1024 * 1024),
            allowed_serials=frozenset(serials),
            debug_endpoints=_env_bool("ZK_DEBUG_ENDPOINTS", False),
            silence_secs=_env_int("ZK_SILENCE_SECS", 300),
        )
        cfg.validate()
        return cfg

    def validate(self):
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"ZK_PORT={self.port} is out of range")
        if not self.device_tz:
            raise ConfigError(
                "ZK_DEVICE_TZ is required. The terminal reports naive local "
                "time, so we need its zone to store an unambiguous instant "
                '(e.g. ZK_DEVICE_TZ="Asia/Kolkata").')
        try:
            ZoneInfo(self.device_tz)
        except (ZoneInfoNotFoundError, ValueError):
            raise ConfigError(
                f"ZK_DEVICE_TZ={self.device_tz!r} is not a known IANA zone")
        if not self.auth_token:
            # Not fatal: the device leg still works and is the critical path.
            # The operator endpoints refuse to serve, which is the safe default.
            LOG.warning("ZK_AUTH_TOKEN is not set — operator endpoints "
                        "(/open, /status, /punches) are DISABLED")
        elif len(self.auth_token) < 16:
            raise ConfigError("ZK_AUTH_TOKEN is shorter than 16 characters; "
                              "generate one with secrets.token_urlsafe(24)")
        if os.environ.get("ZK_DB_PATH", "").strip():
            LOG.warning("ZK_DB_PATH is set but ignored — there is no local "
                        "database any more; attendance lives only in Infino.")
        if not self.directory_file:
            LOG.warning("ZK_DIRECTORY_FILE is not set — an arrival will be "
                        "logged by user ID only, with no name, Slack or GitHub. "
                        "Copy directory.example.json and point at it.")
        unknown = set(self.sinks) - KNOWN_SINKS
        if unknown:
            raise ConfigError(f"ZK_SINKS contains unknown sink(s): "
                              f"{', '.join(sorted(unknown))}. Known: "
                              f"{', '.join(sorted(KNOWN_SINKS))}")
        if not self.sinks:
            raise ConfigError("ZK_SINKS is empty; use 'log' to store punches "
                              "without forwarding them")
        # Both Infino sinks share one account, database and key — they differ
        # only in which table they append to.
        cloud = sorted(s for s in self.sinks if s.startswith("infino"))
        if cloud:
            named = " and ".join(f"'{s}'" for s in cloud)
            parsed = urlparse(self.infino_url)
            if parsed.scheme not in ("http", "https"):
                raise ConfigError(f"ZK_INFINO_URL must be http(s), got "
                                  f"{parsed.scheme!r}")
            # Mirrors Infino's own rule: plain HTTP is for local development
            # only, so an API key is never sent in the clear.
            local = (parsed.hostname or "") in ("localhost", "127.0.0.1", "::1")
            if parsed.scheme == "http" and not local:
                raise ConfigError(
                    "ZK_INFINO_URL is plain HTTP against a remote host. Infino "
                    "rejects this at connection time, and attendance data is "
                    "personal data — use HTTPS.")
            if not self.infino_database:
                raise ConfigError(
                    f"ZK_SINKS includes {named} but no database is set. Use "
                    "ZK_INFINO_DATABASE=my-app, or put it in the URL as "
                    "ZK_INFINO_URL=https://api.platform.infino.ws/my-app")
            if not self.infino_api_key:
                raise ConfigError(
                    f"ZK_SINKS includes {named} but no API key is set. Create "
                    "one at https://platform.infino.ws and set "
                    "ZK_INFINO_API_KEY (or INFINO_API_KEY).")
            if self.infino_table == self.infino_arrivals_table:
                raise ConfigError(
                    "ZK_INFINO_TABLE and ZK_INFINO_ARRIVALS_TABLE are both "
                    f"{self.infino_table!r}. They hold different columns, so "
                    "appending both to one table would be rejected.")
            if not self.infino_api_key.startswith("inf_"):
                LOG.warning("the Infino API key does not start with 'inf_' — "
                            "check you copied a key and not something else")
            if self.infino_batch_rows < 1:
                raise ConfigError("ZK_INFINO_BATCH_ROWS must be at least 1")
            if self.infino_batch_bytes > 5 * 1024 * 1024:
                raise ConfigError("ZK_INFINO_BATCH_BYTES exceeds Infino's "
                                  "5 MiB request cap")
        if self.max_attempts < 1:
            raise ConfigError("ZK_MAX_ATTEMPTS must be at least 1")
        if self.max_body_bytes < 4096:
            raise ConfigError("ZK_MAX_BODY_BYTES is implausibly small")


def setup_logging(cfg):
    level = getattr(logging, cfg.log_level, None)
    if not isinstance(level, int):
        raise ConfigError(f"ZK_LOG_LEVEL={cfg.log_level!r} is not a level")
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger("essl")
    root.setLevel(level)
    # We own our handlers; don't also emit through whatever the root logger has.
    root.propagate = False
    for h in list(root.handlers):
        root.removeHandler(h)
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    root.addHandler(stream)
    if cfg.log_file:
        os.makedirs(os.path.dirname(os.path.abspath(cfg.log_file)) or ".",
                    exist_ok=True)
        rot = logging.handlers.RotatingFileHandler(
            cfg.log_file, maxBytes=16 * 1024 * 1024, backupCount=5)
        rot.setFormatter(fmt)
        root.addHandler(rot)


# --------------------------------------------------------------------------
# Punch model
# --------------------------------------------------------------------------

def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Punch:
    serial: str
    # The device's User ID for the person — what the terminal calls PIN on the
    # wire and shows as "User ID" when enrolling. Not a secret: the password is
    # a separate field we deliberately never keep.
    user_id: str
    punched_local: str          # exactly what the device sent
    punched_utc: str            # "" when the timestamp was unparseable
    local_date: str             # device-local calendar day, for daily triggers
    status: int
    verify: int
    workcode: str
    raw: str
    received_utc: str

    @property
    def dedup_key(self):
        """
        Stable identity for one physical punch.

        The device re-sends batches it thinks failed, so the same record can
        arrive many times. Serial + user ID + device-local timestamp + status
        is the natural key: a person cannot produce two distinct punches of the
        same type at the same second on the same terminal.
        """
        material = (f"{self.serial}|{self.user_id}|{self.punched_local}"
                    f"|{self.status}")
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    @property
    def direction(self):
        return PUNCH_STATUS.get(self.status, f"unknown_{self.status}")

    def payload(self, tz_name):
        """
        One row, matching INFINO_TABLE_SCHEMA exactly.

        Infino's append rejects columns the table doesn't declare, so this dict
        and that schema have to move together. `schema_version` is carried as a
        column so a later shape change is queryable rather than silent.
        """
        return {
            "schema_version": PAYLOAD_SCHEMA,
            "event_id": self.dedup_key,
            "device_serial": self.serial,
            "employee_user_id": self.user_id,
            "punched_at": self.punched_utc or None,
            "punched_at_local": self.punched_local,
            "local_date": self.local_date,
            "timezone": tz_name,
            "direction": self.direction,
            "status_code": self.status,
            "verify_method": VERIFY_METHOD.get(self.verify,
                                               f"unknown_{self.verify}"),
            "verify_code": self.verify,
            "workcode": self.workcode,
            "received_at": self.received_utc,
            "source": USER_AGENT,
        }


# Filter values that reach a SQL string. Infino's query API takes SQL text
# with no bind parameters, so anything user-supplied is screened against this
# first and quoted second — the value is rejected outright rather than escaped
# into something clever.
_SAFE_FILTER_RE = re.compile(r"[A-Za-z0-9_\-]{1,64}")


def _sql_text(value):
    """A single-quoted SQL literal, with embedded quotes doubled."""
    return "'" + str(value).replace("'", "''") + "'"


def _minutes_between(first_local, last_local):
    """
    Whole minutes between two "YYYY-MM-DD HH:MM:SS" device-local stamps.

    Done here rather than in SQL: DataFusion would need a cast to timestamp
    and an interval, and the arithmetic is not worth a dialect dependency.
    Returns None if either end is missing or unparseable.
    """
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        start = datetime.datetime.strptime(first_local, fmt)
        end = datetime.datetime.strptime(last_local, fmt)
    except (TypeError, ValueError):
        return None
    return max(0, int((end - start).total_seconds() // 60))


def arrival_payload(punch, person, tz_name):
    """
    One row, matching INFINO_ARRIVALS_SCHEMA exactly.

    Identity is copied onto the row rather than referenced, so it records who
    someone was when they arrived and stays true after they change their Slack
    handle. (Infino does have `/v1/update`, so a dimension table *could* be
    maintained — the reason to denormalise is that a point-in-time record is
    the more correct answer here, not that updating is impossible.)
    `event_id` is the punch's dedup key, so this joins to the attendance row
    it came from.

    `person` is None when the user ID is not in the directory. The arrival
    still gets a row: someone did walk in, and "arrivals we cannot name" is a
    more useful thing to be able to query than silence.
    """
    return {
        "schema_version": ARRIVAL_SCHEMA,
        "event_id": punch.dedup_key,
        "device_serial": punch.serial,
        "employee_user_id": punch.user_id,
        "person_name": (person.name or None) if person else None,
        "slack_id": (person.slack or None) if person else None,
        "github_id": (person.github or None) if person else None,
        "identity_source": "directory" if person else "unmapped",
        "arrived_at": punch.punched_utc or None,
        "arrived_at_local": punch.punched_local,
        "local_date": punch.local_date,
        "timezone": tz_name,
        "direction": punch.direction,
        "status_code": punch.status,
        "verify_method": VERIFY_METHOD.get(punch.verify,
                                           f"unknown_{punch.verify}"),
        "received_at": punch.received_utc,
        "source": USER_AGENT,
    }


def device_user_payload(serial, fields):
    """
    One roster row, matching INFINO_USERS_SCHEMA exactly.

    `Passwd` is a credential that opens a door, so only whether one is set is
    recorded — the value itself never leaves the parser.
    """
    def _int(name):
        try:
            return int(fields[name])
        except (KeyError, TypeError, ValueError):
            return None

    password = fields.get("Passwd") or fields.get("PW") or ""
    privilege = _int("Pri")
    return {
        "device_serial": serial,
        "employee_user_id": fields["PIN"],
        "person_name": fields.get("Name") or None,
        "privilege": privilege,
        "privilege_label": PRIVILEGE.get(privilege, f"unknown_{privilege}"),
        "card": fields.get("Card") or None,
        "group_id": fields.get("Grp") or None,
        "timezones": fields.get("TZ") or None,
        "has_password": 1 if password.strip() else 0,
        "synced_at": _iso(_utcnow()),
        "source": USER_AGENT,
    }


def parse_attlog_line(line, serial, tz, received_utc):
    """
    Parse one ATTLOG record into a Punch, or return None if it isn't one.

    Canonical form is tab-separated:
        PIN <TAB> YYYY-MM-DD HH:MM:SS <TAB> status <TAB> verify <TAB> workcode
    with trailing reserved columns we ignore. `PIN` is the wire name for what
    the device calls a User ID, and is carried as `user_id` from here on.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    if "\t" in line:
        cols = [c.strip() for c in line.split("\t")]
        pin = cols[0] if cols else ""
        ts = cols[1] if len(cols) > 1 else ""
        status_s = cols[2] if len(cols) > 2 else "0"
        verify_s = cols[3] if len(cols) > 3 else "0"
        workcode = cols[4] if len(cols) > 4 else "0"
    else:
        m = _ATTLOG_RE.match(line)
        if not m:
            return None
        pin = m.group("pin")
        ts = m.group("ts")
        status_s = m.group("status") or "0"
        verify_s = m.group("verify") or "0"
        workcode = m.group("workcode") or "0"

    if not pin or not ts:
        return None

    punched_utc, local_date = "", ""
    try:
        naive = datetime.datetime.strptime(ts.replace("T", " "),
                                           "%Y-%m-%d %H:%M:%S")
        local = naive.replace(tzinfo=tz)
        punched_utc = _iso(local)
        local_date = naive.date().isoformat()
    except ValueError:
        # Keep the record rather than dropping it: an unparseable timestamp is
        # a data-quality problem to investigate, not a reason to lose a punch.
        LOG.error("unparseable ATTLOG timestamp %r from SN=%s", ts, serial)

    def _int(s):
        try:
            return int(s)
        except (TypeError, ValueError):
            return -1

    return Punch(
        serial=serial,
        user_id=pin,
        punched_local=ts.replace("T", " "),
        punched_utc=punched_utc,
        local_date=local_date,
        status=_int(status_s),
        verify=_int(verify_s),
        workcode=workcode or "0",
        raw=line[:512],
        received_utc=received_utc,
    )


def parse_kv_record(payload):
    """
    Parse a `Key=value` device record into a dict.

    Canonical form is tab-separated. Firmware that pads with spaces instead
    defeats a naive split, because a value — a person's name — may itself
    contain spaces. In that case we locate the keys and take everything
    between one key and the next as the value.
    """
    out = {}
    if "\t" in payload:
        for field in payload.split("\t"):
            key, sep, value = field.partition("=")
            if sep and key.strip():
                out[key.strip()] = value.strip()
        return out
    marks = list(_KV_KEY_RE.finditer(payload))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(payload)
        out[m.group(1)] = payload[m.end():end].strip()
    return out


def parse_user_line(line):
    """
    Parse one USER record into its fields, or return None if the line isn't
    one. FP / FACE / BIODATA lines from the same dump return None: their
    payload is a biometric template we have no use for and no reason to hold.
    """
    m = _USER_PREFIX_RE.match(line)
    if not m:
        return None
    fields = parse_kv_record(line[m.end():])
    pin = (fields.get("PIN") or fields.get("Pin") or "").strip()
    if not pin:
        return None
    fields["PIN"] = pin
    return fields


def scrub_secrets(text):
    """
    Replace biometric templates and terminal passwords with a marker.

    Asking the device for its user list means USER / FP / FACE / BIODATA
    bodies now flow through the log and the `uploads` table. The templates in
    them are biometric data with no use anywhere in this system, and `Passwd`
    is a credential that opens a door — neither belongs in anything durable.
    Callers hand the *unscrubbed* body to the parser, which keeps only the
    fact that a password is set.
    """
    return _SECRET_VALUE_RE.sub(r"\1<redacted>", text)


# --------------------------------------------------------------------------
# Identity directory
# --------------------------------------------------------------------------

# Field aliases accepted in the directory file. `slack` and `github` are the
# canonical names; the rest are what people actually type. Both lists are
# generated from one set of suffixes rather than written out, because two
# hand-maintained lists drift — `github_id` was once missing while `slack_id`
# was present, so a file using both got a GitHub handle silently dropped.
_ACCOUNT_SUFFIXES = ("", "_id", "_user_id", "_login", "_username", "_handle")
_SLACK_KEYS = tuple("slack" + suffix for suffix in _ACCOUNT_SUFFIXES)
_GITHUB_KEYS = tuple("github" + suffix for suffix in _ACCOUNT_SUFFIXES)


@dataclass(frozen=True)
class Person:
    user_id: str
    name: str
    slack: str          # "" when not known — a person may have no account
    github: str


def _text(value):
    """
    A JSON value as a trimmed string, or "" if there isn't one.

    JSON null must not become the string "None" — that reads as a real name
    and defeats every "is this set?" check downstream. Booleans are excluded
    for the same reason.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()


def _first_value(body, keys):
    """First non-empty value among `keys`, matched case-insensitively."""
    lowered = {str(k).lower(): v for k, v in body.items()}
    for key in keys:
        text = _text(lowered.get(key))
        if text:
            return text
    return ""


# A Slack member ID: U or W, then uppercase alphanumerics. Worth screening for
# because a display name in this field looks perfectly fine in a log line and
# only fails much later, when chat.postMessage cannot resolve it.
_SLACK_ID_RE = re.compile(r"^[UW][A-Z0-9]{6,}$")


def _stray_key(body, prefix, keys):
    """
    A key that was plainly meant to be `prefix` but isn't one we read.

    Only consulted when the field came out empty, which makes it precise: it
    answers "you wrote something github-shaped and got nothing, here is why"
    rather than complaining about extra fields someone keeps for their own use.
    """
    for key in body:
        low = str(key).lower()
        if low.startswith(prefix) and low not in keys:
            return str(key)
    return None


class Directory:
    """
    User ID -> person, read from a JSON file maintained by hand.

    The file is built from the /users dump: the terminal knows a User ID and a
    name, and this adds the Slack and GitHub handles it cannot know. A plain
    file is the right home for it — it is edited by a human, reviewed in a
    diff, and small. ROADMAP M4.5 moves it to Infino behind this same
    interface, which is why callers only ever see `get()`.

    Two shapes are accepted, because both are natural to write:

        {"7": {"name": "Asha Rao", "slack": "U0123ABC", "github": "asha"}}
        [{"user_id": "7", "name": "Asha Rao", "slack": "U0123ABC", ...}]

    Errors name the offending entry. A typo in a fifty-person file is only
    findable if the message says which line to look at.
    """

    def __init__(self, path=""):
        self.path = path
        self._people = {}

    def __len__(self):
        return len(self._people)

    def get(self, user_id):
        return self._people.get(str(user_id).strip())

    def load(self):
        """
        Read and validate the file, replacing what is held. Raises ConfigError
        so a bad file fails at startup — and under --check-config — rather
        than at 9am on the first punch of the day.

        The parse builds a whole new dict before publishing it, so a failed
        reload leaves the previous contents intact.
        """
        if not self.path:
            self._people = {}
            return self
        try:
            with open(self.path, "r", encoding="utf-8-sig") as fh:
                raw = json.load(fh)
        except OSError as e:
            raise ConfigError(
                f"cannot read ZK_DIRECTORY_FILE {self.path}: {e.strerror}")
        except ValueError as e:
            raise ConfigError(f"{self.path} is not valid JSON: {e}")

        if isinstance(raw, dict):
            # JSON has no comment syntax, and this file is maintained by hand
            # by whoever owns the mapping. An "_"-prefixed key is a note to
            # them, not a person.
            entries = [(str(uid), body) for uid, body in raw.items()
                       if not str(uid).startswith("_")]
        elif isinstance(raw, list):
            entries = [(None, body) for body in raw]
        else:
            raise ConfigError(
                f"{self.path}: expected a JSON object keyed by user ID, or a "
                f"list of entries, but the file holds a {type(raw).__name__}")

        people = {}
        nameless, odd_slack = [], []
        for i, (user_id, body) in enumerate(entries, 1):
            where = (f"{self.path}: user ID {user_id}" if user_id
                     else f"{self.path}: entry {i}")
            if not isinstance(body, dict):
                raise ConfigError(f"{where}: expected an object with name, "
                                  f"slack and github, got a "
                                  f"{type(body).__name__}")
            # "pin" is the terminal's wire name for this value, so it is an
            # easy thing to type here. Say so rather than reporting a missing
            # user_id and leaving the author to guess which name won.
            if not user_id and "pin" in body and "user_id" not in body:
                raise ConfigError(
                    f'{where}: use "user_id", not "pin". The device sends it '
                    f'as PIN on the wire, but it is the User ID shown when '
                    f'enrolling — this file uses that name throughout.')
            user_id = (user_id or _text(body.get("user_id"))).strip()
            if not user_id:
                raise ConfigError(f"{where}: no user ID. Either key each entry "
                                  f'by the device user ID, or give it a '
                                  f'"user_id" field.')
            if user_id in people:
                raise ConfigError(
                    f"{self.path}: user ID {user_id} appears twice")
            name = _text(body.get("name"))
            if not name:
                # Not fatal. The terminal itself has no name for some users
                # (admin and test accounts), so a directory built from /users
                # inherits the gap — and losing attendance over a missing
                # greeting name would be the wrong trade (ROADMAP M4.3).
                nameless.append(user_id)
            slack = _first_value(body, _SLACK_KEYS)
            github = _first_value(body, _GITHUB_KEYS)
            # An unreadable account field is otherwise silent — it just prints
            # as "-", which looks like "this person has no GitHub" rather than
            # "you spelled the key differently than I read it".
            for label, value, keys in (("slack", slack, _SLACK_KEYS),
                                       ("github", github, _GITHUB_KEYS)):
                stray = _stray_key(body, label, keys) if not value else None
                if stray:
                    LOG.warning(
                        "%s: user ID %s has %r, which is not a field this "
                        "reads, so %s will print as '-'. Accepted: %s",
                        self.path, user_id, stray, label, ", ".join(keys[:3]))
            if slack and not _SLACK_ID_RE.match(slack):
                odd_slack.append(user_id)
            people[user_id] = Person(user_id=user_id, name=name,
                                     slack=slack, github=github)

        # Reported together, after the whole file is read: fixing a directory
        # one restart per problem is miserable when several entries need it.
        if nameless:
            LOG.warning("%s: %d entr%s have no name (user ID%s %s). They will "
                        "be announced by user ID — the terminal has no name "
                        "for them either, so these have to be filled in by "
                        "hand.", self.path, len(nameless),
                        "y" if len(nameless) == 1 else "ies",
                        "" if len(nameless) == 1 else "s", ", ".join(nameless))
        if odd_slack:
            one = len(odd_slack) == 1
            LOG.warning("%s: user ID%s %s %s a slack value that is not a "
                        "member ID (U… or W…). A display name reads fine here "
                        "but cannot be messaged — copy the ID from Slack "
                        "under Profile -> More -> Copy member ID.",
                        self.path, "" if one else "s", ", ".join(odd_slack),
                        "has" if one else "have")
        self._people = people
        return self


# --------------------------------------------------------------------------
# Infino — the only place attendance is stored
# --------------------------------------------------------------------------
#
# There is no local database. A punch is acknowledged to the terminal only
# once Infino has accepted it, which makes the device's own buffer the retry
# mechanism: refuse the upload and it keeps the records and offers them again.
# The trade is deliberate — no attendance data at rest on this machine, at the
# cost of the device's poll loop depending on the cloud being reachable.

# The attendance table as Infino holds it. Kept beside Punch.payload(), which
# must produce exactly these column names.
INFINO_TABLE_SCHEMA = [
    {"name": "event_id", "type": "large_utf8", "nullable": False},
    {"name": "schema_version", "type": "large_utf8"},
    {"name": "device_serial", "type": "large_utf8"},
    {"name": "employee_user_id", "type": "large_utf8"},
    {"name": "punched_at", "type": "large_utf8"},
    {"name": "punched_at_local", "type": "large_utf8"},
    {"name": "local_date", "type": "large_utf8"},
    {"name": "timezone", "type": "large_utf8"},
    {"name": "direction", "type": "large_utf8"},
    {"name": "status_code", "type": "i32"},
    {"name": "verify_method", "type": "large_utf8"},
    {"name": "verify_code", "type": "i32"},
    {"name": "workcode", "type": "large_utf8"},
    {"name": "received_at", "type": "large_utf8"},
    {"name": "source", "type": "large_utf8"},
]

# One row per person per day: the first time they were seen. This table is
# also the greeting ledger — its existence for (user, day) is what says
# "already greeted", so it must be written exactly when a greeting is issued.
INFINO_ARRIVALS_SCHEMA = [
    {"name": "event_id", "type": "large_utf8", "nullable": False},
    {"name": "schema_version", "type": "large_utf8"},
    {"name": "device_serial", "type": "large_utf8"},
    {"name": "employee_user_id", "type": "large_utf8"},
    {"name": "person_name", "type": "large_utf8"},
    {"name": "slack_id", "type": "large_utf8"},
    {"name": "github_id", "type": "large_utf8"},
    {"name": "identity_source", "type": "large_utf8"},
    {"name": "arrived_at", "type": "large_utf8"},
    {"name": "arrived_at_local", "type": "large_utf8"},
    {"name": "local_date", "type": "large_utf8"},
    {"name": "timezone", "type": "large_utf8"},
    {"name": "direction", "type": "large_utf8"},
    {"name": "status_code", "type": "i32"},
    {"name": "verify_method", "type": "large_utf8"},
    {"name": "received_at", "type": "large_utf8"},
    {"name": "source", "type": "large_utf8"},
]

# The terminal's roster, captured by the one-off /users/sync. Append-only, so
# a re-sync adds rows and the newest `synced_at` per (serial, user_id) wins.
INFINO_USERS_SCHEMA = [
    {"name": "device_serial", "type": "large_utf8", "nullable": False},
    {"name": "employee_user_id", "type": "large_utf8", "nullable": False},
    {"name": "person_name", "type": "large_utf8"},
    {"name": "privilege", "type": "i32"},
    {"name": "privilege_label", "type": "large_utf8"},
    {"name": "card", "type": "large_utf8"},
    {"name": "group_id", "type": "large_utf8"},
    {"name": "timezones", "type": "large_utf8"},
    {"name": "has_password", "type": "i32"},
    {"name": "synced_at", "type": "large_utf8"},
    {"name": "source", "type": "large_utf8"},
]


class InfinoError(Exception):
    """
    A call to Infino failed.

    `permanent` distinguishes "this request will never work" (a malformed row,
    a schema mismatch) from "try again" (network, timeout, cold start). With
    no outbox, that distinction decides whether the terminal is told to keep
    the record or the record is dropped.
    """

    def __init__(self, message, status=502, permanent=False, retry_after=0.0):
        super().__init__(message)
        self.status = status
        self.permanent = permanent
        self.retry_after = retry_after


class InfinoClient:
    """
    Both halves of Infino: `/v1/append/{db}` to write, `/v1/query_sql/{db}` to
    read, plus the bootstrap that creates the database and tables.

    Reads come back as a plain JSON array of row objects when we ask for
    `Accept: application/json` — the default is an Arrow IPC stream, which
    would mean a pyarrow dependency to read our own attendance. A NULL column
    is *omitted* from the row object rather than returned as null, so callers
    use .get() throughout.

    Appends are eventually consistent: measured at roughly half a second
    before a written row is visible to a query. Anything that needs to know
    "did I just write this?" cannot rely on a read (see GreetingGuard).
    """

    def __init__(self, cfg):
        self.base = cfg.infino_url
        self.database = cfg.infino_database
        self.api_key = cfg.infino_api_key
        self.timeout = cfg.infino_timeout
        self.autocreate = cfg.infino_bootstrap
        self.batch_rows = cfg.infino_batch_rows
        self._bootstrapped = set()
        self._lock = threading.Lock()

    @property
    def configured(self):
        return bool(self.database and self.api_key)

    # ---- HTTP ----------------------------------------------------------
    def _request(self, path, body, params=None, accept_json=False):
        url = f"{self.base}{path}"
        if params:
            url += "?" + urlencode(params)
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("User-Agent", USER_AGENT)
        if accept_json:
            req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.status, resp.read()

    @staticmethod
    def _describe(err):
        """Pull Infino's ErrorBody message out of a failed response."""
        try:
            detail = err.read(500).decode("utf-8", "replace")
        except Exception:
            return f"HTTP {err.code}"
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict) and "error" in parsed:
                detail = str(parsed["error"])
        except ValueError:
            pass
        return f"HTTP {err.code}: {detail.strip()[:300]}"

    def _call(self, path, body, params=None, accept_json=False):
        """Translate every failure mode into one InfinoError."""
        if not self.configured:
            raise InfinoError(
                "Infino is not configured: set ZK_INFINO_DATABASE and "
                "ZK_INFINO_API_KEY. Attendance is stored only in Infino, so "
                "there is nowhere for a punch to go without them.", 503)
        try:
            return self._request(path, body, params, accept_json)
        except urllib.error.HTTPError as e:
            desc = self._describe(e)
            if e.code == 404:
                # Database or table missing — recoverable once re-created.
                with self._lock:
                    self._bootstrapped.clear()
                raise InfinoError(desc, 502)
            if e.code == 401:
                raise InfinoError(f"Infino rejected the API key ({desc})", 502)
            if e.code == 503:
                try:
                    wait = float(e.headers.get("Retry-After", 0) or 0)
                except (TypeError, ValueError):
                    wait = 0.0
                raise InfinoError(f"Infino is starting up ({desc})", 503,
                                  retry_after=wait)
            permanent = 400 <= e.code < 500 and e.code not in (408, 429)
            raise InfinoError(desc, 502, permanent=permanent)
        except urllib.error.URLError as e:
            raise InfinoError(f"cannot reach Infino: {e.reason}", 502)
        except TimeoutError:
            raise InfinoError("Infino timed out", 504)

    # ---- bootstrap -----------------------------------------------------
    def ensure_ready(self, tables):
        """
        Create the database and the given {table: schema} if absent.

        Idempotent: 409 means someone got there first, which is success. Safe
        to call on every append — the work is skipped once a table is known
        good, and a 404 clears that memory so the next call rebuilds.
        """
        if not self.autocreate or not self.configured:
            return
        with self._lock:
            missing = {t: s for t, s in tables.items()
                       if t not in self._bootstrapped}
        if not missing:
            return
        try:
            self._call("/v1/databases", {"name": self.database})
            LOG.info("created Infino database %r", self.database)
        except InfinoError as e:
            if "409" not in str(e):
                LOG.debug("database create returned: %s", e)
        for table, schema in missing.items():
            try:
                self._call(f"/v1/create_table/{self.database}",
                           {"table_name": table, "schema": schema})
                LOG.info("created Infino table %r in %r", table, self.database)
            except InfinoError as e:
                if "409" not in str(e):
                    LOG.debug("table %s create returned: %s", table, e)
            with self._lock:
                self._bootstrapped.add(table)

    # ---- write ---------------------------------------------------------
    def append(self, table, rows):
        """
        Append rows to a table. One append is one atomic commit, so the batch
        succeeds or fails together. Raises InfinoError.
        """
        if not rows:
            return 0
        for batch in _chunked(rows, self.batch_rows):
            status, _ = self._call(f"/v1/append/{self.database}",
                                   {"data": batch}, {"table": table})
            if not 200 <= status < 300:
                raise InfinoError(f"unexpected status {status} appending to "
                                  f"{table}")
        return len(rows)

    # ---- read ----------------------------------------------------------
    def rows(self, sql):
        """Run a read-only query and return a list of row dicts."""
        _status, body = self._call(f"/v1/query_sql/{self.database}",
                                   {"query": sql}, accept_json=True)
        try:
            parsed = json.loads(body)
        except ValueError:
            raise InfinoError("Infino returned a non-JSON body", 502)
        if not isinstance(parsed, list):
            raise InfinoError(
                f"expected a JSON array of rows, got {type(parsed).__name__}",
                502)
        return parsed


def _chunked(rows, size):
    for i in range(0, len(rows), max(1, size)):
        yield rows[i:i + size]


class Publisher:
    """
    Sends rows to their destination, synchronously, on the request thread.

    `ZK_SINKS` decides where each kind goes: 'infino'/'infino_arrivals' append
    to the cloud, 'log'/'log_arrivals' only print — the dry run that needs no
    account. A row can go to both.

    Transient failures propagate, so the caller can refuse to acknowledge the
    upload and let the terminal keep the records. A row Infino permanently
    rejects is logged in full at ERROR and dropped: with no queue to park it
    in, the alternative is refusing the batch forever and blocking every punch
    behind it.
    """

    def __init__(self, cfg, client):
        self.cfg = cfg
        self.client = client
        self.dropped = 0
        self.appended = 0

    def _emit(self, cloud_sink, log_sink, table, rows, kind):
        if not rows:
            return
        if log_sink in self.cfg.sinks:
            for row in rows:
                LOG.info("[%s] %s", log_sink,
                         json.dumps(row, separators=(",", ":")))
        if cloud_sink not in self.cfg.sinks:
            return
        try:
            self.client.append(table, rows)
            self.appended += len(rows)
        except InfinoError as e:
            if not e.permanent:
                raise
            if len(rows) > 1:
                # The batch is atomic, so a rejection says nothing about which
                # row was at fault. Re-send singly to isolate the bad one.
                LOG.warning("Infino rejected a batch of %d %s rows (%s); "
                            "retrying individually to isolate it",
                            len(rows), kind, e)
                for row in rows:
                    self._emit(cloud_sink, log_sink, table, [row], kind)
                return
            self.dropped += 1
            LOG.error("DROPPED %s row, Infino rejected it permanently (%s): %s",
                      kind, e, json.dumps(rows[0], separators=(",", ":")))

    def publish_attendance(self, rows):
        self._emit("infino", "log", self.cfg.infino_table, rows, "attendance")

    def publish_arrivals(self, rows):
        self._emit("infino_arrivals", "log_arrivals",
                   self.cfg.infino_arrivals_table, rows, "arrival")

    def publish_users(self, rows):
        self._emit("infino", "log", self.cfg.infino_users_table, rows, "user")


class GreetingGuard:
    """
    Has this person already been greeted today?

    The durable answer is the arrivals table itself: one row per person per
    day means "a row exists" *is* "already greeted", and it survives a restart
    or a device re-upload without any local state.

    A short-lived local set sits in front of it, because a query cannot answer
    the one case that matters most here: an append takes roughly half a second
    to become visible, and this terminal reports the same face twice one
    second apart. The set closes that window; Infino closes the long ones.

    Checking and marking are one locked operation, so two concurrent uploads
    for the same person cannot both decide they are first.
    """

    def __init__(self, client, table, keep_days=7):
        self.client = client
        self.table = table
        self.keep_days = keep_days
        self._lock = threading.Lock()
        self._seen = {}                 # local_date -> {user_id, ...}

    def _remember(self, user_id, local_date):
        day = self._seen.setdefault(local_date, set())
        day.add(user_id)
        # Bound the memory: only recent days can still be asked about.
        for stale in sorted(self._seen)[:-self.keep_days]:
            del self._seen[stale]

    def claim(self, user_id, local_date):
        """
        True if this greeting is ours to send, and records it as sent.
        False if the person has already been greeted today.

        Raises InfinoError if the ledger cannot be read — failing closed, so
        an unreachable cloud never causes a duplicate greeting.
        """
        with self._lock:
            if user_id in self._seen.get(local_date, ()):
                return False
        rows = self.client.rows(
            f"SELECT 1 AS hit FROM {self.table} "
            f"WHERE employee_user_id = {_sql_text(user_id)} "
            f"  AND local_date = {_sql_text(local_date)} LIMIT 1")
        with self._lock:
            if user_id in self._seen.get(local_date, ()):
                return False            # another thread got there first
            self._remember(user_id, local_date)
            return not rows

    def release(self, user_id, local_date):
        """Undo a claim whose append then failed, so a retry can greet."""
        with self._lock:
            self._seen.get(local_date, set()).discard(user_id)


# --------------------------------------------------------------------------
# Device command queue
# --------------------------------------------------------------------------

class CommandQueue:
    """
    Per-serial FIFO of commands awaiting the device's next poll.

    Deliberately in-memory: a queued door-open that survived a restart and
    fired minutes later would be a safety surprise, not a feature.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._queues = {}
        self._next_id = 0

    def enqueue(self, serial, command_body):
        with self._lock:
            self._next_id += 1
            cmd = f"C:{self._next_id}:{command_body}"
            self._queues.setdefault(serial, []).append(cmd)
        LOG.info("queued for SN=%s: %s", serial, cmd)
        return cmd

    def pop(self, serial):
        with self._lock:
            q = self._queues.get(serial)
            return q.pop(0) if q else None

    def snapshot(self):
        with self._lock:
            return {sn: list(cmds) for sn, cmds in self._queues.items() if cmds}


class DeviceRegistry:
    """Tracks which terminals are talking to us and when they last did."""

    def __init__(self):
        self._lock = threading.Lock()
        self._last_seen = {}        # serial -> monotonic
        self._last_serial = None

    def note(self, serial):
        now = time.monotonic()
        with self._lock:
            prev = self._last_seen.get(serial)
            self._last_seen[serial] = now
            self._last_serial = serial
        return None if prev is None else now - prev

    def silent_for(self):
        now = time.monotonic()
        with self._lock:
            return {sn: now - t for sn, t in self._last_seen.items()}

    def resolve(self, requested=None):
        """
        Pick the device an operator command targets. An explicit ?sn= wins;
        otherwise fall back to the only known device. With more than one
        terminal we refuse to guess rather than unlock the wrong door.
        """
        with self._lock:
            if requested:
                return (requested, None) if requested in self._last_seen else \
                    (None, f"no device with serial {requested} has checked in")
            if not self._last_seen:
                return None, ("no device has checked in yet; wait for a poll "
                              "to appear in the log")
            if len(self._last_seen) > 1:
                return None, ("more than one device is registered (" +
                              ", ".join(sorted(self._last_seen)) +
                              "); pass ?sn=<serial>")
            return next(iter(self._last_seen)), None


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

# Ask the terminal to upload its whole user table. There is no single form
# every firmware honours — the wildcard is the most widely supported, the bare
# form is what older builds want — so both are queued and whichever produces
# USER records wins. Unrecognised commands are answered with a non-zero Return
# and are otherwise harmless.
_USERINFO_QUERIES = (
    "DATA QUERY USERINFO PIN=*",
    "DATA QUERY USERINFO",
)


def _door_payload(door, seconds, cc="01", dd="00"):
    """
    Build a CONTROL DEVICE payload per the ZK PUSH spec:
        <AA><BB><CC><DD><EE>
        AA = 01  output-control operation
        BB = door id (01-10)
        CC = 01 lock relay / 02 aux output
        DD = 00 normal / FF normal-open latch
        EE = duration in seconds (01-FE); FF = indefinite
    """
    ss = max(1, min(254, int(seconds)))
    return f"01{int(door):02X}{cc}{dd}{ss:02X}"


class Handler(BaseHTTPRequestHandler):
    # Injected by main(); class attributes keep the stdlib handler signature.
    cfg = None
    queue = None
    registry = None
    directory = None
    infino = None
    publisher = None
    greetings = None
    started_at = time.monotonic()

    protocol_version = "HTTP/1.0"    # terminals don't benefit from keep-alive
    timeout = 20                     # don't let a half-open socket hold a thread
    server_version = USER_AGENT
    sys_version = ""

    def log_message(self, fmt, *args):
        LOG.debug("%s - %s", self.client_address[0], fmt % args)

    def log_error(self, fmt, *args):
        LOG.warning("%s - %s", self.client_address[0], fmt % args)

    # ---- plumbing ------------------------------------------------------
    def _reply(self, body="OK", status=200, ctype="text/plain; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # Some firmware uses our Date header to sync its clock.
        self.send_header("Date", self.date_time_string())
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            LOG.debug("client %s went away before the reply was written",
                      self.client_address[0])

    def _reply_json(self, obj, status=200):
        self._reply(json.dumps(obj, indent=2) + "\n", status,
                    "application/json")

    def _read_body(self):
        """Read the request body, refusing anything over the configured cap."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            self._reply("bad Content-Length\n", 400)
            return None
        if length < 0:
            self._reply("bad Content-Length\n", 400)
            return None
        if length > self.cfg.max_body_bytes:
            LOG.warning("rejecting %d-byte body from %s (cap %d)",
                        length, self.client_address[0],
                        self.cfg.max_body_bytes)
            self._reply("payload too large\n", 413)
            return None
        if not length:
            return ""
        raw = self.rfile.read(length)
        return raw.decode("utf-8", errors="replace")

    def _user_id_for_log(self, user_id):
        """Hash the user ID when ZK_REDACT_PINS is on. The variable keeps its
        name for compatibility; what it redacts is the User ID."""
        if not self.cfg.redact_pins:
            return user_id
        return "user:" + hashlib.sha256(user_id.encode()).hexdigest()[:8]

    def _serial(self, q):
        """Extract and screen the device serial from the query string."""
        sn = (q.get("SN", [""])[0] or q.get("sn", [""])[0]).strip()
        if not sn:
            return None, "missing SN"
        if len(sn) > 64 or not re.fullmatch(r"[A-Za-z0-9_\-]+", sn):
            return None, "implausible SN"
        if self.cfg.allowed_serials and sn not in self.cfg.allowed_serials:
            return None, f"serial {sn} is not in ZK_ALLOWED_SERIALS"
        return sn, None

    def _authorized(self, q):
        if not self.cfg.auth_token:
            self._reply("ZK_AUTH_TOKEN is not set, so the operator endpoints "
                        "are disabled.\n", 503)
            return False
        supplied = q.get("token", [""])[0] or \
            self.headers.get("X-Auth-Token", "")
        if not secrets.compare_digest(supplied, self.cfg.auth_token):
            LOG.warning("DENIED %s from %s (bad or missing token)",
                        urlparse(self.path).path, self.client_address[0])
            self._reply("Unauthorized: pass ?token=<ZK_AUTH_TOKEN> or an "
                        "X-Auth-Token header.\n", 401)
            return False
        return True

    def _note(self, serial, event):
        gap = self.registry.note(serial)
        LOG.info("%-24s SN=%s %s", event, serial,
                 "(first contact)" if gap is None else f"(+{gap:.1f}s)")

    def _target(self, q):
        serial, err = self.registry.resolve(q.get("sn", [""])[0].strip() or None)
        if err:
            self._reply(err + "\n", 409)
            return None
        return serial

    # ---- device endpoints ----------------------------------------------
    def _handshake(self, serial):
        """
        Reply to the device's config request.

        Realtime=1 asks it to push punches as they happen rather than batching.
        Stamp / OpStamp are the protocol's high-water marks; we pin them so the
        device always offers everything it has and we rely on our own dedup key
        instead. See ROADMAP.md M2.6 for making these real.
        """
        self._note(serial, "HANDSHAKE (cdata GET)")
        cfg = (
            f"GET OPTION FROM: {serial}\r\n"
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

    def _handle_attlog(self, serial, body):
        """
        Publish an uploaded attendance batch to Infino.

        The reply must be `OK: <count>` where count is the number of records
        accepted; anything else and most firmware re-sends the whole batch on
        its next transfer. Nothing is acknowledged until Infino has the rows —
        with no local store, the terminal's own buffer *is* the retry queue,
        so a refused upload is how a punch survives a cloud outage.

        Greetings are claimed before the append and released if it fails, so a
        transient error cannot consume someone's one greeting for the day.
        """
        tz = ZoneInfo(self.cfg.device_tz)
        received = _iso(_utcnow())
        punches, malformed = [], 0
        for line in body.splitlines():
            if not line.strip():
                continue
            punch = parse_attlog_line(line, serial, tz, received)
            if punch is None:
                malformed += 1
                LOG.warning("unparseable ATTLOG line from SN=%s: %r",
                            serial, line[:200])
                continue
            punches.append(punch)

        arrivals, claimed = [], []
        try:
            for punch in punches:
                arrival = self._arrival_for(punch)
                if arrival:
                    arrivals.append(arrival)
                    claimed.append((punch.user_id, punch.local_date))
            self.publisher.publish_attendance(
                [p.payload(self.cfg.device_tz) for p in punches])
            self.publisher.publish_arrivals(arrivals)
        except InfinoError as e:
            # Hand the records back to the device rather than lose them.
            for user_id, local_date in claimed:
                self.greetings.release(user_id, local_date)
            LOG.error("refusing ATTLOG batch from SN=%s, Infino unavailable: "
                      "%s (the terminal will re-send)", serial, e)
            self._reply(f"cloud unavailable: {e}\n", 503)
            return

        for punch in punches:
            LOG.info("PUNCH %s %s %s (%s via %s)",
                     self._user_id_for_log(punch.user_id), punch.punched_local,
                     punch.punched_utc or "?", punch.direction,
                     VERIFY_METHOD.get(punch.verify, punch.verify))
        for arrival in arrivals:
            self._log_arrival(arrival)

        LOG.info("ATTLOG batch from SN=%s: %d published (%d arrival(s)), "
                 "%d malformed", serial, len(punches), len(arrivals), malformed)
        # Count everything consumed, malformed included: re-sending a line we
        # cannot parse will not make it parseable, and stalling the device on
        # it would block every later punch behind it.
        self._reply(f"OK: {len(punches) + malformed}")

    # ---- arrivals ------------------------------------------------------
    def _arrival_for(self, punch):
        """
        Decide whether this punch is someone showing up for the first time
        today, and if so build the row for it. Returns the payload, or None.

        Anything that is not explicitly a departure counts as an arrival. Many
        terminals never report a direction at all — they send status 255 — so
        requiring an explicit check-in would mean never announcing anyone.

        One decision, two consumers: the terminal line and the row written to
        Infino come from the same payload, so they cannot disagree.

        Claiming the greeting here is what makes it once per person per day
        (ROADMAP M5.1/M5.2): the arrivals table is the ledger, so a restart, a
        device re-upload, and the reader matching the same face twice all
        collapse to a single greeting.
        """
        if punch.status in DEPARTURE_STATUS:
            LOG.debug("no arrival for %s: direction is %s",
                      self._user_id_for_log(punch.user_id), punch.direction)
            return None
        if not punch.local_date:
            LOG.warning("no arrival for %s: its timestamp was unparseable, so "
                        "there is no day to key the greeting on",
                        self._user_id_for_log(punch.user_id))
            return None
        if not self.greetings.claim(punch.user_id, punch.local_date):
            LOG.debug("no arrival for %s: already greeted on %s",
                      self._user_id_for_log(punch.user_id), punch.local_date)
            return None
        return arrival_payload(punch, self.directory.get(punch.user_id),
                               self.cfg.device_tz)

    def _log_arrival(self, arrival):
        """
        Say who just walked in.

        ZK_REDACT_PINS silences this line but does not suppress the arrival
        row: it is a control over logs and API output, and the forwarded
        payload has always carried real identifiers.
        """
        if self.cfg.redact_pins:
            return
        if arrival["identity_source"] == "unmapped":
            LOG.warning("user %s entered office, but is not in %s — add them "
                        "to see their name, Slack and GitHub",
                        arrival["employee_user_id"],
                        self.cfg.directory_file or "any directory file")
            return
        LOG.info("%s entered office. slack: %s github: %s",
                 arrival["person_name"] or f"user {arrival['employee_user_id']}",
                 arrival["slack_id"] or "-", arrival["github_id"] or "-")

    # ---- attendance query ----------------------------------------------
    def _int_param(self, q, name, default, low, high):
        """Read a bounded integer query parameter, or None after replying 400."""
        raw = q.get(name, [""])[0].strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            self._reply(f"{name} must be an integer, got {raw!r}\n", 400)
            return None
        if not low <= value <= high:
            self._reply(f"{name} must be between {low} and {high}, "
                        f"got {value}\n", 400)
            return None
        return value

    def _date_param(self, q, name):
        """Read a YYYY-MM-DD parameter. Returns (value, ok)."""
        raw = q.get(name, [""])[0].strip()
        if not raw:
            return "", True
        try:
            datetime.date.fromisoformat(raw)
        except ValueError:
            self._reply(f"{name} must be a date as YYYY-MM-DD, got {raw!r}\n",
                        400)
            return "", False
        return raw, True

    def _attendance(self, q):
        """
        Attendance as JSON: one row per person per day, read from Infino.

            /attendance?date=2026-08-09
            /attendance?user_id=3&from=2026-08-01&to=2026-08-09
            /attendance?limit=500&offset=500&order=asc

        Attendance is a daily summary, not a list of punches: when someone
        first appeared, when they were last seen, and how many times the
        reader caught them. `/punches` is still there for the raw events.

        Infino is the source of record. SQLite is a delivery buffer on the way
        there, so it is deliberately not consulted here — reading it would
        answer a subtly different question depending on how far the outbox had
        drained. The pending count is reported instead, so a caller can tell
        the difference between "nobody came in" and "nothing has shipped yet".
        """
        limit = self._int_param(q, "limit", 100, 1, 1000)
        if limit is None:
            return
        offset = self._int_param(q, "offset", 0, 0, 10_000_000)
        if offset is None:
            return

        # ?date= is shorthand for a single day, and cannot be combined with a
        # range without one silently winning.
        single, ok = self._date_param(q, "date")
        if not ok:
            return
        date_from, ok = self._date_param(q, "from")
        if not ok:
            return
        date_to, ok = self._date_param(q, "to")
        if not ok:
            return
        if single and (date_from or date_to):
            return self._reply("pass either date= or from=/to=, not both\n",
                               400)
        if single:
            date_from = date_to = single
        if date_from and date_to and date_from > date_to:
            return self._reply(f"from={date_from} is after to={date_to}\n", 400)

        order = q.get("order", ["desc"])[0].strip().lower() or "desc"
        if order not in ("asc", "desc"):
            return self._reply("order must be asc or desc\n", 400)

        user_id = q.get("user_id", [""])[0].strip()
        if user_id and not _SAFE_FILTER_RE.fullmatch(user_id):
            return self._reply("user_id must be alphanumeric\n", 400)
        serial = q.get("sn", [""])[0].strip()
        if serial and not _SAFE_FILTER_RE.fullmatch(serial):
            return self._reply("sn must be alphanumeric\n", 400)

        where = []
        if user_id:
            where.append(f"employee_user_id = {_sql_text(user_id)}")
        if serial:
            where.append(f"device_serial = {_sql_text(serial)}")
        if date_from:
            where.append(f"local_date >= {_sql_text(date_from)}")
        if date_to:
            where.append(f"local_date <= {_sql_text(date_to)}")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        direction = "DESC" if order == "desc" else "ASC"

        try:
            total = self.infino.rows(
                f"SELECT COUNT(*) AS n FROM (SELECT DISTINCT "
                f"employee_user_id, local_date FROM "
                f"{self.cfg.infino_table} {clause}) t")
            rows = self.infino.rows(
                self._attendance_sql(clause, direction, limit + 1, offset))
        except InfinoError as e:
            LOG.warning("attendance query failed: %s", e)
            return self._reply_json(
                {"error": str(e),
                 "hint": "Attendance lives only in Infino. If this "
                         "persists, punches are being refused at the door and "
                         "the terminal is holding them."},
                e.status)

        has_more = len(rows) > limit
        return self._reply_json({
            "source": {"infino_database": self.cfg.infino_database,
                       "attendance_table": self.cfg.infino_table,
                       "arrivals_table": self.cfg.infino_arrivals_table},
            "filters": {"user_id": user_id or None, "serial": serial or None,
                        "from": date_from or None, "to": date_to or None,
                        "order": order},
            "total": total[0].get("n", 0) if total else 0,
            "returned": min(len(rows), limit),
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "redacted": self.cfg.redact_pins,
            "attendance": [self._attendance_json(r) for r in rows[:limit]],
        })

    def _attendance_sql(self, clause, direction, limit, offset):
        """
        One row per person per day.

        `deduped` is not optional: Infino has no idempotency on append, so a
        retry after an ambiguous failure can land the same punch twice, and
        every count downstream would inherit it (M3.6).

        Identity is joined from the arrivals table rather than the local
        directory, so the answer is the same whoever asks and does not shift
        when directory.json is edited.
        """
        return f"""
        WITH deduped AS (
          SELECT DISTINCT event_id, employee_user_id, local_date,
                          punched_at_local
            FROM {self.cfg.infino_table}
            {clause}
        ),
        days AS (
          SELECT employee_user_id AS user_id,
                 local_date,
                 MIN(punched_at_local) AS first_seen_local,
                 MAX(punched_at_local) AS last_seen_local,
                 COUNT(*) AS punches
            FROM deduped
           GROUP BY employee_user_id, local_date
        ),
        people AS (
          SELECT employee_user_id AS user_id,
                 MAX(person_name) AS person_name,
                 MAX(slack_id) AS slack_id,
                 MAX(github_id) AS github_id
            FROM {self.cfg.infino_arrivals_table}
           GROUP BY employee_user_id
        )
        SELECT d.user_id, d.local_date, p.person_name, p.slack_id, p.github_id,
               d.first_seen_local, d.last_seen_local, d.punches
          FROM days d LEFT JOIN people p ON d.user_id = p.user_id
         ORDER BY d.local_date {direction}, d.user_id {direction}
         LIMIT {int(limit)} OFFSET {int(offset)}
        """

    def _attendance_json(self, row):
        """
        One day for one person. A NULL column is absent from Infino's row
        object rather than null, so every read here goes through .get().
        """
        redact = self.cfg.redact_pins
        first = row.get("first_seen_local")
        last = row.get("last_seen_local")
        return {
            "user_id": self._user_id_for_log(str(row.get("user_id", ""))),
            "local_date": row.get("local_date"),
            "name": None if redact else row.get("person_name"),
            "slack_id": None if redact else row.get("slack_id"),
            "github_id": None if redact else row.get("github_id"),
            "first_seen_local": first,
            "last_seen_local": last,
            "punches": row.get("punches", 0),
            # The span between the first and last sighting — not a sum of
            # in/out pairs. This terminal reports no direction at all (every
            # punch is status 255), so pairing them up would be invention.
            "minutes_on_site": _minutes_between(first, last),
        }

    # ---- user roster ---------------------------------------------------
    def _harvest_users(self, serial, body):
        """
        Pick USER records out of a device upload and publish them.

        Which endpoint and table the dump arrives on varies by firmware — a
        `table=USERINFO` POST, an OPERLOG push, or the body of a devicecmd
        reply to DATA QUERY USERINFO. Rather than guess, every non-ATTLOG body
        is scanned; a body with no USER lines costs one failed regex per line.

        A failure here is logged, never fatal: the upload still has to be
        acknowledged or the terminal re-sends it forever, and the roster is a
        convenience next to attendance.
        """
        rows = []
        for line in body.splitlines():
            fields = parse_user_line(line)
            if fields is not None:
                rows.append(device_user_payload(serial, fields))
        if not rows:
            return 0
        try:
            self.publisher.publish_users(rows)
        except InfinoError as e:
            LOG.error("could not publish %d user record(s) from SN=%s: %s "
                      "(re-run /users/sync)", len(rows), serial, e)
            return 0
        LOG.info("  published %d user record(s) from SN=%s", len(rows), serial)
        return len(rows)

    @staticmethod
    def _missing_table_hint(err):
        """Turn the query planner's 'table not found' into something actionable."""
        if "not found" in str(err).lower():
            return ("The table does not exist yet. It is created at startup "
                    "when Infino is configured; for the roster, run "
                    "/users/sync and let the device answer.")
        return None

    def _person_json(self, row):
        """
        One roster row as /users returns it. Infino omits NULL columns from a
        row object rather than returning null, so every field goes through
        .get().
        """
        redact = self.cfg.redact_pins
        privilege = row.get("privilege")
        return {
            "serial": row.get("device_serial"),
            "user_id": self._user_id_for_log(str(row.get("employee_user_id",
                                                         ""))),
            "name": "<redacted>" if redact else row.get("person_name"),
            "privilege": row.get("privilege_label")
                         or PRIVILEGE.get(privilege, f"unknown_{privilege}"),
            "card": "<redacted>" if redact else row.get("card"),
            "group": row.get("group_id"),
            "timezones": row.get("timezones"),
            "has_password": bool(row.get("has_password")),
            "synced_at": row.get("synced_at"),
        }

    @staticmethod
    def _log_roster(people):
        """Print the roster — the point of the endpoint is to read it."""
        LOG.info("=" * 68)
        LOG.info(" device user roster — %d user(s)", len(people))
        LOG.info("=" * 68)
        if not people:
            LOG.info("  (nothing harvested yet — call /users/sync)")
        for p in people:
            LOG.info("  user %-6s %-28s %-11s card=%-10s group=%s",
                     p["user_id"], (p["name"] or "(unnamed)")[:28],
                     p["privilege"],
                     p["card"] or "-", p["group"] or "-")
        LOG.info("=" * 68)

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        q = parse_qs(u.query)

        if path.startswith("/iclock/"):
            serial, err = self._serial(q)
            if err:
                LOG.warning("rejecting device GET %s from %s: %s",
                            path, self.client_address[0], err)
                return self._reply("bad request\n", 400)

            if path.startswith("/iclock/getrequest"):
                self._note(serial, "POLL (getrequest)")
                cmd = self.queue.pop(serial)
                if cmd:
                    LOG.info("  -> SENDING: %s", cmd)
                    return self._reply(cmd)
                return self._reply("OK")

            if path.startswith("/iclock/cdata"):
                return self._handshake(serial)

            if path.startswith("/iclock/ping"):
                self._note(serial, "PING")
                return self._reply("OK")

            self._note(serial, f"OTHER GET {path}")
            return self._reply("OK")

        # /healthz is unauthenticated on purpose (process supervisors and
        # uptime checks need it) and therefore says nothing about people.
        if path == "/healthz":
            silent = self.registry.silent_for()
            worst = max(silent.values()) if silent else None
            degraded = worst is None or worst > self.cfg.silence_secs
            return self._reply_json(
                {"status": "degraded" if degraded else "ok",
                 "uptime_secs": round(time.monotonic() - self.started_at),
                 "devices_registered": len(silent),
                 "seconds_since_last_contact":
                     None if worst is None else round(worst),
                 # A punch that could not be published was refused at the
                 # door, so the terminal still holds it. This is the count of
                 # rows Infino rejected outright, which are gone.
                 "rows_dropped_this_run": self.publisher.dropped},
                200 if not degraded else 503)

        if not self._authorized(q):
            return

        if path == "/status":
            silent = self.registry.silent_for()
            return self._reply_json({
                "config": {"device_tz": self.cfg.device_tz,
                           "sinks": list(self.cfg.sinks),
                           "infino": {
                               "url": self.cfg.infino_url,
                               "database": self.cfg.infino_database or None,
                               "attendance_table": self.cfg.infino_table,
                               "arrivals_table":
                                   self.cfg.infino_arrivals_table,
                               "users_table": self.cfg.infino_users_table,
                           } if self.infino.configured else None,
                           "debug_endpoints": self.cfg.debug_endpoints},
                "devices": [
                    {"serial": serial,
                     "seconds_since_contact": round(gap)}
                    for serial, gap in sorted(silent.items())],
                "queued_commands": self.queue.snapshot(),
                "published_this_run": self.publisher.appended,
                "dropped_this_run": self.publisher.dropped,
            })

        if path == "/punches":
            limit = self._int_param(q, "limit", 20, 1, 500)
            if limit is None:
                return
            try:
                # DISTINCT on event_id: Infino has no append idempotency, so a
                # retried batch can land the same punch twice (M3.6).
                rows = self.infino.rows(f"""
                    SELECT DISTINCT event_id, employee_user_id, device_serial,
                           punched_at_local, punched_at, direction,
                           verify_method
                      FROM {self.cfg.infino_table}
                     ORDER BY punched_at_local DESC
                     LIMIT {limit}
                """)
            except InfinoError as e:
                LOG.warning("punches query failed: %s", e)
                return self._reply_json({"error": str(e)}, e.status)
            return self._reply_json([
                {"event_id": r.get("event_id"),
                 "user_id": self._user_id_for_log(
                     str(r.get("employee_user_id", ""))),
                 "punched_local": r.get("punched_at_local"),
                 "punched_utc": r.get("punched_at"),
                 "direction": r.get("direction"),
                 "verify": r.get("verify_method"),
                 "serial": r.get("device_serial")}
                for r in rows])

        if path == "/attendance":
            return self._attendance(q)

        # The device's user list, for the one-off sync that seeds the identity
        # file. /users/sync asks the terminal for it; /users reads back what
        # came in, which is what you copy out.
        if path == "/users":
            serial = q.get("sn", [""])[0].strip() or None
            if serial and not _SAFE_FILTER_RE.fullmatch(serial):
                return self._reply("sn must be alphanumeric\n", 400)
            where = (f"WHERE device_serial = {_sql_text(serial)}"
                     if serial else "")
            try:
                # The roster table is append-only, so a re-sync adds rows
                # rather than replacing them: newest synced_at per person wins.
                rows = self.infino.rows(f"""
                    WITH latest AS (
                      SELECT device_serial, employee_user_id,
                             MAX(synced_at) AS synced_at
                        FROM {self.cfg.infino_users_table}
                        {where}
                       GROUP BY device_serial, employee_user_id
                    )
                    SELECT u.* FROM {self.cfg.infino_users_table} u
                      JOIN latest l
                        ON u.device_serial = l.device_serial
                       AND u.employee_user_id = l.employee_user_id
                       AND u.synced_at = l.synced_at
                     ORDER BY CAST(u.employee_user_id AS INT),
                              u.employee_user_id
                """)
            except InfinoError as e:
                LOG.warning("roster query failed: %s", e)
                return self._reply_json({"error": str(e), "hint": self._missing_table_hint(e)}, e.status)
            people = [self._person_json(r) for r in rows]
            self._log_roster(people)
            return self._reply_json({
                "device_serial": serial,
                "redacted": self.cfg.redact_pins,
                "count": len(people),
                "users": people,
                "hint": ("Empty — call /users/sync, wait a poll or two for the "
                         "device to answer, then reload this.")
                        if not people else None,
            })

        if path == "/users/sync":
            serial = self._target(q)
            if not serial:
                return
            queued = [self.queue.enqueue(serial, c) for c in _USERINFO_QUERIES]
            return self._reply(
                f"Queued {len(queued)} user-dump command(s) for {serial}:\n"
                + "".join(f"  {c}\n" for c in queued) +
                "They fire one per poll (~10-15s each). Firmware differs on "
                "which form it honours, so both are sent and whichever\n"
                "the device answers is harvested. Watch the log, then read "
                "/users.\n")

        if path == "/open":
            serial = self._target(q)
            if not serial:
                return
            try:
                payload = _door_payload(q.get("door", ["1"])[0],
                                        q.get("sec", ["5"])[0],
                                        q.get("cc", ["01"])[0],
                                        q.get("dd", ["00"])[0])
            except ValueError:
                return self._reply("door and sec must be integers\n", 400)
            cmd = self.queue.enqueue(serial, f"CONTROL DEVICE {payload}")
            return self._reply(f"Door-open queued for {serial}: {cmd}\n"
                               "Fires on the device's next poll (<15s).\n")

        if path == "/hold":
            serial = self._target(q)
            if not serial:
                return
            cmd = self.queue.enqueue(serial, "CONTROL DEVICE 010101FF00")
            return self._reply(f"Normal-open ENABLE queued: {cmd}\n"
                               "The door will stay unlocked until /release.\n")

        if path == "/release":
            serial = self._target(q)
            if not serial:
                return
            cmd = self.queue.enqueue(serial, "CONTROL DEVICE 0101010000")
            return self._reply(f"Normal-open DISABLE queued: {cmd}\n")

        # Below here: operational tools that can send arbitrary frames or take
        # the terminal offline. Off unless explicitly enabled.
        if path in ("/raw", "/reboot"):
            if not self.cfg.debug_endpoints:
                return self._reply("Disabled. Set ZK_DEBUG_ENDPOINTS=1 to "
                                   "enable /raw and /reboot.\n", 403)
            serial = self._target(q)
            if not serial:
                return
            if path == "/reboot":
                cmd = self.queue.enqueue(serial, "CONTROL DEVICE 03000000")
                return self._reply(f"Reboot queued: {cmd}\n")
            payload = q.get("p", [""])[0]
            if not re.fullmatch(r"[0-9A-Fa-f]{2,32}", payload):
                return self._reply("p must be an even-length hex payload, "
                                   "e.g. /raw?p=01010105\n", 400)
            cmd = self.queue.enqueue(serial, f"CONTROL DEVICE {payload}")
            return self._reply(f"Raw command queued: {cmd}\n")

        return self._reply("Unknown endpoint. See the module docstring.\n", 404)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        q = parse_qs(u.query)

        if not path.startswith("/iclock/"):
            return self._reply("Unknown endpoint.\n", 404)

        serial, err = self._serial(q)
        if err:
            LOG.warning("rejecting device POST %s from %s: %s",
                        path, self.client_address[0], err)
            return self._reply("bad request\n", 400)

        body = self._read_body()
        if body is None:
            return                                  # already answered

        table = q.get("table", [""])[0]

        if path.startswith("/iclock/cdata"):
            self._note(serial, f"UPLOAD (table={table or '?'})")
            if table.upper() == "ATTLOG":
                return self._handle_attlog(serial, body)
            if body.strip():
                # OPERLOG (door events, admin actions), USERINFO, options
                # replies, etc. Scrub before logging or storing: a user dump
                # also carries biometric templates and door passwords.
                safe = scrub_secrets(body)
                LOG.info("  table=%s body=%s", table or "?",
                         safe.strip()[:400])
                self._harvest_users(serial, body)
            return self._reply("OK")

        if path.startswith("/iclock/devicecmd"):
            self._note(serial, "CMD RESULT (devicecmd)")
            if body.strip():
                safe = scrub_secrets(body)
                LOG.info("  ack: %s", safe.strip()[:300])
                self._harvest_users(serial, body)
            return self._reply("OK")

        self._note(serial, f"OTHER POST {path}")
        if body.strip():
            safe = scrub_secrets(body)
            LOG.info("  body: %s", safe.strip()[:300])
            self._harvest_users(serial, body)
        return self._reply("OK")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def _lan_ip():
    """Best-effort local IP, so the banner can show what to type on the device."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))    # TEST-NET-1: routed nowhere, never sent
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _banner(cfg, directory):
    ip = _lan_ip()
    LOG.info("=" * 68)
    LOG.info(" eSSL / ZKTeco attendance push server")
    LOG.info("=" * 68)
    LOG.info(" listening      http://%s:%s   (bind %s)", ip, cfg.port,
             cfg.bind)
    LOG.info(" device config  Address=%s  Port=%s  Mode=ADMS", ip, cfg.port)
    LOG.info(" storage        Infino only — nothing at rest on this machine")
    LOG.info(" directory      %s", f"{cfg.directory_file} ({len(directory)} "
             f"person/people)" if cfg.directory_file else "not set")
    LOG.info(" device tz      %s", cfg.device_tz)
    LOG.info(" sinks          %s", ", ".join(cfg.sinks))
    if any(s.startswith("infino") for s in cfg.sinks):
        LOG.info(" infino         %s/%s", cfg.infino_url, cfg.infino_database)
        LOG.info(" tables         %s (punches), %s (arrivals), %s (roster)",
                 cfg.infino_table, cfg.infino_arrivals_table,
                 cfg.infino_users_table)
    if cfg.allowed_serials:
        LOG.info(" serials        %s", ", ".join(sorted(cfg.allowed_serials)))
    if cfg.debug_endpoints:
        LOG.warning(" /raw and /reboot are ENABLED")
    LOG.info(" Keep this port on a trusted LAN — it can unlock a door.")
    LOG.info("=" * 68)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Production iclock/ADMS push server for eSSL terminals.")
    ap.add_argument("port", nargs="?", type=int,
                    help="listen port (overrides $ZK_PORT, default 8081)")
    ap.add_argument("--env-file", action="append", metavar="PATH", default=[],
                    help="read ZK_* settings from a KEY=value file; repeatable, "
                         "later files win. Real environment variables still "
                         "override the file unless --override-env is given.")
    ap.add_argument("--dev", action="store_true",
                    help=f"development mode: load ./{DEV_ENV_FILE}")
    ap.add_argument("--override-env", action="store_true",
                    help="let the file(s) win over already-exported variables")
    ap.add_argument("--check-config", action="store_true",
                    help="validate configuration and exit")
    args = ap.parse_args(argv)

    # Log to stdout at INFO before config is parsed, so config warnings show.
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    # --dev is a shorthand for the repo's dev.env, and is applied first so an
    # explicit --env-file can layer on top of it.
    paths = list(args.env_file)
    if args.dev:
        dev_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                DEV_ENV_FILE)
        if not os.path.exists(dev_path):
            print(f"configuration error: --dev needs {DEV_ENV_FILE}, which is "
                  f"gitignored. Copy it from {DEV_ENV_FILE}.example and edit.",
                  file=sys.stderr)
            return 2
        paths.insert(0, dev_path)

    try:
        # Snapshot first: every file yields to the real environment, but a
        # later file may override an earlier one.
        preset = frozenset(os.environ)
        for path in paths:
            names = load_env_file(path, override=args.override_env,
                                  protect=preset)
            LOG.info("config file %s: %d setting(s) applied", path, len(names))
        cfg = Config.from_env(args.port)
        setup_logging(cfg)
        # Loaded here rather than lazily so a malformed file is a startup
        # failure that --check-config catches, not a surprise on a Monday.
        directory = Directory(cfg.directory_file).load()
    except ConfigError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return 2

    if cfg.directory_file:
        LOG.info("directory %s: %d person/people loaded",
                 cfg.directory_file, len(directory))

    if args.check_config:
        LOG.info("configuration OK")
        return 0

    client = InfinoClient(cfg)
    publisher = Publisher(cfg, client)
    tables = {cfg.infino_table: INFINO_TABLE_SCHEMA,
              cfg.infino_arrivals_table: INFINO_ARRIVALS_SCHEMA,
              cfg.infino_users_table: INFINO_USERS_SCHEMA}
    # Not gated on the sinks: /attendance and /users read these tables even in
    # a log-only dry run, and a missing table is a confusing 400 from the
    # query planner. Surfaces a bad key at startup rather than at 9am.
    # Non-fatal — tables are re-created on demand, and until then the device
    # is told to hold its records.
    if client.configured:
        try:
            client.ensure_ready(tables)
        except InfinoError as e:
            LOG.error("Infino is not ready: %s — punches will be refused "
                      "until it is reachable", e)

    Handler.cfg = cfg
    Handler.queue = CommandQueue()
    Handler.registry = DeviceRegistry()
    Handler.directory = directory
    Handler.infino = client
    Handler.publisher = publisher
    Handler.greetings = GreetingGuard(client, cfg.infino_arrivals_table)
    Handler.started_at = time.monotonic()

    try:
        httpd = ThreadingHTTPServer((cfg.bind, cfg.port), Handler)
    except OSError as e:
        print(f"cannot listen on {cfg.bind}:{cfg.port}: {e}", file=sys.stderr)
        return 1
    httpd.daemon_threads = True

    def _shutdown(signum, _frame):
        LOG.info("signal %s received, shutting down", signal.Signals(signum).name)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    _banner(cfg, directory)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
        LOG.info("stopped. %d row(s) published, %d dropped this run.",
                 publisher.appended, publisher.dropped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
