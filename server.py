#!/usr/bin/env python3
"""
server.py  —  Production iclock / ADMS push server for ZKTeco / eSSL terminals.

This is the service you actually run. It is derived from the exploratory
scripts in this repo (adms.py, door_open.py, caps.py) but differs from them in
the ways that matter once attendance data has to reach somewhere else:

  * Every punch is committed to SQLite BEFORE the device is acknowledged, and
    de-duplicated on a stable key. The terminal re-uploads whole ATTLOG batches
    whenever it doesn't like our reply, so "at least once" delivery from the
    device has to become "exactly once" storage here.
  * Outbound delivery is a durable outbox drained by a background worker, not
    an HTTP call inside the request handler. A slow or failing cloud must never
    stall the device's poll loop or cause it to re-send.
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
    python3 server.py --check-config      # validate env and exit
    python3 server.py                     # listens on :8081

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
    /punches?limit=20    most recent stored punches
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
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

USER_AGENT = "essl-automation-server/1.0"
PAYLOAD_SCHEMA = "essl.attendance.v1"
LOG = logging.getLogger("essl")

# ATTLOG status codes (byte 3 of each record).
PUNCH_STATUS = {
    0: "check_in",
    1: "check_out",
    2: "break_out",
    3: "break_in",
    4: "overtime_in",
    5: "overtime_out",
}
# Verification method (byte 4). Firmware-dependent beyond these.
VERIFY_METHOD = {
    0: "password",
    1: "fingerprint",
    2: "card",
    3: "fingerprint_or_password",
    4: "card_or_fingerprint",
    15: "face",
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


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised for a bad or missing environment variable."""


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
    db_path: str
    log_level: str
    log_file: str
    redact_pins: bool
    sinks: tuple
    infino_url: str
    infino_database: str
    infino_table: str
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
            db_path=os.environ.get("ZK_DB_PATH", "data/attendance.db"),
            log_level=os.environ.get("ZK_LOG_LEVEL", "INFO").upper(),
            log_file=os.environ.get("ZK_LOG_FILE", ""),
            redact_pins=_env_bool("ZK_REDACT_PINS", False),
            sinks=sinks,
            infino_url=infino_url,
            infino_database=database,
            infino_table=os.environ.get("ZK_INFINO_TABLE", "attendance"),
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
        unknown = set(self.sinks) - {"log", "infino"}
        if unknown:
            raise ConfigError(f"ZK_SINKS contains unknown sink(s): "
                              f"{', '.join(sorted(unknown))}")
        if not self.sinks:
            raise ConfigError("ZK_SINKS is empty; use 'log' to store punches "
                              "without forwarding them")
        if "infino" in self.sinks:
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
                    "ZK_SINKS includes 'infino' but no database is set. Use "
                    "ZK_INFINO_DATABASE=my-app, or put it in the URL as "
                    "ZK_INFINO_URL=https://api.platform.infino.ws/my-app")
            if not self.infino_api_key:
                raise ConfigError(
                    "ZK_SINKS includes 'infino' but no API key is set. Create "
                    "one at https://platform.infino.ws and set "
                    "ZK_INFINO_API_KEY (or INFINO_API_KEY).")
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
    pin: str
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
        arrive many times. Serial + PIN + device-local timestamp + status is
        the natural key: a person cannot produce two distinct punches of the
        same type at the same second on the same terminal.
        """
        material = f"{self.serial}|{self.pin}|{self.punched_local}|{self.status}"
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
            "employee_pin": self.pin,
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


def parse_attlog_line(line, serial, tz, received_utc):
    """
    Parse one ATTLOG record into a Punch, or return None if it isn't one.

    Canonical form is tab-separated:
        PIN <TAB> YYYY-MM-DD HH:MM:SS <TAB> status <TAB> verify <TAB> workcode
    with trailing reserved columns we ignore.
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
        pin=pin,
        punched_local=ts.replace("T", " "),
        punched_utc=punched_utc,
        local_date=local_date,
        status=_int(status_s),
        verify=_int(verify_s),
        workcode=workcode or "0",
        raw=line[:512],
        received_utc=received_utc,
    )


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    serial          TEXT PRIMARY KEY,
    first_seen_utc  TEXT NOT NULL,
    last_seen_utc   TEXT NOT NULL,
    last_event      TEXT,
    contacts        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS punches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key       TEXT NOT NULL UNIQUE,
    serial          TEXT NOT NULL,
    pin             TEXT NOT NULL,
    punched_local   TEXT NOT NULL,
    punched_utc     TEXT,
    local_date      TEXT,
    status          INTEGER,
    verify          INTEGER,
    workcode        TEXT,
    raw             TEXT NOT NULL,
    received_utc    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS punches_person_day
    ON punches (pin, local_date);

-- One row per (punch, sink). Adding a sink later (e.g. the good-morning
-- greeter) means writing an extra row here, not changing the device path.
CREATE TABLE IF NOT EXISTS outbox (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    punch_id          INTEGER NOT NULL REFERENCES punches(id),
    sink              TEXT NOT NULL,
    dedup_key         TEXT NOT NULL,
    payload           TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'pending',
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_utc  TEXT NOT NULL,
    last_error        TEXT,
    created_utc       TEXT NOT NULL,
    delivered_utc     TEXT,
    UNIQUE (dedup_key, sink)
);
CREATE INDEX IF NOT EXISTS outbox_ready
    ON outbox (state, next_attempt_utc);

-- Non-attendance uploads (OPERLOG door events, options replies, ...). Kept
-- capped and raw so door-event work later has real samples to build on.
CREATE TABLE IF NOT EXISTS uploads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    serial        TEXT NOT NULL,
    table_name    TEXT,
    body          TEXT NOT NULL,
    received_utc  TEXT NOT NULL
);
"""


class Store:
    """
    SQLite persistence. One connection per thread (handlers run concurrently),
    WAL so the delivery worker's writes don't block device requests.
    """

    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._local = threading.local()
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")   # a punch must survive a crash
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @property
    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._connect()
            self._local.conn = c
        return c

    # ---- writes --------------------------------------------------------
    def note_contact(self, serial, event):
        now = _iso(_utcnow())
        with self.conn as conn:
            conn.execute(
                """INSERT INTO devices (serial, first_seen_utc, last_seen_utc,
                                        last_event, contacts)
                   VALUES (?, ?, ?, ?, 1)
                   ON CONFLICT(serial) DO UPDATE SET
                       last_seen_utc = excluded.last_seen_utc,
                       last_event    = excluded.last_event,
                       contacts      = contacts + 1""",
                (serial, now, now, event))

    def record_punch(self, punch, sinks, tz_name):
        """
        Store a punch and queue it for every sink, atomically.

        Returns True if this punch was new, False if it was a re-upload we have
        already accepted. Either way the device gets an OK — the whole point of
        the dedup key is that a retry is harmless.
        """
        payload = json.dumps(punch.payload(tz_name), separators=(",", ":"))
        now = _iso(_utcnow())
        with self.conn as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO punches
                       (dedup_key, serial, pin, punched_local, punched_utc,
                        local_date, status, verify, workcode, raw, received_utc)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (punch.dedup_key, punch.serial, punch.pin, punch.punched_local,
                 punch.punched_utc or None, punch.local_date or None,
                 punch.status, punch.verify, punch.workcode, punch.raw,
                 punch.received_utc))
            if cur.rowcount == 0:
                return False
            punch_id = cur.lastrowid
            for sink in sinks:
                conn.execute(
                    """INSERT OR IGNORE INTO outbox
                           (punch_id, sink, dedup_key, payload, state,
                            next_attempt_utc, created_utc)
                       VALUES (?,?,?,?, 'pending', ?, ?)""",
                    (punch_id, sink, punch.dedup_key, payload, now, now))
        return True

    def record_upload(self, serial, table_name, body):
        with self.conn as conn:
            conn.execute(
                """INSERT INTO uploads (serial, table_name, body, received_utc)
                   VALUES (?,?,?,?)""",
                (serial, table_name, body[:8192], _iso(_utcnow())))

    # ---- outbox --------------------------------------------------------
    def ready_outbox(self, limit=50):
        return self.conn.execute(
            """SELECT id, sink, dedup_key, payload, attempts
                 FROM outbox
                WHERE state = 'pending' AND next_attempt_utc <= ?
                ORDER BY id
                LIMIT ?""",
            (_iso(_utcnow()), limit)).fetchall()

    def mark_delivered(self, row_ids):
        """Mark a whole batch delivered in one transaction — an Infino append
        is atomic, so the rows succeed or fail together."""
        now = _iso(_utcnow())
        with self.conn as conn:
            conn.executemany(
                """UPDATE outbox
                      SET state='delivered', delivered_utc=?, attempts=attempts+1,
                          last_error=NULL
                    WHERE id=?""", [(now, rid) for rid in row_ids])

    def mark_retry(self, row_id, error, delay_secs):
        nxt = _iso(_utcnow() + datetime.timedelta(seconds=delay_secs))
        with self.conn as conn:
            conn.execute(
                """UPDATE outbox
                      SET attempts=attempts+1, last_error=?, next_attempt_utc=?
                    WHERE id=?""", (error[:500], nxt, row_id))

    def mark_dead(self, row_id, error):
        with self.conn as conn:
            conn.execute(
                """UPDATE outbox
                      SET state='dead', attempts=attempts+1, last_error=?
                    WHERE id=?""", (error[:500], row_id))

    # ---- reads ---------------------------------------------------------
    def stats(self):
        counts = {r["state"]: r["n"] for r in self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM outbox GROUP BY state")}
        punches = self.conn.execute(
            "SELECT COUNT(*) AS n FROM punches").fetchone()["n"]
        return {"punches": punches,
                "outbox_pending": counts.get("pending", 0),
                "outbox_delivered": counts.get("delivered", 0),
                "outbox_dead": counts.get("dead", 0)}

    def devices(self):
        return self.conn.execute(
            """SELECT serial, first_seen_utc, last_seen_utc, last_event, contacts
                 FROM devices ORDER BY last_seen_utc DESC""").fetchall()

    def recent_punches(self, limit=20):
        return self.conn.execute(
            """SELECT pin, punched_local, punched_utc, status, verify, serial
                 FROM punches ORDER BY id DESC LIMIT ?""",
            (max(1, min(500, limit)),)).fetchall()


# --------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class DeliveryResult:
    ok: bool
    permanent: bool = False     # don't retry: the request itself is wrong
    error: str = ""
    retry_after: float = 0.0    # honour a server-supplied Retry-After


# The attendance table as Infino will hold it. Kept beside Punch.payload(),
# which must produce exactly these column names.
#
# No fts or vector index is declared: every question we ask of this table
# ("what did PIN 12 do today?") is a SQL predicate, which /v1/query_sql answers
# without one. Adding a full-text or embedding index later is a deliberate
# schema change, not something to guess at now.
INFINO_TABLE_SCHEMA = [
    {"name": "event_id", "type": "large_utf8", "nullable": False},
    {"name": "schema_version", "type": "large_utf8"},
    {"name": "device_serial", "type": "large_utf8"},
    {"name": "employee_pin", "type": "large_utf8"},
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


class LogSink:
    """Writes rows to the log. The dry-run target: set ZK_SINKS=log."""

    name = "log"

    def deliver(self, rows):
        for row in rows:
            LOG.info("[log-sink] %s", row["payload"])
        return DeliveryResult(ok=True)


class InfinoSink:
    """
    Appends punches as rows to a table in Infino Cloud.

    Infino is a retrieval engine, not an event bus: a database and a table have
    to exist before any append, and there is no idempotency key. Two
    consequences shape this class.

    First, bootstrap. We create the database and table on first use and
    whenever an append reports 404, because "table missing" is recoverable —
    unlike a malformed row.

    Second, duplicates. Our outbox guarantees each punch is *sent* once, but if
    a response is lost after Infino committed the append, the retry appends the
    row twice. Every row therefore carries `event_id`, so readers can dedup
    (`SELECT ... GROUP BY event_id`). Closing that window properly means
    checking for the row before retrying an ambiguous failure — ROADMAP M3.6.
    """

    name = "infino"

    def __init__(self, cfg):
        self.base = cfg.infino_url
        self.database = cfg.infino_database
        self.table = cfg.infino_table
        self.api_key = cfg.infino_api_key
        self.timeout = cfg.infino_timeout
        self.autocreate = cfg.infino_bootstrap
        self._bootstrapped = False
        self._lock = threading.Lock()

    # ---- HTTP ----------------------------------------------------------
    def _post(self, path, body, query=""):
        """
        POST JSON to an Infino path. Returns (status, parsed_body_or_text).
        Raises nothing the caller has to catch except transport errors, which
        are translated into DeliveryResult by the callers below.
        """
        url = f"{self.base}{path}" + (f"?{query}" if query else "")
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("User-Agent", USER_AGENT)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read(4096).decode("utf-8", "replace")
            return resp.status, raw

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

    @staticmethod
    def _retry_after(err):
        try:
            return max(0.0, float(err.headers.get("Retry-After", 0) or 0))
        except (TypeError, ValueError):
            return 0.0

    # ---- bootstrap -----------------------------------------------------
    def ensure_ready(self):
        """
        Create the database and table if they don't exist.

        Idempotent and best-effort: 409 means someone got there first, which is
        success. A failure here is logged but never raised — punches keep
        accumulating in the outbox and the next delivery attempt retries this.
        """
        with self._lock:
            if self._bootstrapped or not self.autocreate:
                return self._bootstrapped
            try:
                try:
                    self._post("/v1/databases", {"name": self.database})
                    LOG.info("created Infino database %r", self.database)
                except urllib.error.HTTPError as e:
                    if e.code != 409:
                        raise
                    LOG.debug("Infino database %r already exists",
                              self.database)
                try:
                    self._post(f"/v1/create_table/{self.database}",
                               {"table_name": self.table,
                                "schema": INFINO_TABLE_SCHEMA})
                    LOG.info("created Infino table %r in %r",
                             self.table, self.database)
                except urllib.error.HTTPError as e:
                    if e.code != 409:
                        raise
                    LOG.debug("Infino table %r already exists", self.table)
                self._bootstrapped = True
            except urllib.error.HTTPError as e:
                LOG.error("Infino bootstrap failed: %s", self._describe(e))
            except Exception as e:
                LOG.error("Infino bootstrap failed: %s: %s",
                          type(e).__name__, e)
            return self._bootstrapped

    # ---- delivery ------------------------------------------------------
    def deliver(self, rows):
        """
        Append a batch of rows. One append is one atomic commit, so the whole
        batch shares a fate — which is why the worker retries a rejected batch
        row by row to find the poison record.
        """
        self.ensure_ready()
        data = [json.loads(r["payload"]) for r in rows]
        try:
            status, _ = self._post(f"/v1/append/{self.database}",
                                   {"data": data},
                                   query=f"table={self.table}")
            if 200 <= status < 300:
                return DeliveryResult(ok=True)
            return DeliveryResult(ok=False,
                                  error=f"unexpected status {status}")
        except urllib.error.HTTPError as e:
            desc = self._describe(e)
            if e.code == 404:
                # Database or table is missing — recoverable, so re-bootstrap
                # and let the normal backoff bring this batch back.
                with self._lock:
                    self._bootstrapped = False
                LOG.warning("Infino reported 404; will re-create the database "
                            "and table on the next attempt (%s)", desc)
                return DeliveryResult(ok=False, error=desc)
            if e.code == 503:
                # Documented cold start: the request did not run.
                return DeliveryResult(ok=False, error=desc,
                                      retry_after=self._retry_after(e))
            if e.code == 413:
                # Batch too large. Splitting is the fix, and the worker does
                # that on any permanent error, so this resolves itself.
                return DeliveryResult(ok=False, permanent=True, error=desc)
            permanent = 400 <= e.code < 500 and e.code not in (408, 429)
            return DeliveryResult(ok=False, permanent=permanent, error=desc,
                                  retry_after=self._retry_after(e))
        except urllib.error.URLError as e:
            return DeliveryResult(ok=False, error=f"network: {e.reason}")
        except TimeoutError:
            return DeliveryResult(ok=False, error="timeout")
        except Exception as e:                       # never kill the worker
            return DeliveryResult(ok=False, error=f"{type(e).__name__}: {e}")


def build_sinks(cfg):
    sinks = {}
    for name in cfg.sinks:
        sinks[name] = InfinoSink(cfg) if name == "infino" else LogSink()
    return sinks


class DeliveryWorker(threading.Thread):
    """
    Drains the outbox. Single-threaded on purpose: ordering per person is
    easier to reason about, and the volume (a few hundred punches a day) is
    nowhere near needing concurrency.
    """

    def __init__(self, cfg, store, sinks, stop_event):
        super().__init__(name="delivery", daemon=True)
        self.cfg = cfg
        self.store = store
        self.sinks = sinks
        self.stop = stop_event
        self.delivered = 0
        self.failed = 0
        self.last_success_utc = None

    def _backoff(self, attempts):
        raw = self.cfg.retry_base_secs * (2 ** min(attempts, 12))
        capped = min(raw, self.cfg.retry_cap_secs)
        return capped * (0.5 + random.random())      # jitter: avoid lockstep

    def _chunks(self, rows):
        """
        Split rows into batches within Infino's per-request budget. Punch rows
        are a few hundred bytes, so the row count is what normally binds; the
        byte budget only matters when draining a long backlog.
        """
        batch, size = [], 0
        for row in rows:
            n = len(row["payload"])
            if batch and (len(batch) >= self.cfg.infino_batch_rows
                          or size + n > self.cfg.infino_batch_bytes):
                yield batch
                batch, size = [], 0
            batch.append(row)
            size += n
        if batch:
            yield batch

    def run(self):
        LOG.info("delivery worker started (sinks: %s)",
                 ", ".join(sorted(self.sinks)))
        while not self.stop.is_set():
            try:
                rows = self.store.ready_outbox(
                    limit=max(self.cfg.infino_batch_rows * 2, 100))
            except Exception:
                LOG.exception("outbox read failed")
                self.stop.wait(self.cfg.worker_poll_secs)
                continue
            if not rows:
                self.stop.wait(self.cfg.worker_poll_secs)
                continue
            by_sink = {}
            for row in rows:
                by_sink.setdefault(row["sink"], []).append(row)
            for sink_name, sink_rows in by_sink.items():
                for batch in self._chunks(sink_rows):
                    if self.stop.is_set():
                        break
                    self._deliver_batch(sink_name, batch)
        LOG.info("delivery worker stopped")

    def _deliver_batch(self, sink_name, batch):
        sink = self.sinks.get(sink_name)
        if sink is None:
            # Sink was removed from config while rows for it were pending.
            for row in batch:
                self.store.mark_retry(row["id"],
                                      f"sink {sink_name} not enabled",
                                      self.cfg.retry_cap_secs)
            return

        result = sink.deliver(batch)
        if result.ok:
            self.store.mark_delivered([r["id"] for r in batch])
            self.delivered += len(batch)
            self.last_success_utc = _iso(_utcnow())
            LOG.info("delivered %d row(s) -> %s [%s]", len(batch), sink_name,
                     ", ".join(r["dedup_key"][:12] for r in batch[:3])
                     + (", ..." if len(batch) > 3 else ""))
            return

        # An append is atomic, so a rejected batch tells us nothing about which
        # row was at fault. Re-send them one at a time so a single bad record
        # gets dead-lettered instead of blocking everyone behind it.
        if result.permanent and len(batch) > 1:
            LOG.warning("batch of %d rejected by %s (%s); retrying "
                        "individually to isolate the bad row",
                        len(batch), sink_name, result.error)
            for row in batch:
                self._deliver_batch(sink_name, [row])
            return

        for row in batch:
            self._fail_row(row, sink_name, result)

    def _fail_row(self, row, sink_name, result):
        self.failed += 1
        attempts = row["attempts"] + 1
        key = row["dedup_key"][:12]
        if result.permanent:
            self.store.mark_dead(row["id"], result.error)
            LOG.error("permanent failure for %s -> %s: %s (dead-lettered)",
                      key, sink_name, result.error)
        elif attempts >= self.cfg.max_attempts:
            self.store.mark_dead(row["id"], result.error)
            LOG.error("giving up on %s -> %s after %d attempts: %s",
                      key, sink_name, attempts, result.error)
        else:
            # A server-supplied Retry-After beats our guess — Infino sends one
            # on the 503 it returns while an idle database is starting up.
            delay = result.retry_after or self._backoff(attempts)
            self.store.mark_retry(row["id"], result.error, delay)
            LOG.warning("delivery of %s -> %s failed (attempt %d/%d), retry in "
                        "%.0fs: %s", key, sink_name, attempts,
                        self.cfg.max_attempts, delay, result.error)


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
    store = None
    queue = None
    registry = None
    worker = None
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

    def _pin_for_log(self, pin):
        if not self.cfg.redact_pins:
            return pin
        return "pin:" + hashlib.sha256(pin.encode()).hexdigest()[:8]

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
        self.store.note_contact(serial, event)
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
        Store an uploaded attendance batch.

        The reply must be `OK: <count>` where count is the number of records we
        accepted; anything else and most firmware re-sends the whole batch on
        its next transfer. We only send it after the rows are committed.
        """
        tz = ZoneInfo(self.cfg.device_tz)
        received = _iso(_utcnow())
        accepted = new = malformed = 0
        for line in body.splitlines():
            if not line.strip():
                continue
            punch = parse_attlog_line(line, serial, tz, received)
            if punch is None:
                malformed += 1
                LOG.warning("unparseable ATTLOG line from SN=%s: %r",
                            serial, line[:200])
                continue
            try:
                is_new = self.store.record_punch(punch, self.cfg.sinks,
                                                 self.cfg.device_tz)
            except Exception:
                # Do NOT acknowledge what we failed to store — let the device
                # keep the record and re-send it.
                LOG.exception("failed to store punch from SN=%s", serial)
                self._reply("storage error\n", 500)
                return
            accepted += 1
            if is_new:
                new += 1
                LOG.info("PUNCH %s %s %s (%s via %s)",
                         self._pin_for_log(punch.pin), punch.punched_local,
                         punch.punched_utc or "?", punch.direction,
                         VERIFY_METHOD.get(punch.verify, punch.verify))
            else:
                LOG.debug("duplicate punch ignored: %s", punch.dedup_key[:12])

        LOG.info("ATTLOG batch from SN=%s: %d accepted (%d new), %d malformed",
                 serial, accepted, new, malformed)
        # Count everything we consumed, malformed included: re-sending a line we
        # cannot parse will not make it parseable, and stalling the device on it
        # would block every later punch behind it.
        self._reply(f"OK: {accepted + malformed}")

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
            stats = self.store.stats()
            degraded = (worst is None or worst > self.cfg.silence_secs
                        or stats["outbox_dead"] > 0)
            return self._reply_json(
                {"status": "degraded" if degraded else "ok",
                 "uptime_secs": round(time.monotonic() - self.started_at),
                 "devices_registered": len(silent),
                 "seconds_since_last_contact":
                     None if worst is None else round(worst),
                 "outbox_pending": stats["outbox_pending"],
                 "outbox_dead": stats["outbox_dead"]},
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
                               "table": self.cfg.infino_table,
                           } if "infino" in self.cfg.sinks else None,
                           "debug_endpoints": self.cfg.debug_endpoints},
                "devices": [
                    {"serial": r["serial"],
                     "last_seen_utc": r["last_seen_utc"],
                     "last_event": r["last_event"],
                     "contacts": r["contacts"],
                     "seconds_since_contact":
                         round(silent[r["serial"]])
                         if r["serial"] in silent else None}
                    for r in self.store.devices()],
                "queued_commands": self.queue.snapshot(),
                "delivery": {"delivered_this_run": self.worker.delivered,
                             "failures_this_run": self.worker.failed,
                             "last_success_utc": self.worker.last_success_utc},
                "store": self.store.stats(),
            })

        if path == "/punches":
            try:
                limit = int(q.get("limit", ["20"])[0])
            except ValueError:
                return self._reply("limit must be an integer\n", 400)
            return self._reply_json([
                {"pin": self._pin_for_log(r["pin"]),
                 "punched_local": r["punched_local"],
                 "punched_utc": r["punched_utc"],
                 "direction": PUNCH_STATUS.get(r["status"], r["status"]),
                 "verify": VERIFY_METHOD.get(r["verify"], r["verify"]),
                 "serial": r["serial"]}
                for r in self.store.recent_punches(limit)])

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
                # OPERLOG (door events, admin actions), options replies, etc.
                LOG.info("  table=%s body=%s", table or "?",
                         body.strip()[:400])
                self.store.record_upload(serial, table, body)
            return self._reply("OK")

        if path.startswith("/iclock/devicecmd"):
            self._note(serial, "CMD RESULT (devicecmd)")
            if body.strip():
                LOG.info("  ack: %s", body.strip()[:300])
                self.store.record_upload(serial, "devicecmd", body)
            return self._reply("OK")

        self._note(serial, f"OTHER POST {path}")
        if body.strip():
            LOG.info("  body: %s", body.strip()[:300])
            self.store.record_upload(serial, table or path, body)
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


def _banner(cfg):
    ip = _lan_ip()
    LOG.info("=" * 68)
    LOG.info(" eSSL / ZKTeco attendance push server")
    LOG.info("=" * 68)
    LOG.info(" listening      http://%s:%s   (bind %s)", ip, cfg.port,
             cfg.bind)
    LOG.info(" device config  Address=%s  Port=%s  Mode=ADMS", ip, cfg.port)
    LOG.info(" database       %s", os.path.abspath(cfg.db_path))
    LOG.info(" device tz      %s", cfg.device_tz)
    LOG.info(" sinks          %s", ", ".join(cfg.sinks))
    if "infino" in cfg.sinks:
        LOG.info(" infino         %s/v1/append/%s?table=%s",
                 cfg.infino_url, cfg.infino_database, cfg.infino_table)
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
    ap.add_argument("--check-config", action="store_true",
                    help="validate configuration and exit")
    args = ap.parse_args(argv)

    # Log to stdout at INFO before config is parsed, so config warnings show.
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    try:
        cfg = Config.from_env(args.port)
        setup_logging(cfg)
    except ConfigError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return 2

    if args.check_config:
        LOG.info("configuration OK")
        return 0

    store = Store(cfg.db_path)
    sinks = build_sinks(cfg)
    stop = threading.Event()
    # Surface a bad key or unreachable cloud at startup rather than on the
    # first punch. Deliberately non-fatal: collecting attendance matters more
    # than forwarding it, and the outbox holds anything we can't send yet.
    for sink in sinks.values():
        if hasattr(sink, "ensure_ready"):
            sink.ensure_ready()
    worker = DeliveryWorker(cfg, store, sinks, stop)

    Handler.cfg = cfg
    Handler.store = store
    Handler.queue = CommandQueue()
    Handler.registry = DeviceRegistry()
    Handler.worker = worker
    Handler.started_at = time.monotonic()

    try:
        httpd = ThreadingHTTPServer((cfg.bind, cfg.port), Handler)
    except OSError as e:
        print(f"cannot listen on {cfg.bind}:{cfg.port}: {e}", file=sys.stderr)
        return 1
    httpd.daemon_threads = True

    def _shutdown(signum, _frame):
        LOG.info("signal %s received, shutting down", signal.Signals(signum).name)
        stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    worker.start()
    _banner(cfg)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        httpd.server_close()
        worker.join(timeout=10)
        LOG.info("stopped. %d delivered, %d failures this run.",
                 worker.delivered, worker.failed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
