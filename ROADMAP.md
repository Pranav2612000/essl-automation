# Roadmap: attendance punch → Infino cloud → good-morning Slack DM

**Goal.** When someone marks attendance on the eSSL terminal, push the punch to
Infino's hosted cloud. On a person's first check-in of the day, gather their
pending work from GitHub and Slack and DM them a good-morning summary.

**Shape agreed.** This server does the orchestration locally (it is not just an
ingest client). Messages are DMs to the person who punched in. Identity starts
in a local mapping file and moves to Infino cloud later.

**Status.** Phases 0–2 are done and tested — see `server.py`. Phase 3 onward is
not built.

---

## 1. Review of what exists

`adms.py`, `door_open.py`, and `caps.py` are good exploratory tools. They proved
the protocol works and they document the device's quirks well. None of them is a
service, and the gap is not cosmetic — most of the following would have caused
silent data loss the first week.

### Blocking for "push attendance to a cloud"

1. **No persistence.** A punch existed only as a line of stdout. A restart, a
   crash, or a full terminal buffer meant the record was gone with nothing to
   replay from.
2. **No idempotency.** The terminal re-uploads an entire ATTLOG batch whenever
   it dislikes our reply. With no dedup key, every retry becomes a duplicate
   record — and duplicate downstream messages.
3. **No place for outbound calls.** Putting an HTTPS POST inside the request
   handler couples the device's poll loop to the cloud's availability: a 10s
   cloud stall becomes a device timeout, which becomes a re-upload, which
   becomes duplicates. Delivery has to be asynchronous and durable.
4. **Timestamps have no timezone.** ATTLOG sends naive device-local time. Stored
   or forwarded as-is, it is unanchored: `09:14:22` in what zone? This also
   breaks "first punch of the day", which is a local-calendar concept.

### Correctness bugs present today

5. **Races on shared state.** `ThreadingHTTPServer` runs handlers concurrently,
   but `_queue`, `_cmd_id`, and `_last_seen` are mutated with no lock.
   `_cmd_id["n"] += 1` is a read-modify-write — two simultaneous requests can
   mint the same command id, and the device dedups by id, so one command is
   silently dropped.
6. **Single-device assumption.** `_known_serial["sn"]` is overwritten by
   whichever terminal polled last, so `/open` can unlock a different door than
   the operator intended once a second device exists.
7. **Unbounded body read.** `self.rfile.read(Content-Length)` trusts an
   attacker-controlled length on an unauthenticated endpoint — memory exhaustion
   from one request.
8. **`Stamp`/`OpStamp` hardcoded to 9999.** These are the protocol's high-water
   marks. Pinning them means the device offers everything it has every time;
   tolerable *because* we now dedup, but it is a real protocol shortcut and
   should be revisited (M2.6).

### Operational gaps

9. **`print()` for logging.** No levels, no rotation, no date, and a blocked
   stdout (piped to something that stopped reading) stalls a request thread.
10. **Lab endpoints in the blast radius.** `/sweep` queues seven door-unlock
    payloads, `/raw` sends arbitrary control frames, `/reboot` restarts the
    terminal. Correct for discovery, wrong to leave enabled in production.
11. **No health, no shutdown, no supervision.** Ctrl+C only; nothing to run
    under systemd; and — most important — no way to notice the terminal has
    stopped checking in. Silent failure here means missing attendance nobody
    hears about until payroll.
12. **No config validation.** A typo'd port raised a traceback; a missing token
    silently disabled control endpoints with no startup warning.
13. **No tests, despite "test files".** No captured ATTLOG fixture to parse
    against, so protocol changes were unverifiable.

### Standing constraints (not fixable, must be designed around)

14. **The device leg cannot be authenticated or encrypted.** The terminal has no
    way to present a credential and speaks plain HTTP. Anyone who can reach the
    port can forge punches — which, once phases 5–8 land, means they can trigger
    a DM to any employee. LAN-only is a load-bearing assumption, and it belongs
    in the threat model (M10.4), not in a footnote.
15. **Punch data is personal data.** PINs, timestamps, and movement patterns.
    Retention, log redaction, and who can read `/punches` are policy decisions,
    not defaults to inherit.

---

## 2. Milestones

Small enough that each is one sitting and independently verifiable. `[x]` is
built and tested; `[ ]` is not started.

### Phase 0 — Foundations
- [x] **M0.1** Typed config from env with fail-fast validation and
  `--check-config`.
- [x] **M0.2** `logging` with levels, rotating file handler, `ZK_REDACT_PINS`
  for PIN hashing.
- [x] **M0.3** Keep `adms.py` / `door_open.py` / `caps.py` as-is; production
  code lives in `server.py` so lab tools stay disposable.

### Phase 1 — Production server core (`server.py`)
- [x] **M1.1** Skeleton: config, logging, SIGTERM/SIGINT graceful shutdown,
  `/healthz`.
- [x] **M1.2** Device protocol: `cdata` GET handshake, `getrequest` poll,
  `cdata` POST uploads, `devicecmd` acks, `.aspx` variants.
- [x] **M1.3** Thread-safe `CommandQueue` (locked, monotonic ids) and
  `DeviceRegistry`.
- [x] **M1.4** Request hardening: body cap → 413, socket timeout, serial format
  screening, optional `ZK_ALLOWED_SERIALS` allowlist.
- [x] **M1.5** Multi-device targeting: `?sn=` required when more than one
  terminal is registered, rather than guessing.
- [x] **M1.6** `Punch` model + ATTLOG parser, tab-separated with a
  space-padded-firmware fallback; malformed lines logged, never fatal.
- [x] **M1.7** Timezone anchoring via `ZK_DEVICE_TZ`; store local string, UTC
  instant, and local calendar date.
- [x] **M1.8** Drop `/sweep`, `/caps*`, `/setopt`, `/param`, `/info`; gate
  `/raw` and `/reboot` behind `ZK_DEBUG_ENDPOINTS`.

### Phase 2 — Durability
- [x] **M2.1** SQLite schema (WAL, `synchronous=FULL`): `devices`, `punches`,
  `outbox`, `uploads`; thread-local connections.
- [x] **M2.2** Idempotent insert on `dedup_key` =
  sha256(serial|pin|local time|status).
- [x] **M2.3** Outbox rows written in the same transaction as the punch, one row
  per `(punch, sink)` — the seam every later sink plugs into.
- [x] **M2.4** `OK: <count>` sent only after commit; storage failure returns 500
  so the device keeps the record.
- [x] **M2.5** Delivery worker: exponential backoff with jitter, attempt cap,
  dead-letter, 4xx-vs-5xx retry classification.
- [ ] **M2.6** Real `Stamp`/`OpStamp` high-water marks per device instead of
  9999, so the terminal stops re-offering old records. Low priority — dedup
  makes it a bandwidth issue, not a correctness one.
- [ ] **M2.7** Retention job: purge `uploads` and delivered `outbox` rows older
  than N days; decide the `punches` retention period with whoever owns HR data.

### Phase 3 — Infino cloud sink
- [x] **M3.1** Contract established from https://infino.ai/docs. Infino Cloud is
  a retrieval engine, not an event bus:
  - `POST /v1/databases` `{"name"}` — 201, or 409 if it exists.
  - `POST /v1/create_table/{database}` `{"table_name", "schema", "indexes"?}`.
  - `POST /v1/append/{database}?table=…` `{"data": [row, …]}` — one append is
    one atomic commit; 404 if the table is missing.
  - Auth is `Authorization: Bearer inf_…` only; HTTPS required off localhost.
  - 503 with `Retry-After` on cold start, and the request provably did not run.
  - 5 MiB request cap (413); aim at 4 MiB.
  - **No idempotency mechanism** — see M3.6.
- [x] **M3.2** `InfinoSink`: bootstrap database + table, batched appends,
  `Retry-After` honoured, 404 triggers re-bootstrap, and a rejected batch is
  re-sent row by row so one bad record is dead-lettered instead of blocking the
  queue. `Punch.payload()` now matches `INFINO_TABLE_SCHEMA` column for column.
- [ ] **M3.3** Run it against the real tenant with a live key and confirm the
  rows are queryable via `/v1/query_sql`.
- [ ] **M3.6** **New, from M3.1.** Close the duplicate window: Infino has no
  idempotency key, so a response lost after a committed append means the retry
  writes the row twice. Before retrying a row whose previous failure was
  ambiguous (timeout / connection reset rather than a clean status), check
  `exact_match` on `event_id` and skip if it is already there. Until then, rows
  carry `event_id` and readers must dedup on it.
- [ ] **M3.4** Credential handling: env file permissions, rotation runbook,
  confirm the key never reaches a log line.
- [ ] **M3.5** Delivery SLO instrumentation: oldest pending age, dead count, and
  alerting when either crosses a threshold.
- [ ] **M3.7** Decide whether the attendance table wants an FTS or vector index.
  Today it has neither: every query we need is a SQL predicate. Revisit if
  phases 6–8 want retrieval over attendance history.

### Phase 4 — Identity directory
- [ ] **M4.1** `directory.yaml` (gitignored): `pin → {name, email, github_login,
  slack_user_id, timezone, active, greetings_enabled}`.
- [ ] **M4.2** Loader behind a `Directory` interface — not inline file reads —
  so M4.5 is a swap. Validate on load; reload on SIGHUP.
- [ ] **M4.3** Unknown PIN handling: record the punch, skip the greeting, count
  and alert. A new hire must never crash the server or lose attendance.
- [ ] **M4.4** PII policy: what goes in logs, what is hashed, who can call
  `/punches`.
- [ ] **M4.5** Move the directory to Infino cloud behind the same interface.

### Phase 5 — First-punch-of-day trigger
- [ ] **M5.1** Define it precisely: `status == check_in`, first row for
  `(pin, local_date)`, plus a cooldown so a double-tap at the reader doesn't
  double-fire.
- [ ] **M5.2** `greetings` table keyed `(pin, local_date)` — the idempotency
  guard that makes restarts and device re-uploads safe.
- [ ] **M5.3** Suppression rules: quiet hours, weekends, a holiday list, and
  `greetings_enabled=false`.
- [ ] **M5.4** Register a `greeting` sink so trigger evaluation runs on the
  worker, off the device's request path.
- [ ] **M5.5** `/greet?pin=…&dry_run=1` to render a message without sending —
  the thing you will actually use while building phases 6–8.

### Phase 6 — GitHub pending work
- [ ] **M6.1** Decide GitHub App vs PAT (App: per-org install, rotating tokens,
  no personal account coupling — likely right) and pin least-privilege scopes.
- [ ] **M6.2** Fetch per person: issues assigned, PRs authored and open, PRs
  awaiting their review, PRs with unresolved review threads.
- [ ] **M6.3** Normalise to a common `Task {source, title, url, age, urgency}`
  shape shared with Slack.
- [ ] **M6.4** Rank and truncate: top N, drafts last, staleness surfaced.
- [ ] **M6.5** Rate-limit budget and caching; degrade to a partial message on
  failure rather than sending nothing.

### Phase 7 — Slack pending work
- [ ] **M7.1** Slack app + manifest; scopes `chat:write`, `im:write`,
  `users:read`, `users:read.email`.
- [ ] **M7.2** **Resolve early:** `search.messages` requires a *user* token, not
  a bot token, and there is no bot-accessible "unread mentions" API. Realistic
  options are (a) a user token per person, (b) subscribe to `app_mention` /
  keyword events and maintain our own pending-mentions table, or (c) scope Slack
  down to saved items / reminders. This decision materially changes phases 7–8,
  so make it before building either.
- [ ] **M7.3** Implement the chosen source; normalise to the same `Task` shape.
- [ ] **M7.4** Thread-aware dedup so one conversation isn't five bullets.

### Phase 8 — The message
- [ ] **M8.1** Block Kit template: greeting, GitHub section, Slack section,
  empty state that reads as good news rather than an error.
- [ ] **M8.2** Renderer with golden tests (empty, one item, overflowing,
  partial-failure).
- [ ] **M8.3** Send via `conversations.open` + `chat.postMessage`, with retry,
  429 `Retry-After` handling, and graceful handling of deactivated users.
- [ ] **M8.4** Opt-out path and a footer saying where the data came from.
- [ ] **M8.5** Pilot with two or three volunteers before enabling org-wide.

### Phase 9 — Operations
- [ ] **M9.1** systemd unit: `Restart=always`, env file with `0600`, log
  rotation, non-root user.
- [ ] **M9.2** Device-silence alert: no contact in N minutes → page someone.
  This is the single most valuable alert in the system.
- [ ] **M9.3** Metrics endpoint and a small dashboard: punches/day, delivery
  lag, greetings sent, dead letters.
- [ ] **M9.4** SQLite backup on a schedule; verify a restore.
- [ ] **M9.5** Runbook: replay a day, reprocess dead letters, re-point the
  device, rotate credentials.

### Phase 10 — Verification
- [ ] **M10.1** Fake-device harness replaying captured requests as a committed
  test (the scripted smoke test used for phases 1–2, promoted into the repo).
- [ ] **M10.2** Unit tests for the ATTLOG parser against real captured bodies,
  including the space-padded variant and a DST boundary.
- [ ] **M10.3** End-to-end test: punch → outbox → stub cloud → stub Slack.
- [ ] **M10.4** Threat model doc: LAN-forged punches, greeting as an
  amplification vector, PII exposure through logs and `/punches`.
- [ ] **M10.5** Soak test: retry storm, 1000-record batch, cloud down for an
  hour then recovering.

---

## 3. Suggested order

M3.1 unblocks the actual goal, so get the Infino ingest spec first — everything
in phase 3 is one edit once it exists. M7.2 is the other decision with the power
to reshape work, so settle it early even though phase 7 is built late. Phase 4
and 5 are independent of both and can proceed immediately.

A reasonable first slice to something demoable: M3.1 → M3.2 → M4.1 → M4.2 →
M5.1 → M5.2 → M5.5 → M6.1 → M6.2 → M8.1 → M8.3, with Slack tasks (phase 7)
added after. That gives a real good-morning DM containing GitHub work, with
Slack items as a follow-up rather than a blocker.

## 4. Open questions

1. The Infino ingest contract (M3.1).
2. Slack: are we allowed per-user tokens, or do we build our own mention
   tracking (M7.2)?
3. Retention: how long do we keep punches, and who owns that decision?
4. Does the LAN carrying the terminal count as trusted, or do we need to treat
   forged punches as a live risk (M10.4)?
5. One terminal or several, now and in a year? It changes device targeting and
   the silence alert.
