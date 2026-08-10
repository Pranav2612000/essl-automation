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
15. **Punch data is personal data.** User IDs, timestamps, and movement
    patterns. Retention, log redaction, and who can read `/punches` are policy
    decisions, not defaults to inherit.

---

## 2. Milestones

Small enough that each is one sitting and independently verifiable. `[x]` is
built and tested; `[ ]` is not started.

### Phase 0 — Foundations
- [x] **M0.1** Typed config from env with fail-fast validation and
  `--check-config`.
- [x] **M0.2** `logging` with levels, rotating file handler, `ZK_REDACT_PINS`
  for user-ID hashing.
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
**Superseded by M2.8.** SQLite is gone: attendance is stored only in Infino,
and the terminal's own buffer is the retry queue. M2.1–M2.5 describe the
outbox that used to provide this; they are kept for the reasoning, not as a
description of the code.

- [x] **M2.8** **Remove SQLite.** No local database, no outbox, no delivery
  worker. A punch is acknowledged only once Infino accepts it, so refusing the
  upload is how a punch survives an outage — the device holds it and re-offers
  it. Greetings are claimed once per person per day against the `arrivals`
  table itself, which makes them survive a restart with no local state; a small
  in-process set covers the ~600 ms window before an append is visible to a
  query, which matters because this reader reports the same face twice one
  second apart. A row Infino permanently rejects is logged in full at ERROR and
  dropped, since there is no queue to park it in. `device_users` is a third
  Infino table. Trade accepted: the device's poll loop now depends on the cloud
  being reachable, and nothing personal is left at rest on this machine.
- [x] **M2.1** SQLite schema (WAL, `synchronous=FULL`): `devices`, `punches`,
  `outbox`, `uploads`; thread-local connections.
- [x] **M2.2** Idempotent insert on `dedup_key` =
  sha256(serial|user id|local time|status).
- [x] **M2.3** Outbox rows written in the same transaction as the punch, one row
  per `(punch, sink)` — the seam every later sink plugs into.
- [x] **M2.4** `OK: <count>` sent only after commit; storage failure returns 500
  so the device keeps the record.
- [x] **M2.5** Delivery worker: exponential backoff with jitter, attempt cap,
  dead-letter, 4xx-vs-5xx retry classification.
- [ ] **M2.6** Real `Stamp`/`OpStamp` high-water marks per device instead of
  9999, so the terminal stops re-offering old records. Low priority — dedup
  makes it a bandwidth issue, not a correctness one.
- [x] **M2.7** Retention job — **moot**: nothing is stored locally to purge.
  Retention is now an Infino-side decision, still to be agreed with whoever
  owns HR data.

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
- [x] **M3.8** **Arrivals sink.** A second Infino table, `arrivals`, one row per
  announced arrival with `person_name` / `slack_id` / `github_id` denormalised
  onto it and `event_id` joining back to `attendance`. Identity is copied, not
  referenced, because a point-in-time record — who someone was when they
  arrived — is the correct answer for an attendance row, and a dimension table
  would need a latest-row-wins join on every read. (Infino does expose
  `/v1/update`, so a dimension table was possible; it was not the right shape.) Unmapped
  users still get a row (`identity_source='unmapped'`). Same `InfinoSink` class
  parameterised by table and schema, so retry, batching, bootstrap and
  dead-lettering are shared. `log_arrivals` is the dry-run twin. Verified
  against a stub that rejects unknown columns: two tables created, batches
  never mixed across sinks, and a cloud outage left arrivals pending and
  delivered them on recovery.
- [x] **M3.3** Run against the real tenant. Both tables bootstrapped and
  appended on the first attempt, and both are queryable. The read contract,
  which M3.1 never captured:
  - `POST /v1/query_sql/{database}` `{"query": "…"}` — database is a path
    segment, and the only body field is `query`.
  - Send `Accept: application/json` or the response is an Arrow IPC stream,
    which would mean a pyarrow dependency to read our own attendance.
  - The body is a plain array of row objects: `[{"col": value}, …]`.
  - **A NULL column is omitted from the row object entirely**, not returned as
    null — every read goes through `.get()`.
  - SQL is read-only, Apache DataFusion, Postgres-leaning: CTEs, JOINs,
    GROUP BY with aggregates, window functions, ORDER BY, LIMIT.
  - **No bind parameters.** Filter values are screened against a strict
    charset and rejected, then quoted — never escaped into the query.
  - 400 bad body, 401 bad key, 503 with `Retry-After` while workers activate.
- [x] **M3.9** `/attendance` reads Infino, not SQLite: one row per person per
  day (first seen, last seen, punch count, minutes on site), identity joined
  from the `arrivals` table so the answer does not shift when directory.json
  is edited. Dedups on `event_id` per M3.6. Reports `pending_delivery` from
  the local outbox so a caller can tell "nobody came in" from "nothing has
  shipped yet", and returns 502/503 rather than silently falling back to the
  buffer.
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

**Naming.** The device sends this identifier as `PIN`, but it is the User ID
shown when enrolling someone — not a secret. (A per-user password exists as a
separate `Passwd` field, which this server never stores.) `PIN` is therefore
kept only in the ATTLOG/USERINFO parser and the comments describing the wire
format; everything above that layer says `user_id`: the SQLite columns, the
`/users` and `/punches` output, the directory file keys, and the Infino column
`employee_user_id`. Done before the Infino table had real rows and before the
directory file was written, when it was still free. `ZK_REDACT_PINS` keeps its
name so existing configs are not broken. Dedup keys hash the *value*, so
renaming changed no `event_id`; older databases are migrated in place on
startup.

- [x] **M4.0** One-off device roster sync. `/users/sync` queues
  `DATA QUERY USERINFO` at the terminal; `USER` records are harvested from
  whatever upload the reply arrives on (firmware disagrees on the table), kept
  in `device_users`, and read back from `/users`. This is run by hand to seed
  M4.1 — it is not a live mirror of the device, so a person enrolled after the
  sync stays unknown until it is run again. Biometric templates and `Passwd`
  are stripped before anything is logged or stored; only the fact that a
  password is set is kept.
- [x] **M4.1** `directory.json` (gitignored): `user_id → {name, slack, github}`,
  built by hand from the M4.0 dump, at `ZK_DIRECTORY_FILE`. Accepts either a
  user-ID-keyed object or a list; `_`-prefixed keys are notes, since JSON has
  no comments. `directory.example.json` is the template. Supersedes the YAML
  sketch below — the extra fields there are added when something needs them.
- [ ] **M4.1a** `directory.yaml` (gitignored): `user_id → {name, email,
  github_login, slack_user_id, timezone, active, greetings_enabled}`.
- [x] **M4.2** Loader behind a `Directory` interface — not inline file reads —
  so M4.5 is a swap. Validated at startup, so `--check-config` catches a bad
  file; errors name the offending user ID. Reload on SIGHUP is **not** done: a
  restart is currently the way to pick up an edit.
- [x] **M4.3** Unknown user-ID handling: the punch is recorded exactly as before
  and a warning names the file to add the person to. Counting and alerting on
  the rate is still open.
- [ ] **M4.4** PII policy: what goes in logs, what is hashed, who can call
  `/punches`.
- [ ] **M4.5** Move the directory to Infino cloud behind the same interface.

### Phase 5 — First-punch-of-day trigger
An arrival line already prints on every new punch that is not a departure
(`"<name> entered office. slack: … github: …"`), which is the shape the DM
will take, debounced 60s in memory against a double-reading reader. What phase
5 adds is *when*: once per person per day, durably, and off the request path.

**Observed on the real terminal (NYU7261200921):** every punch arrives with
`status=255` and `verify=15` — the attendance-state feature is off, so the
device reports no direction at all. `status == check_in` is therefore *not* a
usable trigger here; M5.1 must key off the first punch of the day rather than
a direction. The same reader also produced two punches one second apart for a
single face match, which is why the cooldown below is not optional.

- [x] **M5.1** Defined and built: not a departure, first row for
  `(user_id, local_date)`, plus a cooldown so a double-tap at the reader
  doesn't double-fire.
- [x] **M5.2** Done as part of M2.8: the `arrivals` table *is* the ledger,
  one row per `(user_id, local_date)`, so restarts and device re-uploads are
  safe with no local state.
- [ ] **M5.3** Suppression rules: quiet hours, weekends, a holiday list, and
  `greetings_enabled=false`.
- [ ] **M5.4** Register a `greeting` sink so trigger evaluation runs on the
  worker, off the device's request path.
- [ ] **M5.5** `/greet?user_id=…&dry_run=1` to render a message without sending —
  the thing you will actually use while building phases 6–8.

### Phase 6 — GitHub pending work
- [~] **M6.1** PAT for now, via `ZK_GITHUB_TOKEN`. A GitHub App is still the
  right end state, but App auth signs a JWT with **RS256**, which the standard
  library cannot do — adopting it means taking a crypto dependency on a
  stdlib-only project. Decide that trade before org-wide rollout; a PAT is one
  person's credential and sees only what they can see.
- [~] **M6.2** PRs awaiting their review: done, via
  `/search/issues?q=is:open is:pr archived:false draft:false
  review-requested:<login>`, oldest first. Issues assigned, PRs authored, and
  unresolved review threads are still open.
- [ ] **M6.3** Normalise to a common `Task {source, title, url, age, urgency}`
  shape shared with Slack.
- [x] **M6.4** Oldest first, capped at `ZK_GITHUB_MAX_ITEMS` (5), age shown
  per PR. Drafts are excluded rather than ranked last — nobody can act on one.
- [x] **M6.5** Degrades to a partial message: a GitHub failure leaves the
  greeting intact and says the queue could not be fetched, rather than
  implying it is empty. Search allows 30 requests a minute and one arrival is
  one request, so the budget only binds if something else shares the token.
  Caching is not needed at this volume.

### Phase 7 — Slack pending work
- [x] **M7.1** Slack app needs **only `chat:write`**. `chat.postMessage`
  accepts a user ID as its `channel` and opens the DM itself, so
  `conversations.open` — and the `im:write` scope it requires — is not needed.
  The `users:read*` scopes would only matter if we resolved emails to IDs,
  which the hand-maintained directory avoids.
- [ ] **M7.2** **Resolve early:** `search.messages` requires a *user* token, not
  a bot token, and there is no bot-accessible "unread mentions" API. Realistic
  options are (a) a user token per person, (b) subscribe to `app_mention` /
  keyword events and maintain our own pending-mentions table, or (c) scope Slack
  down to saved items / reminders. This decision materially changes phases 7–8,
  so make it before building either.
- [ ] **M7.3** Implement the chosen source; normalise to the same `Task` shape.
- [ ] **M7.4** Thread-aware dedup so one conversation isn't five bullets.

### Phase 8 — The message
- [x] **M8.1** Block Kit template: greeting + context footer saying where the
  message came from. The GitHub and Slack sections are the gap phases 6-7
  fill; the empty state is currently the whole message.
- [ ] **M8.2** Renderer with golden tests (empty, one item, overflowing,
  partial-failure).
- [x] **M8.3** Sent via `conversations.open` (channel cached) + 
  `chat.postMessage`. Slack signals failure with HTTP 200 and `ok:false`, so
  every response is inspected; 429 gets one retry on its own `Retry-After`;
  `user_not_found` / `account_inactive` / `missing_scope` and friends are
  permanent and not retried. A failure never affects the punch.
- [ ] **M8.4** Opt-out path and a footer saying where the data came from.
- [ ] **M8.5** Pilot with two or three volunteers before enabling org-wide.
  `ZK_SLACK_ALLOW` is the gate; an empty value means everyone and warns at
  startup. **Not yet run against real Slack — no token has been issued.**

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
