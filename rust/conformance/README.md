# API conformance harness

`silo-conformance` replays one request plan against a reference server and a
candidate server, diffs every answer, and reports parity per surface. It exists to
keep a reimplementation wire compatible with the Go server: a route counts as
matched only when the candidate served it itself and answered the same.

Commands assume the repository root is the cwd. Paths passed to `self-compare.sh`
are relative to the repository root.

## Run

```sh
rust/conformance/scripts/self-compare.sh --up-only     # both Go stacks
cargo build --release --manifest-path rust/Cargo.toml
rust/target/release/silo-conformance list                # routes and cases, sends nothing
rust/conformance/scripts/self-compare.sh \
  --baseline rust/conformance/baseline/expected-v2.json   # Go vs Go, gate on regressions
```

Against another candidate:

```sh
rust/target/release/silo-conformance run \
  --reference http://127.0.0.1:28080 --candidate http://127.0.0.1:18080 \
  --surface jellycompat=http://127.0.0.1:28096,http://127.0.0.1:18096 \
  --surface abs=http://127.0.0.1:28378,http://127.0.0.1:18378 \
  --reset-reference 'rust/conformance/scripts/reset.sh --fast' \
  --reset-candidate '<command that restores the candidate database>' \
  --baseline rust/conformance/baseline/expected.json
```

## Scope

`--scope v2` plans and scores only the native API that 1.0 locks: `api_v2`, `api_v2_walked`, `root`, and
`api_delegate`. It drops the `api_v1`, `jellycompat`, `abs`, `metrics`, debug, node, and peer cases, except
seed cases, which rebuild the state every stage reads, and any case that captures a fact a kept case uses.
Parity, surface counts, and baseline comparison then cover those four surfaces only. `self-compare.sh`,
`front-compare.sh`, and `mutation-test.sh` default to `--scope v2`; pass `--scope full` for every surface.
The binary itself defaults to `full`. A baseline records its scope, and a run against a baseline of another
scope stops before sending anything. `list --scope v2` prints the scoped plan.

## Speed

The scripts build `rust/` in release mode (`CONF_PROFILE=debug` switches back) and run
`rust/target/release/...`.

The plan runs in units. The reads and rejections stage is cut into eight units of similar expected time (a write
case counts six reads), only between routes and never between a case that captures a fact and a later case
that uses it; each write stage is one unit. Every unit
starts from a reset of both stacks and a replay of the seed cases, and per-side facts, created ids, and id
aliases start empty, so units do not depend on each other. One lane runs them in order. `--lane FILE`
(repeatable) adds another independent stack pair, described as JSON with `reference`, `candidate`,
`surfaces`, the reset, empty-users, and effects commands, and `origin_log`; units then run on all lanes at
once, largest first, and the results merge back in plan order, so a report reads the same for any lane count.
Peer cases run on lane 0. Events carry `elapsed_ms`, and a `unit_done` event gives each unit's time.

`CONF_LANES=N` makes `self-compare.sh` and `front-compare.sh` bring up pairs `CONF_PAIR` to
`CONF_PAIR+N-1` (with `scripts/lane-up.sh`, which also starts a front per pair for `front-compare.sh`) and
pass them as lanes. A pair's first start seeds it from scratch, which takes a few minutes. `CONF_ACTIVITY_DIR`
and `CONF_FRONT_AFTER` need one lane.

A v2 run took 1891 s before this (full plan, debug build, one stack pair) and about 445 s of run time on three
lanes in release mode (about 500 s with lane startup), on a laptop whose Docker has 4 CPUs.

The local client that sweeps new listeners (`conf_wait_listener_sweep`) also sweeps every listening port on the
host now and then, Go vs Go included. Through a front, the candidate's Go gets those requests twice (on its own
port and through the front), so a sweep that lands inside a unit shows as `stage_effect_differs` on
`jellycompat request GET / 302` and `GET /web/ 404` rows, and the run needs repeating. One of the two
three-lane front runs here met it.

## Stack pairs

`CONF_PAIR=N` (0 to 9) moves a whole pair: the reference becomes compose project `silo-conformance-pN`, the
candidate `silo-conformance-pN-b`, every host port (both stacks, the front's listeners in `front-compare.sh`, and
the mutation proxy's) moves up by `10*N`, and run state and reports go to `.run/pairN/`. Pair 0 is the default
layout: projects `silo-conformance` and `silo-conformance-b`, ports 25432-29090 and 35432-39090, the front on
18080-19090, the proxy on 48080-49090. Each of `CONF_PROJECT`, `CONF_B_PROJECT`, `CONF_*_PORT`,
`CONF_B_*_PORT`, `CONF_FRONT_*_PORT`, and `CONF_MUT_*_PORT` still overrides its pair default (see
`scripts/lib.sh`).

```sh
CONF_PAIR=1 rust/conformance/scripts/self-compare.sh --up-only
CONF_PAIR=1 rust/conformance/scripts/front-compare.sh --baseline rust/conformance/baseline/expected-v2.json
CONF_PAIR=2 rust/conformance/scripts/mutation-test.sh --baseline rust/conformance/baseline/expected-v2.json none
```

A pair takes about 0.8 GB of memory in Docker. Every stack publishes on `127.0.0.1` only, and the scripts
reach it there, so a pair on another host runs with the whole harness on that host: check out the repository
there, build with `cargo`, and run the same commands. Give the stacks there a project name of their own
(`CONF_PAIR` does that) so they cannot touch anything else running on the host, cap their CPU with Docker if
the host serves other work, and remove them with `docker compose -p <project> down -v` when done. The image
builds from the checkout, so both hosts compare the same Go source only when they hold the same commit.

Run output goes to `--out` (default `rust/conformance/.run/report`): `report.json`,
`cases.jsonl` (every case with its differences) and `summary.txt`. The exit code is
1 on any regression, 2 on a harness failure, otherwise 0.

## How a route is scored

| State | Meaning |
|---|---|
| `matched` | No difference in any case, no case proxied, and at least one case got a success whose body was compared in full. |
| `weak_evidence` | No difference, but no such success. Not matched. |
| `differs` | A case differed in a way no recorded flake explains. |
| `known_flake` | Only differences recorded in the baseline's `known_flakes`. Not matched. |
| `not_ported` | The candidate proxied at least one case to Go. Not matched, whatever it returned. |
| `not_exercised` | No case reached it on both servers. Not matched. |

Parity is `matched / total`, with the total taken from the sources, so a route nothing
reached or only refused lowers it. A server pair that answers everything with the same
401 reads 0% (`mutation-test.sh refuse_401`).

A route is `weak_evidence` when two servers agree but the handler's work was never
compared: it only got refusals, validation errors or 5xx, or its only success was a stream,
an oversized or skipped body, or a feed. `weak_reason` on the route says which, and the
`refusals` column counts the routes that never got past a 401, 403, 404 or 405. A CORS
preflight and a slash variant do not count as a success, because middleware and the router
answer those, not the handler.

The Rust front never marks a response, because a marker would change the header set being
compared. It writes an origin log instead (`SILO_FRONT_ORIGIN_LOG`), one JSON line per request
before answering it, and `--origin-log` reads it. A case counts as native only if lines exist for
it and every one says `native`. A candidate that cannot write a log may mark proxied answers with
the `X-Silo-Strangler-Upstream` response header (`--proxied-header` changes the name) instead; any
value counts.

Against the front, with a second Go stack behind it:

```sh
cargo build --release --manifest-path rust/Cargo.toml -p silo-server -p silo-conformance
DATABASE_URL='postgres://silo:silo@127.0.0.1:35432/silo?sslmode=disable' \
SILO_FRONT_WEB_DIST=rust/conformance/baseline/web-dist \
SILO_FRONT_ORIGIN_LOG=rust/conformance/.run/origin.jsonl \
rust/target/release/silo \
  --front main=127.0.0.1:18080,http://127.0.0.1:38080 \
  --front jellycompat=127.0.0.1:18096,http://127.0.0.1:38096 \
  --front abs=127.0.0.1:18378,http://127.0.0.1:38378 \
  --front metrics=127.0.0.1:19090,http://127.0.0.1:39090 &
rust/target/release/silo-conformance run \
  --reference http://127.0.0.1:28080 --candidate http://127.0.0.1:18080 \
  --surface jellycompat=http://127.0.0.1:28096,http://127.0.0.1:18096 \
  --surface abs=http://127.0.0.1:28378,http://127.0.0.1:18378 \
  --surface metrics=http://127.0.0.1:29090,http://127.0.0.1:19090 \
  --origin-log rust/conformance/.run/origin.jsonl \
  --candidate-kind strangler \
  --reset-reference 'rust/conformance/scripts/reset.sh --fast' \
  --reset-candidate '<reset for the second stack>'
```

The front outlives each reset of its stack, and two of its writers run on their own clocks: the machine ID lease
renewal, which claims again in the restored table, and log batch retries for inserts that failed while the database
was gone. `front-compare.sh` therefore passes `CONF_DIGEST_SKIP='idgen_machine_leases|operational_logs'` to the
candidate's `reset.sh`, which leaves those tables out of the seed digest check.

`SILO_FRONT_FORCE_GO=all` sends every native row to Go too, which is the proxy-all run: every route
is then `not_ported`, and any difference at all is the front's.

`scripts/native-chain-traits.sh` (run as `CONF_FRONT_AFTER`) and `scripts/native-chain-isolation.sh` cover
what a request plan cannot: non-UTF-8 headers, policy and settings reloads, the decision log, the live tail,
and the deployments whose credentialed rows stay on Go.

`baseline/web-dist` is the stub frontend the baseline image embeds. `scripts/front-compare.sh` runs
all of the above, with `--proxy-all` for the proxy-all run.

`CONF_ACTIVITY_DIR=<dir>` makes `front-compare.sh` also save each stage's `activity_log` rows, grouped by method,
route pattern, path, status, accounts, and audit action, and write `diff.txt` with `scripts/activity-diff.py`. The
differ reads those rows only as feeds, so this is what shows a wrong route pattern or a request logged twice. Two
differences here are not the front's: rows dropped with a batch when a first-run setup case removes the users they
name, which Go's batch writer does too, and `GET /` rows from a local process on the host that probes new listeners.

## Effects

`--effects-reference` and `--effects-candidate` take `pg=URL,redis=HOST:PORT` for each side, and `self-compare.sh`,
`front-compare.sh`, and `mutation-test.sh` pass them. After each reset the harness puts a trigger on every table, which
records row changes in the separate schema `conformance_fx`, and it subscribes to `silo:*` on Redis. After each write
case it compares the rows touched and the events published, so a difference is reported at `effect.<table>.<op>` or
`effect.event.<type>`, and it lowers the route like any other difference. Values are masked by format (IDs, clocks,
hashes, tokens). A write whose only success is an empty body that changed nothing is `weak_evidence`, not `matched`.

`operational_logs` rows and live tail rows are batched, so they are compared at the end of each stage, counted by what
names them. A difference is a `stage_effect_differs` regression, and it appears in `stage_effects` in `report.json`.
The feed rules on the log routes stay, because a log's contents depend on timing between two Go servers.
`front-compare.sh` waits out a local client's one-time sweep of each new listener before the first reset (`conf_wait_listener_sweep`), so those requests never reach the counts.

`baseline/effects.json` lists the tables, events, fields, and log messages that differ between two Go servers, each
with its evidence. An entry needs a Go vs Go run that shows it. `mutation-test.sh wrong_write` proves the check: the
proxy changes one value in each candidate write, so a 204 with the wrong row stored has to be reported.

## Peer lab

The baseline's socat edge makes every client one private, trusted address, on both sides. A run through
it cannot see what a relay does to the peer trust decision, and it gives the two Go servers different
client addresses: the edge's on the reference, `127.0.0.1` through the front. `front-compare.sh`
evens out the second problem without a front on the reference: `--reference-forwarded-for 127.0.0.1`
sends the reference the header the front sends the candidate's Go, so both servers file the client
under one address, and the `client-address` normalizer is dropped.

`scripts/peer-lab.sh` removes both problems:

```sh
rust/conformance/scripts/self-compare.sh --up-only
rust/conformance/scripts/peer-lab.sh build    # the Linux front, built in a container
rust/conformance/scripts/peer-lab.sh up
rust/conformance/scripts/peer-lab.sh compare --proxy-all --from trusted_a \
  --baseline rust/conformance/baseline/expected.json
rust/conformance/scripts/peer-lab.sh compare --from untrusted_a \
  --baseline rust/conformance/baseline/expected.json
rust/conformance/scripts/peer-lab.sh compare --go --from trusted_a   # Go vs Go, same topology
rust/conformance/scripts/peer-lab.sh down
```

Each client is a socat container with its own address, on a network both stacks share, and the front
runs in the candidate Go server's network namespace, so it reaches Go on loopback from a per-client
`127/8` source. That is the deployment the front is designed for, and it needs Linux: macOS cannot bind
those sources. `203.0.113.0/24` is outside the default trusted list and `10.77.0.0/24` is inside it.
`--from` picks the client the whole plan runs from. Options the script takes come before any it passes
to `silo-conformance run`.

`--sources` gives the harness the clients, which also enables the `Peers` phase, the last stage of a
run. Those cases are in `plan.rs` and name a client each:

| Name | What it compares |
|---|---|
| `origin:*` | `request_origin` with forwarded host and scheme, which only a trusted peer may set. |
| `client:*` | `SessionInfo.RemoteEndPoint` for each branch of `resolver.resolve`, from both kinds of peer. |
| `activity:*` | The address the activity log files a request under, read from `admin/ips`. |
| `auth_limit:*` | A per-client budget that new forwarded names cannot refill, and one trusted peer's budget running out without touching another's. |
| `abs_limit:*` | The Audiobookshelf login limiter, which keys on the peer alone. |
| `grant:*` | Which address and path may use a Jellyfin stream grant without a credential. |
| `base_url:*` | The speed test URL, whose code reads forwarding headers and Host directly. |
| `native:*` | Rows the front answers itself, with spoofed forwarding headers. |

A run without `--sources` does not send them. They are not in `baseline/expected.json`, which comes from
a run without the lab, so a change in them shows only as a difference in that run, not as a regression
against the recording.

Both servers see the same client address here, so a run with `--sources` drops the `client-address`
normalizer and compares those values exactly.

`--pace-ms` slows a run. Some Go state depends on how fast requests arrive, so a difference that shows
only through a slower candidate needs a Go vs Go run at that pace before anything may excuse it.

These peer cases differ through the front, on purpose or because Go has to change. See
`crates/silo-front/README.md`:

- `grant:proxy_claiming_direct_client`: a trusted peer naming a directly connected client's address gets
  that client's stream grant. Go tells a direct client from a proxied one by comparing its peer with its
  client address, and through the front those always differ.
- `base_url:ip_host_forwarded_host`, `base_url:proto`, and in a run from an untrusted client
  `plugin_launch.secure_flag`: Go's raw `X-Forwarded-Host` and `X-Forwarded-Proto` readers believe an
  untrusted client, and the front strips those headers because `clientip` would otherwise believe them too.
  The same is true of `forwardedHost`'s other raw reader, `checkWebSocketOrigin`'s same-origin fallback
  for a WebSocket upgrade (`internal/api/handlers/ws_shared.go`), but no case here exercises it yet: it
  needs a valid events-ws ticket, and this lab needs Linux to run at all.

## What is compared

- Status.
- Every response header, by value, except:
  - `Connection`, `Content-Length`, `Date`, `Keep-Alive` and `Transfer-Encoding`, which
    describe the connection. A HEAD answer's `Content-Length` is compared.
  - `Expires`, `Last-Modified`, `Retry-After`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
    and `X-Request-ID`, compared by presence because their values change on every answer.
  - `Set-Cookie`, compared without its value. `Allow`, compared as a set, because Go
    builds it from a map.
- ETag as behaviour: presence, weak or strong, quoting, and the status of a replay with
  `If-None-Match`. Two implementations may hash differently.
- JSON bodies by structure: key presence, JSON type, array length and order, value.
  Integer and float forms of the same number differ, and so does a key sent twice.
- Other bodies as bytes. When both sides are cut off, by a stream or the 8 MiB limit, the
  body is not compared and the case records why. When only one side is cut off, that is a
  difference.

Every request carries the same fixed `Host`, so URLs derived from it cannot differ just
because the servers listen on different ports.

## Request plan

Sources: `contracts/api/v2/openapi.json` (the `api_v2` surface), `route-inventory.json`
(`api_v1`, `api_delegate`, `root`, `metrics`, `debug`, `proxy_node`, `transcode_node`),
`internal/api/testdata/media_routes.txt` for what those two omit (`api_v2_walked`: raw plugin and
artwork routes), the route manifests of the Jellyfin and Audiobookshelf routers plus routes mentioned
in `docs/jellycompat-api.md`, the few rows only router source shows (`WIRED_*` in `sources.rs`), and
contract fixtures and scenarios where the seed supports
their principals and placeholders. `list` prints what was skipped and why.

This universe equals the front's row table, as `tests/contracts.rs` checks. Doc mentions that are not
routes, such as `/Items/{id}/Images/Thumb`, are in `sources::DOC_ILLUSTRATIONS` with a reason, are out
of the denominator, and still run as `doc_example:*` cases of the route they illustrate. An `ALL` row
is a mount that takes any method, and its cases send `GET`.

Each route gets anonymous, normal-user and admin cases where sensible, a CORS preflight,
and invalid input: an unknown path id, an invalid typed query parameter, a malformed
JSON body and a wrong-shape JSON body. Reads repeat after the writes of their stage
(`after_writes`), so objects that did not exist on the seed are read back and a write
that stored the wrong thing shows up.

Two kinds of case exist because no source lists them. `slash_variant` sends each route with
its trailing slash toggled. `auth_variant:*` authenticates with one spelling of a credential
and no other: every spelling the Jellyfin server accepts on `/Users/Me`, one per other
Jellyfin read in turn, and lower- and upper-case `Bearer` on the native and Audiobookshelf
APIs.

The order is a pure function of the sources, and within a lane cases run one at a time, so
both servers stay in step (see Speed for units and lanes):

1. Create the objects later routes need (`seed`).
2. Reads, on the seed.
3. Writes that should be refused, which should change nothing.
4. Real writes in stages (v2, v1, v1 scenarios, compatibility), each from a reset database
   (reads and rejections are eight such units too):
   creates, then updates, then deletes, children before parents.

Ids a server generates stay on that server: path parameters and bodies are filled per
side. After a write that succeeded, credentials are probed on both sides. A lost login
session means logging in again; a lost API key or dead server triggers a reset, recorded
in the report's `events`. `plan.rs` lists the routes with no privileged case at all,
because they would disrupt the run.

## Normalizers

`baseline/normalizers.json` lists every volatile value the tool tolerates. A rule names
a route regex, a JSON path or header, and a value format, and it applies only when both
sides' values have that format. Type and presence are compared before a rule is
consulted, so no rule can hide a missing key or a changed type. There is no way to ignore
a field. The report lists each rule with its hit count. A rule that never hits across
several runs should be removed; a few only hit on a race, such as an hourly signature
bucket rolling over between the two requests.

Formats check more than shape where a client could notice:

| Format | Also requires |
|---|---|
| `uuid` | Same letter case and same version on both sides. |
| `jwt` | Decodes on both sides, with the same header, the same claim names, and lifetimes within 60 seconds. |
| `rfc3339_run_time`, `rfc3339_near` | Same separator, offset, and presence of a fraction. `rfc3339_run_time` also needs both values from this run and within its skew limit. Digit counts are not compared, because Go trims trailing zeros. |
| `regex` | Each capture group the same length on both sides, unless the rule sets `any_length`. |
| `hex` | Same length. |
| `unordered_array` | Same items, and only where the parent object has the named sibling value: `section_type` is `random`. |
| `any_number` | Same sign. |
| `array_of_objects` | Both empty or both not, required keys of the same JSON types, and no key that every entry on one side has and no entry on the other does. The job feeds set `keys_vary` to drop that last check, because a job gains keys as it runs. |

A rule marked `alias` remembers the pair. If either value was already paired with something
else, or the request named an id and the answer is not the id that side's request named, it
is a difference. An id captured from a create is only excused when both sides' ids have the
same shape.

Seven rules are feed rules (`array_of_objects`): admin logs, audit, policy decisions,
sessions, jobs and the catalog import listing record the comparison's own activity, so their
length and contents depend on timing. Inside a feed nothing else is compared. A success that
was only a feed makes the route `weak_evidence`.

`tests/normalizers.rs` drives every rule through the differ with the pair it excuses and
values it must not excuse. A new rule needs a row there.

## Testing the differ

`scripts/mutation-test.sh` runs the whole plan with `conformance-mutproxy` in front of the
candidate, once per fault. The proxy changes one thing in each response, for example dropping
a field or changing a status, and logs it. `check` then confirms that the same case reported a
difference at that place.

```sh
rust/conformance/scripts/self-compare.sh --up-only
rust/conformance/scripts/mutation-test.sh --baseline rust/conformance/baseline/expected-v2.json \
  none reserialize refuse_401 drop_field rule_out_of_format rule_in_format
```

Results go to `.run/mutation/<fault>/` as `check.txt` and `check.json`. The proxy's listeners are new, so each run
first waits out a local client's one-time sweep of them, which would otherwise land in the candidate's stage counts.
`CONF_PROJECT`, `CONF_B_PROJECT`, `CONF_B_RUN`, the `CONF_*_PORT` and `CONF_B_*_PORT` variables, and
`CONF_MUT_*_PORT` put a run on its own pair of stacks, so faults can be split across pairs. Each run takes about
half an hour on one pair. Pairs running at once disturb each other: a few requests per run then fail at the
transport level on both sides, and a fault applied to such a case counts as escaped although the differ never saw
it. Rerun a fault alone when its only escapes are such cases (`body_skip_reason` in `cases.jsonl`), and run `none`
and `reserialize` alone. `none` and
`reserialize` are controls and must report nothing. `all` applies a different fault per case
in one run, which is the quick way to try all of them. `rule_out_of_format` and
`rule_in_format` change every value a normalizer covers. A value a rule is meant to accept,
such as any non-negative gauge, is counted under `by_design` for that rule rather than as an
escape, so that column is the list of what the rules still allow.

A feed rule only compares a feed with the other side's, so a fault that leaves the candidate's feed
holding what the reference's already holds cannot show: emptied against an empty feed, a key dropped
that not every reference entry has, a key retyped that is never non-null there. Each case records its
reference feed, and these count under `reference_matches_fault`, not as escapes.

The proxy only touches requests carrying the runner's `--tag-cases` header, so logins and
liveness probes stay honest and each fault maps to one case.

## Multi-request flows

`src/auth_flows.rs` adds cases that use what an earlier answer gave each side (`Case.capture_facts`), so sign-in
rows reach a success and read-after-write through Go-served rows is compared. A case with `needs_empty_users`
runs `scripts/empty-users.sh` on both stacks first, for first-run setup, and the next stage's reset restores the
seed. Facts named `flow_*` survive the liveness check's fresh login.

## Baselines

`baseline/expected-v2.json` (scope `v2`) and `baseline/expected.json` (scope `full`) are recorded from Go vs
Go over several runs:

```sh
CONF_LANES=3 rust/conformance/scripts/self-compare.sh --runs 3 \
  --record-baseline rust/conformance/baseline/expected-v2.json
rust/conformance/scripts/self-compare.sh --scope full --runs 3 \
  --record-baseline rust/conformance/baseline/expected.json
```

Any case that differed in any run goes in `known_flakes` with the difference signatures
it may show. Anything else on that case is still a difference. The file also stores what
the reference answered on each case, so a changed reference shows up as `reference_drift`
rather than silently changing what is being compared.

`baseline/known-flakes.json` lists, with a reason, the races too rare for a recording to
reliably catch. It merges into any baseline at load time and allows only the signatures it
names.

Regression kinds: `route_differs`, `evidence_lost`, `coverage_lost`, `case_lost`,
`reference_drift`, `route_removed`, `proxy_not_transparent`, and, against a baseline
recorded with `--candidate-kind strangler`, `ported_route_now_proxied`.

Without `--baseline`, a run reports differing routes in its summary but exits 0, so a gate
must pass one.

Re-record after changing the seed, the plan, or the Go server on purpose.

## Known gaps

These lower what a green result proves. Parity counts the first group as not matched.

- `debug`, `proxy_node` and `transcode_node` are not exercised: the baseline has no such
  listeners reachable. The debug listener is loopback-only and checks `Host`; the node
  surfaces need separate server modes and node credentials.
- Playback is shallow. `POST /api/v2/playback/start` answers on the seed without opening a
  session, so `/stream`, HLS and `/playback/{session_id}` routes only get their error
  cases, and Range requests are not sent.
- The seed has no audiobook, ebook or podcast library, so most `abs` routes and the
  ebook routes only compare not-found and refusal bodies.
- The baseline is offline with no plugins, so metadata providers, plugin installation,
  request integrations and OAuth flows stop early.
- WebSocket routes are sent as plain HTTP; no upgrade happens.
- HTTPS and response compression are not exercised: the client neither speaks TLS nor
  sends `Accept-Encoding`.
- Activity log rows are only visible through feeds and `admin/ips`, so a route that stops writing one
  shows nowhere unless it carries a user. `native-chain-traits.sh` reads the rows, the decision log, and
  the live tail for the native rows.
- `reset.sh --fast` restores Postgres and Redis only. Files the run writes to the data
  volume, such as catalog exports, survive into later runs.
- Generated request bodies fill required fields only, so optional-field behaviour is only
  reached through fixtures and scenarios.
- Metrics and debug bodies are not compared, so those routes are `weak_evidence` at best. A
  dropped or renamed metric goes unnoticed.
- A bandwidth probe's body is compared by length only, because the filler is random.
- `/api/v2/.../trailers/refresh` and the export routes stay `known_flake`: a change to their
  flaky fields is not reported as a regression.
- A generated id on a create is accepted if it has the right shape: nothing can say which
  fresh id a server should have picked. A cursor's contents and a gauge's value within its
  sign are also accepted.
