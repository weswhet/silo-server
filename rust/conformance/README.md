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
cargo build --manifest-path rust/Cargo.toml
rust/target/debug/silo-conformance list                # routes and cases, sends nothing
rust/conformance/scripts/self-compare.sh \
  --baseline rust/conformance/baseline/expected.json   # Go vs Go, gate on regressions
```

Against another candidate:

```sh
rust/target/debug/silo-conformance run \
  --reference http://127.0.0.1:28080 --candidate http://127.0.0.1:18080 \
  --surface jellycompat=http://127.0.0.1:28096,http://127.0.0.1:18096 \
  --surface abs=http://127.0.0.1:28378,http://127.0.0.1:18378 \
  --reset-reference 'rust/conformance/scripts/reset.sh --fast' \
  --reset-candidate '<command that restores the candidate database>' \
  --baseline rust/conformance/baseline/expected.json
```

Output goes to `--out` (default `rust/conformance/.run/report`): `report.json`,
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
cargo build --manifest-path rust/Cargo.toml -p silo-server -p silo-conformance
DATABASE_URL='postgres://silo:silo@127.0.0.1:35432/silo?sslmode=disable' \
SILO_FRONT_WEB_DIST=rust/conformance/baseline/web-dist \
SILO_FRONT_ORIGIN_LOG=rust/conformance/.run/origin.jsonl \
rust/target/debug/silo \
  --front main=127.0.0.1:18080,http://127.0.0.1:38080 \
  --front jellycompat=127.0.0.1:18096,http://127.0.0.1:38096 \
  --front abs=127.0.0.1:18378,http://127.0.0.1:38378 \
  --front metrics=127.0.0.1:19090,http://127.0.0.1:39090 &
rust/target/debug/silo-conformance run \
  --reference http://127.0.0.1:28080 --candidate http://127.0.0.1:18080 \
  --surface jellycompat=http://127.0.0.1:28096,http://127.0.0.1:18096 \
  --surface abs=http://127.0.0.1:28378,http://127.0.0.1:18378 \
  --surface metrics=http://127.0.0.1:29090,http://127.0.0.1:19090 \
  --origin-log rust/conformance/.run/origin.jsonl \
  --candidate-kind strangler \
  --reset-reference 'rust/conformance/scripts/reset.sh --fast' \
  --reset-candidate '<reset for the second stack>'
```

`SILO_FRONT_FORCE_GO=all` sends every native row to Go too, which is the proxy-all run: every route
is then `not_ported`, and any difference at all is the front's.

`baseline/web-dist` is the stub frontend the baseline image embeds. `scripts/front-compare.sh` runs
all of the above, with `--proxy-all` for the proxy-all run.

## Peer lab

The baseline's socat edge makes every client one private, trusted address, on both sides. A run through
it cannot see what a relay does to the peer trust decision, and it gives the two Go servers different
client addresses: the edge's on the reference, `127.0.0.1` through the front. The one route that shows
this, `GET /api/v2/admin/ips` with `ip=127.0.0.1`, therefore differs there.

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
the route manifests of the Jellyfin and Audiobookshelf routers plus routes mentioned in
`docs/jellycompat-api.md`, and contract fixtures and scenarios where the seed supports
their principals and placeholders. `list` prints what was skipped and why.

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

The order is a pure function of the sources, and cases run one at a time, so both
servers stay in step:

1. Create the objects later routes need (`seed`).
2. Reads, on the seed.
3. Writes that should be refused, which should change nothing.
4. Real writes in stages (v2, v1, v1 scenarios, compatibility), each from a reset database:
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
rust/conformance/scripts/mutation-test.sh --baseline rust/conformance/baseline/expected.json \
  none reserialize refuse_401 drop_field rule_out_of_format rule_in_format
```

Results go to `.run/mutation/<fault>/` as `check.txt` and `check.json`. `none` and
`reserialize` are controls and must report nothing. `all` applies a different fault per case
in one run, which is the quick way to try all of them. `rule_out_of_format` and
`rule_in_format` change every value a normalizer covers. A value a rule is meant to accept,
such as any non-negative gauge, is counted under `by_design` for that rule rather than as an
escape, so that column is the list of what the rules still allow.

The proxy only touches requests carrying the runner's `--tag-cases` header, so logins and
liveness probes stay honest and each fault maps to one case.

## Baselines

`baseline/expected.json` is recorded from Go vs Go over several runs:

```sh
rust/conformance/scripts/self-compare.sh --runs 3 \
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
  shows nowhere unless it carries a user. Native rows on the front write none.
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
