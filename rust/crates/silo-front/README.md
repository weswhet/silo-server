# silo-front

The test-only front from the Rust port plan. It owns the public listeners, answers the rows ported so
far, and relays every other request to a Go reference server. It never serves users until Go is gone,
and the `silo` binary says so when it starts.

Commands assume the repository root is the cwd.

## Row table

`src/rows_table.rs` declares every denominator row `native` or `go`. `build.rs` fails the build when it
disagrees with `contracts/api/v2/route-inventory.json`, `contracts/api/v2/openapi.json`, or the
`media_routes.txt` manifests, in either direction, and prints the lines to add or delete. The six rows
those files cannot list are in `WIRING_CONDITIONAL_ROWS` in `src/reconcile.rs`, with reasons.

## Relay

`src/relay.rs` maps a client connection to one Go connection and copies bytes. It reads only what it
needs to find message boundaries, by Go's rules (`src/http1.rs`). It does not decode, buffer, or reorder
anything, and a `101` turns the connection into a tunnel. A closed upstream closes the client, which is
how Go's timeouts reach it. A head the relay cannot vouch for goes to silo-http's reader for Go's refusal
and never reaches Go, so nothing it did not sanitize can be parsed as a request.

## Trust

Go trusts loopback by default, so a relay on loopback would make every client a trusted peer.
`src/trust.rs` evaluates the live `clientip.trusted_proxies` setting. From an untrusted peer it strips
`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, and `Forwarded`, and from any peer
it writes the `X-Forwarded-For` that makes Go resolve what it would have on a direct connection.
`src/peer.rs` connects to a loopback Go from a per-client 127/8 address where the host allows it, so Go's
peer-keyed checks see distinct clients. When `Host` is an address and the client named no forwarding
header, it also writes `X-Forwarded-Host` with that same host, because Go otherwise reads the relay's
`X-Forwarded-For` as a proxy having rewritten `Host` (`bandwidthProbeBaseURL`).

Three things stay different, and the harness's peer cases show them
(`rust/conformance/README.md`, Peer lab). None can be fixed from here:

- Go reads `X-Forwarded-Proto` and `X-Forwarded-Host` directly in `isSecureRequest`, `requestBaseURL`,
  `absBaseURL`, and `forwardedHost` (`checkWebSocketOrigin`'s same-origin fallback for a WebSocket
  upgrade), whoever sent them. The front strips them from an untrusted peer because `clientip` believes
  them from the front, so those readers do not see an untrusted client's spoof. The harness has no peer
  case for the `checkWebSocketOrigin` path yet (`base_url:*` covers the other readers); it needs minting
  a valid events-ws ticket, which the Linux-only peer lab this repo's macOS development hosts cannot run
  to verify.
- `sameStreamPath` takes a peer that differs from the client address to mean a proxy. Through the front that
  is always so, and a trusted peer naming a direct client's address gets that client's Jellyfin stream grant.
- Go's peer is the hashed source, not the client, so anything logged or keyed on the peer differs by value.

## Native rows

`src/native/` holds the rows Rust answers. `rows_table.rs` lists every row and proxies it to Go unless a
domain's `ROWS` names it; the build fails if a `ROWS` entry is not in the table. `Gate` routes a request to
the native handler when its path has a native row, except a method the table gives Go at that path, a
network access ingress request, or a v2 request with a query string, which go to Go.

`src/native/chain.rs` is the chain: `useBaseMiddleware` (request ID, client IP, logger, metrics, activity
log), the gates as an ordered `Step` list, the v1 refusal body, the v2 `denialWriter` translation, and
`prepareCapabilityOperation`. The gates themselves are in `silo_gate::mw` and `silo_gate::limiter`.

### Adding a native row

1. Create or open `src/native/<domain>.rs`. Declare `pub const ROWS: &[NativeRow]` with the row.
2. A new file: add `pub mod <domain>;`, then add `<domain>::ROWS` to `DOMAINS` and `<domain>::mount` to
   `main_handler` in `src/native/mod.rs`. That is the only shared file you touch; `rows_table.rs` stays as is.
3. Register the handler in `mount`, with the gates its Go route group has:

   ```rust
   // v1: the list is the chi group's `Use` order, read from `internal/api/router.go`.
   const GROUP: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];
   api.get(PATH, stack.v1(PATH, GROUP, handler_fn(|w, r| Box::pin(async move { /* ... */ }))));
   // v2: the operation's `Class`, as `gateChain` composes it.
   v2.get(PATH, stack.v2(PATH, V2Class::ProfileOptional, handler));
   ```

4. In the handler, read `silo_gate::mw::auth::get_claims(r)`, `get_profile_id(r)`, and
   `r.extensions.get::<Arc<silo_store::access::Scope>>()`. Answer with `write_v1_json`, `write_v2_json`,
   `write_capability`, `write_v1_denial`, or `write_problem`.
5. Add the row to `CHAIN_ROWS` in `rust/conformance/src/plan.rs` and to `native-chain-traits.sh` if it has a
   `rate_limited` or `demo_guarded` trait, then run `front-compare.sh` with `--only` set to the row's case ids.

The front needs `SECRET_KEY` to read the signing secret, or rows behind a credential stay on Go, and
`REDIS_URL` when `ratelimit.backend` is `redis`.

## Tests

```sh
cd rust && cargo test -p silo-front -j 4
```

`tests/gateway_differential.rs` needs `go` with the 1.26.10 toolchain for the real `internal/clientip`. To
also compare raw bytes with a running Go server:

```sh
cd rust && SILO_FRONT_TEST_REFERENCE=127.0.0.1:28080,127.0.0.1:28096,127.0.0.1:28378 \
  DATABASE_URL='postgres://silo:silo@127.0.0.1:25432/silo?sslmode=disable' \
  cargo test -p silo-front -j 4 --test gateway_differential
```

Those tests read only, and skip without the variables. `rust/conformance/vectors/generators/front/run.sh`
regenerates the SPA vectors. See `rust/conformance/README.md` for running the harness against the front.
