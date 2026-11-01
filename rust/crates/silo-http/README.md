# silo-http

Ports of the Go HTTP server stack that Silo's wire behavior comes from:

| Module | Go source |
|---|---|
| `server`, `bufio`, `request`, `response` | `net/http` `server.go`, `request.go`, `transfer.go`, `internal/chunked.go`, `net/textproto`, `bufio` |
| `chi` | `github.com/go-chi/chi/v5` v5.4.0, plus `middleware.StripSlashes` and `RedirectSlashes` |
| `servemux` | `http.ServeMux`, `pattern.go`, `routing_tree.go` |
| `fs` | `http.ServeContent`, `ServeFile`, `FileServer` |
| `sniff`, `mime`, `header`, `status`, `url` | `http.DetectContentType`, `mime`, `http.Header`, `httpguts`, `http.StatusText`, `net/url` |
| `compress` | `internal/httpstream/compress.go`, `codings.go` |
| `tower_bridge` | None. Runs axum handlers behind `chi::Mux`, with the `Params` extractor |

The reference is Go 1.26.7, the toolchain the server builds with. Go 1.27 changed this code in ways a
client can see, so moving the toolchain means rerunning the differential and porting what moved.

## Why this crate owns the connection

The plan named hyper. This crate has its own HTTP/1.1 connection engine instead, because the exit gate
compares bytes and hyper cannot produce Go's:

- hyper writes chunk sizes in uppercase hex; Go writes lowercase.
- `http::Uri` refuses request targets Go accepts, such as a raw `<` or `>`.
- hyper's bad-request replies, Date placement, and `HeaderName` lowercasing differ from Go's.
- Go's `WriteHeader`, `Write`, `Flush`, and `ReadFrom` sequence decides between `Content-Length` and
  chunked, and hyper's frame model does not expose that decision.

`axum` handlers still work: `tower_bridge::service_handler` takes anything from `Handler::with_state`.
WebSocket upgrades take the stream with `ResponseWriter::hijack` rather than `hyper::upgrade`.

## The exit gate

`tests/differential` builds `rust/conformance/vectors/generators/silohttp`, starts it, starts the same
routers on this crate, and compares raw responses over TCP: every route pattern in
`contracts/api/v2/route-inventory.json` and the `media_routes.txt` manifests, with adversarial paths, a
Range matrix against identical files, the response writer's call sequences, and malformed requests.

Commands assume the repository root is the cwd:

```sh
cd rust && cargo test -p silo-http -j 4 --test differential -- --nocapture
```

It needs `go` with the 1.26.7 toolchain available. `tests/vectors.rs` covers the pure functions from
committed Go output and needs no toolchain.

What the comparison normalizes, all because Go does not reproduce it between two of its own runs:

- The `Date` value, after checking its shape.
- The multipart boundary, after checking it is 60 hex characters. Part framing is compared.
- The order of `Allow` lines in chi's default 405, which chi builds by ranging over a map. This crate
  emits them in chi's method-bit order, which is one of the orders Go can produce.

Header order is not normalized: there is no unavoidable difference to document.

Compressed responses compare status, headers apart from framing, and the decoded body. Encoded bytes,
and so `Content-Length` versus chunked on an encoded body, are not expected to match, because the
encoders are different implementations.

## Known differences

- `http.ParseTime` on an RFC 850 date whose zone abbreviation the local zone defines: Go applies that
  zone's offset, this crate reads the wall clock as UTC. They agree when the process runs in UTC.
- `mime.ParseMediaType` is reduced to what system MIME files and the server's own calls use.
- `ServeMux.Handle` panics on the same conflicts as Go, with a shorter message.
- Routing children sort as Go's `sort.Sort` does up to 12 siblings. Past that Go's sort is unstable, which
  only matters for 13 or more regex or param siblings under one node, which no server route has.
