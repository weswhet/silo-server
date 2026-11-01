# Silo Rust port

A rewrite of the Go server in Rust that keeps every external contract: `/api/v1`, `/api/v2`,
jellycompat, Audiobookshelf, the plugin and node protocols, and the database schema.

Commands assume the repository root is the cwd.

- `rust/conformance` replays the same requests against a reference and a candidate server and
  reports parity per surface. See its README.
- `rust/crates` holds the port. The Go tree stays in place as the reference until parity is reached.

A route counts as ported only when Rust serves it natively and a compared success response matches
Go. Proxied, never-exercised, and refusal-only routes do not count.
