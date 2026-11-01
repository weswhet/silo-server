#!/usr/bin/env bash
# Runs the goose parser vector generator. goose's parser is an internal package, so this compiles its
# parser.go into the generator through -overlay, with only the package clause changed. The module
# cache and the Go tree stay untouched. Run it from anywhere.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.7}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
goose_dir="$(go list -m -f '{{.Dir}}' github.com/pressly/goose/v3)"
sed 's/^package sqlparser$/package main/' "$goose_dir/internal/sqlparser/parser.go" > "$tmp/parser.go"
printf '{"Replace":{"%s/rust/conformance/vectors/generators/goose/zz_sqlparser.go":"%s/parser.go"}}' "$PWD" "$tmp" > "$tmp/overlay.json"
go run -overlay "$tmp/overlay.json" -tags goose_vectors ./rust/conformance/vectors/generators/goose
