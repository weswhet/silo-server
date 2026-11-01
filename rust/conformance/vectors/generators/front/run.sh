#!/bin/sh
# Writes the silo-front SPA vectors from the real internal/server handler.
#
#   rust/conformance/vectors/generators/front/run.sh
#
# Commands assume the repository root is the cwd. libvips is replaced through a temporary go.mod with
# the stub the core vectors use, so this builds without cgo. The Go tree is not modified.
#
# The toolchain is what golang:1.26 gives the baseline image today, so these are bytes the reference
# really writes. It answers CONNECT differently from the 1.26.7 silo-http was ported from.
set -eu

here=rust/conformance/vectors/generators/front
export GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 TZ=UTC
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/bimg"
cp rust/conformance/vectors/generators/core/bimg_stub.go.txt "$work/bimg/stub.go"
printf 'module github.com/h2non/bimg\n\ngo 1.21\n' > "$work/bimg/go.mod"
cp go.mod "$work/go.mod"
cp go.sum "$work/go.sum"
printf '\nreplace github.com/h2non/bimg => %s/bimg\n' "$work" >> "$work/go.mod"

go run -modfile "$work/go.mod" -tags front_vectors "./$here/spa" rust/conformance/vectors/front/spa.json
