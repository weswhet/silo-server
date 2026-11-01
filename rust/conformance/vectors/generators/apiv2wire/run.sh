#!/bin/sh
# Writes the silo-api-v2 wire-kit vectors from the real internal/apiv2 package.
#
#   rust/conformance/vectors/generators/apiv2wire/run.sh gen
#
# Commands assume the repository root is the cwd. The Go tree is not modified: the one
# unexported-function need (Huma's validation error mapping) is reached through a build
# overlay that adds an export-shim file to internal/apiv2 (overlay/apiv2.go.txt), and
# libvips is replaced through a temporary go.mod with a stub nothing here calls, so the
# generator builds without cgo. Both techniques, and this file's structure, follow
# rust/conformance/vectors/generators/core/run.sh; this generator keeps its own copies so it
# never shares a workspace or overlay set with that one.
set -eu

here=rust/conformance/vectors/generators/apiv2wire
export GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 TZ=UTC
root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/bimg"
cp "$here/bimg_stub.go.txt" "$work/bimg/stub.go"
printf 'module github.com/h2non/bimg\n\ngo 1.21\n' > "$work/bimg/go.mod"
cp go.mod "$work/go.mod"
cp go.sum "$work/go.sum"
printf '\nreplace github.com/h2non/bimg => %s/bimg\n' "$work" >> "$work/go.mod"

printf '{"Replace":{\n"%s/internal/apiv2/zz_vectors_apiv2.go": "%s/%s/overlay/apiv2.go.txt"\n}}\n' \
  "$root" "$root" "$here" > "$work/overlay.json"

go build -modfile "$work/go.mod" -overlay "$work/overlay.json" -tags apiv2wire_vectors -o "$work/apiv2wire" "./$here"
"$work/apiv2wire" "$@"
